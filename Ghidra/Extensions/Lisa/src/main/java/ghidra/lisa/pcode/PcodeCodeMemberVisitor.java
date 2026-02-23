/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.lisa.pcode;

import java.util.*;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.lisa.pcode.WorkItem.PredType;
import ghidra.lisa.pcode.contexts.*;
import ghidra.lisa.pcode.expressions.*;
import ghidra.lisa.pcode.locations.PcodeLocation;
import ghidra.lisa.pcode.statements.PcodeNop;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import it.unive.lisa.program.annotations.Annotations;
import it.unive.lisa.program.cfg.*;
import it.unive.lisa.program.cfg.controlFlow.ControlFlowStructure;
import it.unive.lisa.program.cfg.edge.Edge;
import it.unive.lisa.program.cfg.edge.SequentialEdge;
import it.unive.lisa.program.cfg.statement.*;
import it.unive.lisa.program.cfg.statement.comparison.Equal;
import it.unive.lisa.program.cfg.statement.literal.*;
import it.unive.lisa.program.type.BoolType;
import it.unive.lisa.type.Type;
import it.unive.lisa.type.Untyped;
import it.unive.lisa.util.datastructures.graph.code.NodeList;

/**
 * An {@link PcodeCodeMemberVisitor} that will parse the pcode of an function
 * 
 */

public class PcodeCodeMemberVisitor {

	private final NodeList<CFG, Statement, Edge> list;

	private final Collection<Statement> entrypoints;
	private final Collection<ControlFlowStructure> cfs;
	private final Map<String, Pair<VariableRef, Annotations>> visibleIds;

	private final CFG cfg;

	private final CodeMemberDescriptor descriptor;

	private Listing listing;

	private final Collection<String> visited;
	private final Map<SequenceNumber, Statement> visitedPcode;
	private Stack<WorkItem> workItems;

	private UnitContext currentUnit;

	private Map<Address, PcodeBranch> flows;

	private int varCount = 0;

	/**
	 * Builds the visitor of an IMP method or constructor.
	 * 
	 * @param descriptor the descriptor of the method or constructor
	 * @param listing    the program listing
	 */
	PcodeCodeMemberVisitor(CodeMemberDescriptor descriptor, Listing listing) {
		this.descriptor = descriptor;
		this.listing = listing;
		list = new NodeList<>(new SequentialEdge());
		entrypoints = new HashSet<>();
		visited = new HashSet<>();
		visitedPcode = new HashMap<>();
		cfs = new LinkedList<>();
		// side effects on entrypoints and matrix will affect the cfg
		cfg = new CFG(descriptor, entrypoints, list);
		this.flows = new HashMap<>();

		visibleIds = new HashMap<>();
		for (VariableTableEntry par : descriptor.getVariables()) {
			visibleIds.put(par.getName(), Pair.of(par.createReference(cfg), par.getAnnotations()));
		}
	}

	/**
	 * Visits the code of a {@link UnitContext} representing the code block of
	 * a method or constructor.
	 * 
	 * @param ctx the block context
	 * 
	 * @return the {@link CFG} built from the block
	 */
	CFG visitCodeMember(UnitContext ctx) {
		this.currentUnit = ctx;
		InstructionContext entry = ctx.entry();
		if (entry == null) {
			throw new RuntimeException("No entry for " + ctx.function());
		}
		while (entry.getPcodeOps().isEmpty()) {
			entry = entry.next();
		}
		visited.clear();
		visitedPcode.clear();
		workItems = new Stack<>();
		workItems.add(new WorkItem(null, entry.getPcodeOp(0)));
		while (!workItems.isEmpty()) {
			processWorkItem(workItems.pop());
		}
		visitBlock(entry);

		cfs.forEach(cf -> cfg.addControlFlowStructure(cf));

		Ret ret = new Ret(cfg, descriptor.getLocation());
		if (cfg.getNodesCount() == 0) {
			// empty method, so the ret is also the entrypoint
			list.addNode(ret);
			entrypoints.add(ret);
		}
		else {
			// every non-throwing instruction that does not have a follower
			// is ending the method
			Collection<Statement> preExits = new LinkedList<>();
			for (Statement st : list.getNodes())
				if (!st.stopsExecution() && list.followersOf(st).isEmpty())
					preExits.add(st);
			list.addNode(ret);
			for (Statement st : preExits)
				list.addEdge(new SequentialEdge(st, ret));

			for (VariableTableEntry vte : descriptor.getVariables())
				if (preExits.contains(vte.getScopeEnd()))
					vte.setScopeEnd(ret);
		}

		cfg.simplify();
		return cfg;
	}

	public void visitBlock(InstructionContext entry) {
		if (entry == null) {
			return;
		}
		while (entry.getPcodeOps().isEmpty()) {
			entry = entry.next();
		}
		visited.clear();
		visitedPcode.clear();
		workItems = new Stack<>();
		workItems.add(new WorkItem(null, entry.getPcodeOp(0)));
		while (!workItems.isEmpty()) {
			processWorkItem(workItems.pop());
		}
	}

	private void processWorkItem(WorkItem item) {
		StatementContext ctx = item.getContext();
		Statement st = visitPcodeOp(ctx);
		if (st == null) {
			return;
		}
		if (visited.contains(item.getKey())) {
			return;
		}
		Statement pred = item.getPred();
		boolean entrypoint = pred == null;
		cfg.addNode(st, entrypoint);
		if (!entrypoint) {
			Edge e = item.computeBranch(st);
			if (e != null) {
				cfg.addEdge(e);
			}
			PredType type = item.getType();
			if (!type.equals(PredType.SEQ)) {
				PcodeLocation location = (PcodeLocation) pred.getLocation();
				Address loc = location.getAddress();
				PcodeBranch flow = flows.get(loc);
				if (flow == null) {
					flow = new PcodeBranch(cfg.getNodeList(), pred);
					cfg.addControlFlowStructure(flow);
				}
				flow.addStatement(st, type);
				flows.put(loc, flow);
			}
		}
		else {
			entrypoints.add(st);
		}

		if (st instanceof Ret || st instanceof Return) {
			return;
		}

		List<StatementContext> branches = currentUnit.branch(ctx, this.listing);
		for (StatementContext branch : branches) {
			WorkItem n = new WorkItem(st, branch);
			if (ctx.isConditional()) {
				n.setType(true);
			}
			workItems.add(n);
		}
		StatementContext next = currentUnit.next(ctx, this.listing);
		if (next != null) {
			WorkItem n = new WorkItem(st, next);
			if (ctx.isBranch()) {
				if (ctx.isConditional()) {
					n.setType(false);
					workItems.add(n);
				}
			}
			else {
				workItems.add(n);
			}
		}
		visited.add(item.getKey());
	}

	public Statement visitPcodeOp(StatementContext ctx) {
		SequenceNumber key = ctx.getOp().getSeqnum();
		if (visitedPcode.containsKey(key)) {
			return visitedPcode.get(key);
		}

		Statement st;
		if (ctx.isRet()) {
			if (ctx.expression() != null) {
				st = new Return(cfg, ctx.location(), visitExpression(ctx));
			}
			else {
				st = new Ret(cfg, ctx.location());
			}
		}
		else if (ctx.isBranch()) {
			if (ctx.isConditional()) {
				st = visitCondition(ctx.condition());
			}
			else {
				st = new PcodeNop(cfg, ctx.location());  // Treating these as a NOP
			}
		}
		else if (ctx.expression() != null) {
			st = visitExpression(ctx);
		}
		else
			throw new IllegalArgumentException(
				"Statement '" + ctx.toString() + "' cannot be parsed");

		visitedPcode.put(key, st);
		return st;
	}

	public Statement visitCondition(
			ConditionContext ctx) {
		VarnodeContext expression = ctx.expression();
		CodeLocation loc = ctx.location();
		if (expression == null) {
			return new NoOp(cfg, loc);
		}
		//return visitVarnode(ctx.location(), expression, BoolType.INSTANCE, false);
		Expression left = visitVarnode(loc, expression, BoolType.INSTANCE, false);
		return new Equal(cfg, loc, left, new TrueLiteral(cfg, loc));
	}

	public Expression visitExpression(StatementContext ctx) {
		CodeLocation loc = ctx.location();
		VarDefContext left = ctx.target();
		PcodeContext right = ctx.expression();

		int opcode = ctx.opcode();

		// Special case logic first
		switch (opcode) {
			case PcodeOp.COPY -> {
				Expression target = visitVariable(loc, left, true);
				Expression expression = visitVarnode(loc, right.basicExpr(), false);
				return new Assignment(cfg, loc, target, expression);
			}
			case PcodeOp.FLOAT_INT2FLOAT, PcodeOp.FLOAT_FLOAT2FLOAT -> {
				Expression target = visitVariable(loc, left, true);
				Expression expression = visitBinaryExpr(new BinaryExprContext(ctx));
				return new Assignment(cfg, loc, target, expression);
			}
			case PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.CALLOTHER -> {
				return visitCallExpr(new CallContext(ctx.getOp(), currentUnit));
			}
			case PcodeOp.RETURN -> {
				return visitVarnode(loc, right.basicExpr(), false);
			}
			case PcodeOp.LOAD -> {
				MemLocContext mem = new MemLocContext(ctx);
				Expression target = visitVariable(loc, left, true);
				Expression expression = visitVarnode(loc, mem, false);
				return new Assignment(cfg, loc, target, expression);
			}
			case PcodeOp.STORE -> {
				MemLocContext mem = new MemLocContext(ctx);
				Expression target = visitVariable(loc, mem, true);
				Expression expression = visitVarnode(loc, left, false);
				return new Assignment(cfg, loc, target, expression);
			}
			case PcodeOp.MULTIEQUAL -> {
				Expression target = visitVariable(loc, left, true);
				//Expression expression = visitVariable(loc, left, true);
				Expression expression = visitVarargsExpr(new VarargsExprContext(right));
				return new Assignment(cfg, loc, target, expression);
			}
		}

		if (right == null) {
			throw new UnsupportedOperationException("Type of expression not supported: " + ctx);
		}

		// Everything else...
		// NB: left is the output of the assignment, right the complete expression
		return switch (right.getNumInputs()) {
			case 1 -> {
				Expression target = visitVariable(loc, left, true);
				Expression expression = visitUnaryExpr(new UnaryExprContext(right));
				yield new Assignment(cfg, loc, target, expression);
			}
			case 2 -> {
				Expression target = visitVariable(loc, left, true);
				Expression expression = visitBinaryExpr(new BinaryExprContext(right));
				yield new Assignment(cfg, loc, target, expression);
			}
			// NB: This may be unnecssary with the move of LOAD and STORE to the special-case section
			case 3 -> {
				Expression target = visitVariable(loc, left, true);
				Expression expression = visitTernaryExpr(new TernaryExprContext(right));
				yield new Assignment(cfg, loc, target, expression);
			}
			default -> throw new UnsupportedOperationException(
				"Type of expression not supported: " + ctx);
		};
	}

	public Expression visitCallExpr(CallContext ctx) {
		CodeLocation loc = ctx.location();
		Expression lexp = visitVarnode(loc, ctx.left, false);
		return new PcodeCallExpression(cfg, ctx, lexp);
	}

	public Expression visitUnaryExpr(UnaryExprContext ctx) {
		CodeLocation loc = ctx.location();
		Expression lexp = visitVarnode(loc, ctx.arg, false);
		return new PcodeUnaryExpression(cfg, ctx, lexp);
	}

	public Expression visitBinaryExpr(BinaryExprContext ctx) {
		CodeLocation loc = ctx.location();
		Expression lexp = visitVariable(loc, ctx.left, false);
		Expression rexp = visitVarnode(loc, ctx.right, false);
		return new PcodeBinaryExpression(cfg, ctx, lexp, rexp);
	}


	public Expression visitTernaryExpr(TernaryExprContext ctx) {
		CodeLocation loc = ctx.location();
		Expression lexp = visitVariable(loc, ctx.left, false);
		Expression mexp = visitVariable(loc, ctx.middle, false);
		Expression rexp = visitVarnode(loc, ctx.right, false);
		return new PcodeTernaryExpression(cfg, ctx, lexp, mexp, rexp);
	}

	public Expression visitVarargsExpr(VarargsExprContext ctx) {
		CodeLocation loc = ctx.location();
		Expression[] exps = new Expression[ctx.varargs.length];
		for (int i = 0; i < ctx.varargs.length; i++) {
			exps[i] = visitVariable(loc, ctx.varargs[i], false);
		}
		return new PcodeVarargsExpression(cfg, ctx, exps);
	}

	public Expression visitVarnode(CodeLocation loc, VarnodeContext ctx, Type type, boolean define) {
		if (ctx.isConstant()) {
			return visitConstant(loc, ctx);
		}
		return visitVariable(loc, ctx, type, define);
	}

	public Expression visitVarnode(CodeLocation loc, VarnodeContext ctx, boolean define) {
		return visitVarnode(loc, ctx, Untyped.INSTANCE, define);
	}

	public Literal<?> visitConstant(CodeLocation loc, VarnodeContext ctx) {
		return switch (ctx.getSize()) {
			case 0 -> new NullLiteral(cfg, loc);
			case 1 -> new Int8Literal(cfg, loc, (byte) ctx.getOffset());
			case 2 -> new Int16Literal(cfg, loc, (short) ctx.getOffset());
			case 4 -> new Int32Literal(cfg, loc, (int) ctx.getOffset());
			case 8 -> new Int64Literal(cfg, loc, ctx.getOffset());
			default -> new Int64Literal(cfg, loc, ctx.getOffset());  // FIXME
//			default -> throw new UnsupportedOperationException(
//				"Type of literal not supported: " + ctx);
		};
	}

	private VariableRef visitVariable(CodeLocation loc, VarnodeContext ctx, boolean define) {
		return visitVariable(loc, ctx, Untyped.INSTANCE, define);
	}

	private VariableRef visitVariable(CodeLocation loc, VarnodeContext ctx, Type type,
			boolean define) {
		VariableRef ref = new VariableRef(cfg, loc,
			ctx.getText(), type);
		if (!visibleIds.containsKey(ref.getName())) {
			visibleIds.put(ref.getName(), Pair.of(ref, new Annotations()));
			descriptor.addVariable(new VariableTableEntry(loc, varCount++, null, null,
				ref.getName(), type));
		}
		return ref;
	}

	public Map<Address, PcodeBranch> getFlows() {
		return flows;
	}

}
