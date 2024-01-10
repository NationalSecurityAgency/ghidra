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
package ghidra.app.plugin.assembler.sleigh.sem;

import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.collections4.IteratorUtils;
import org.apache.commons.collections4.Predicate;
import org.apache.commons.lang3.StringUtils;

import ghidra.app.plugin.assembler.AssemblySelector;
import ghidra.app.plugin.assembler.sleigh.expr.MaskedLong;
import ghidra.app.plugin.assembler.sleigh.expr.RecursiveDescentSolver;
import ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyResolutionFactory.AbstractAssemblyResolutionBuilder;
import ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyResolutionFactory.AbstractAssemblyResolvedPatternsBuilder;
import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol;
import ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol;

/**
 * A {@link AssemblyResolution} indicating successful application of a constructor
 * 
 * <p>
 * This is almost analogous to {@link ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern
 * DisjointPattern}, in that is joins an instruction {@link AssemblyPatternBlock} with a
 * corresponding context {@link AssemblyPatternBlock}. However, this object is mutable, and it
 * collects backfill records, as well as forbidden patterns.
 * 
 * <p>
 * When the applied constructor is from the "instruction" subtable, this represents a fully-
 * constructed instruction with required context. All backfill records ought to be resolved and
 * applied before the final result is given to the user, i.e., passed into the
 * {@link AssemblySelector}. If at any time during the resolution or backfill process, the result
 * becomes confined to one of the forbidden patterns, it must be dropped, since the encoding will
 * actually invoke a more specific SLEIGH constructor.
 */
public class DefaultAssemblyResolvedPatterns extends AbstractAssemblyResolution
		implements AssemblyResolvedPatterns {
	protected static final String INS = AbstractAssemblyResolutionFactory.INS;
	protected static final String CTX = AbstractAssemblyResolutionFactory.CTX;
	protected static final String SEP = AbstractAssemblyResolutionFactory.SEP;

	protected final Constructor cons;
	protected final AssemblyPatternBlock ins;
	protected final AssemblyPatternBlock ctx;

	protected final Set<AssemblyResolvedBackfill> backfills;
	protected final Set<AssemblyResolvedPatterns> forbids;

	/**
	 * @see AssemblyResolution#resolved(AssemblyPatternBlock, AssemblyPatternBlock, String,
	 *      Constructor, List, AssemblyResolution)
	 */
	protected DefaultAssemblyResolvedPatterns(AbstractAssemblyResolutionFactory<?, ?> factory,
			String description, Constructor cons, List<? extends AssemblyResolution> children,
			AssemblyResolution right, AssemblyPatternBlock ins, AssemblyPatternBlock ctx,
			Set<AssemblyResolvedBackfill> backfills, Set<AssemblyResolvedPatterns> forbids) {
		super(factory, description, children, right);
		this.cons = cons;
		this.ins = ins == null ? AssemblyPatternBlock.nop() : ins;
		this.ctx = ctx == null ? AssemblyPatternBlock.nop() : ctx;
		this.backfills = backfills == null ? Set.of() : Collections.unmodifiableSet(backfills);
		this.forbids = forbids == null ? Set.of() : Collections.unmodifiableSet(forbids);
	}

	@Override
	protected int computeHash() {
		int result = 0;
		result += ins.hashCode();
		result *= 31;
		result += ctx.hashCode();
		result *= 31;
		result += backfills.hashCode();
		result *= 31;
		result += forbids.hashCode();
		return result;
	}

	protected boolean partsEqual(DefaultAssemblyResolvedPatterns that) {
		if (!this.ins.equals(that.ins)) {
			return false;
		}
		if (!this.ctx.equals(that.ctx)) {
			return false;
		}
		if (!this.backfills.equals(that.backfills)) {
			return false;
		}
		if (!this.forbids.equals(that.forbids)) {
			return false;
		}
		return true;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (this.getClass() != obj.getClass()) {
			return false;
		}
		DefaultAssemblyResolvedPatterns that = (DefaultAssemblyResolvedPatterns) obj;
		return partsEqual(that);
	}

	protected AbstractAssemblyResolvedPatternsBuilder<?> shiftBuilder(int amt) {
		var builder = factory.newPatternsBuilder();
		builder.description = description;
		builder.cons = cons;
		builder.children = children;
		builder.right = right;
		builder.ins = ins.shift(amt);
		builder.ctx = ctx;

		// Also shift the attached backfills and forbidden patterns
		builder.backfills = new HashSet<>();
		for (AssemblyResolvedBackfill bf : this.backfills) {
			builder.backfills.add(bf.shift(amt));
		}

		builder.forbids = new HashSet<>();
		for (AssemblyResolvedPatterns f : this.forbids) {
			builder.forbids.add(f.shift(amt));
		}

		return builder;
	}

	@Override
	public AssemblyResolvedPatterns shift(int amt) {
		if (amt == 0) {
			return this;
		}
		return shiftBuilder(amt).build();
	}

	protected AbstractAssemblyResolvedPatternsBuilder<?> truncateBuilder(int amt) {
		var builder = factory.newPatternsBuilder();
		builder.description = "Truncated: " + description;
		builder.cons = cons;
		builder.right = right;
		builder.ins = ins.truncate(amt);
		builder.ctx = ctx;
		return builder;
	}

	@Override
	public AssemblyResolvedPatterns truncate(int amt) {
		if (amt == 0) {
			return this;
		}
		return truncateBuilder(amt).build();
	}

	protected AbstractAssemblyResolutionBuilder<?, ?> checkNotForbiddenBuilder() {
		var builder = factory.newPatternsBuilder();

		builder.forbids = new HashSet<>();
		for (AssemblyResolvedPatterns f : forbids) {
			AssemblyResolvedPatterns check = this.combine(f);
			if (null == check) {
				continue;
			}
			builder.forbids.add(f);
			if (check.bitsEqual(this)) {
				// The result would be disassembled by a more-specific constructor.
				return factory.errorBuilder("The result is forbidden by " + f, this);
			}
		}

		builder.description = description;
		builder.cons = cons;
		builder.children = children;
		builder.right = right;
		builder.ins = ins;
		builder.ctx = ctx;
		builder.backfills = backfills;
		return builder;
	}

	@Override
	public AssemblyResolution checkNotForbidden() {
		return checkNotForbiddenBuilder().build();
	}

	@Override
	public boolean bitsEqual(AssemblyResolvedPatterns that) {
		return this.ins.equals(that.getInstruction()) && this.ctx.equals(that.getContext());
	}

	protected AbstractAssemblyResolvedPatternsBuilder<?> combineBuilder(
			AssemblyResolvedPatterns that) {
		var builder = factory.newPatternsBuilder();
		builder.ins = ins.combine(that.getInstruction());
		if (builder.ins == null) {
			return null;
		}
		builder.ctx = ctx.combine(that.getContext());
		if (builder.ctx == null) {
			return null;
		}
		builder.backfills = new HashSet<>(this.backfills);
		builder.backfills.addAll(that.getBackfills());
		builder.forbids = new HashSet<>(this.forbids);
		builder.forbids.addAll(that.getForbids());

		builder.description = description;
		builder.cons = cons;
		builder.children = children;
		builder.right = right;

		return builder;
	}

	protected AbstractAssemblyResolvedPatternsBuilder<?> combineLessBackfillBuilder(
			AssemblyResolvedPatterns that, AssemblyResolvedBackfill bf) {
		var builder = combineBuilder(that);
		builder.backfills.remove(bf);
		return builder;
	}

	@Override
	public AssemblyResolvedPatterns combine(AssemblyResolvedPatterns that) {
		var builder = combineBuilder(that);
		return builder == null ? null : builder.build();
	}

	/**
	 * Combine a backfill result
	 * 
	 * <p>
	 * When a backfill is successful, the result should be combined with the owning resolution. In
	 * addition, for bookkeeping's sake, the resolved record should be removed from the list of
	 * backfills.
	 * 
	 * @param that the result from backfilling
	 * @param bf the resolved backfilled record
	 * @return the result if successful, or null
	 */
	@Override
	public AssemblyResolvedPatterns combineLessBackfill(AssemblyResolvedPatterns that,
			AssemblyResolvedBackfill bf) {
		var builder = combineLessBackfillBuilder(that, bf);
		return builder == null ? null : builder.build();
	}

	protected AbstractAssemblyResolvedPatternsBuilder<?> combineBuilder(
			AssemblyResolvedBackfill bf) {
		var builder = factory.newPatternsBuilder();
		builder.description = description;
		builder.cons = cons;
		builder.children = children;
		builder.right = right;
		builder.ins = ins;
		builder.ctx = ctx;
		builder.backfills = new HashSet<>(backfills);
		builder.backfills.add(bf);
		builder.forbids = forbids;
		return builder;
	}

	@Override
	public AssemblyResolvedPatterns combine(AssemblyResolvedBackfill bf) {
		return combineBuilder(bf).build();
	}

	protected AbstractAssemblyResolvedPatternsBuilder<?> withForbidsBuilder(
			Set<AssemblyResolvedPatterns> more) {
		var builder = factory.newPatternsBuilder();
		builder.description = description;
		builder.cons = cons;
		builder.children = children;
		builder.right = right;
		builder.ins = ins;
		builder.ctx = ctx;
		builder.backfills = backfills;
		builder.forbids = new HashSet<>(forbids);
		builder.forbids.addAll(more);
		return builder;
	}

	@Override
	public AssemblyResolvedPatterns withForbids(Set<AssemblyResolvedPatterns> more) {
		return withForbidsBuilder(more).build();
	}

	protected AbstractAssemblyResolvedPatternsBuilder<?> withDescriptionBuilder(
			String description) {
		var builder = factory.newPatternsBuilder();
		builder.description = description;
		builder.cons = cons;
		builder.children = children;
		builder.right = right;
		builder.ins = ins;
		builder.ctx = ctx;
		builder.backfills = backfills;
		builder.forbids = forbids;
		return builder;
	}

	@Override
	public AssemblyResolvedPatterns withDescription(String description) {
		return withDescriptionBuilder(description).build();
	}

	protected AbstractAssemblyResolvedPatternsBuilder<?> withConstructorBuilder(Constructor cons) {
		var builder = factory.newPatternsBuilder();
		builder.description = description;
		builder.cons = cons;
		builder.children = children;
		builder.right = right;
		builder.ins = ins;
		builder.ctx = ctx;
		builder.backfills = backfills;
		builder.forbids = forbids;
		return builder;
	}

	@Override
	public AssemblyResolvedPatterns withConstructor(Constructor cons) {
		return withConstructorBuilder(cons).build();
	}

	protected AbstractAssemblyResolvedPatternsBuilder<?> writeContextOpBuilder(ContextOp cop,
			MaskedLong val) {
		var builder = factory.newPatternsBuilder();
		builder.description = description;
		builder.cons = cons;
		builder.children = children;
		builder.right = right;
		builder.ins = ins;
		builder.ctx = ctx.writeContextOp(cop, val);
		builder.backfills = backfills;
		builder.forbids = forbids;
		return builder;
	}

	@Override
	public AssemblyResolvedPatterns writeContextOp(ContextOp cop, MaskedLong val) {
		return writeContextOpBuilder(cop, val).build();
	}

	@Override
	public MaskedLong readContextOp(ContextOp cop) {
		return ctx.readContextOp(cop);
	}

	protected AbstractAssemblyResolvedPatternsBuilder<?> copyAppendDescriptionBuilder(
			String append) {
		var builder = factory.newPatternsBuilder();
		builder.description = description + ": " + append;
		builder.cons = cons;
		builder.children = children;
		builder.right = right;
		builder.ins = ins.copy();
		builder.ctx = ctx.copy();
		builder.backfills = backfills;
		builder.forbids = forbids;
		return builder;
	}

	/**
	 * Duplicate this resolution, with additional description text appended
	 * 
	 * @param append the text to append
	 * @return the duplicate NOTE: An additional separator {@code ": "} is inserted
	 */
	public AssemblyResolvedPatterns copyAppendDescription(String append) {
		return copyAppendDescriptionBuilder(append).build();
	}

	protected AbstractAssemblyResolvedPatternsBuilder<?> withRightBuilder(
			AssemblyResolution right) {
		var builder = factory.newPatternsBuilder();
		builder.description = description;
		builder.cons = cons;
		builder.children = children;
		builder.right = right;
		builder.ins = ins.copy();
		builder.ctx = ctx.copy();
		builder.backfills = backfills;
		builder.forbids = forbids;
		return builder;
	}

	@Override
	public AssemblyResolvedPatterns withRight(AssemblyResolution right) {
		return withRightBuilder(right).build();
	}

	protected AbstractAssemblyResolvedPatternsBuilder<?> nopLeftSiblingBuilder() {
		var builder = factory.newPatternsBuilder();
		builder.description = "nop-left";
		builder.right = this;
		builder.ins = ins.copy();
		builder.ctx = ctx.copy();
		builder.backfills = backfills;
		builder.forbids = forbids;
		return builder;
	}

	@Override
	public AssemblyResolvedPatterns nopLeftSibling() {
		return nopLeftSiblingBuilder().build();
	}

	protected AbstractAssemblyResolvedPatternsBuilder<?> parentBuilder(String description,
			int opCount) {
		var builder = factory.newPatternsBuilder();
		builder.description = description;
		builder.cons = cons;
		List<AssemblyResolution> allRight = getAllRight();
		builder.children = allRight.subList(0, opCount);
		builder.right = allRight.get(opCount);
		builder.ins = ins;
		builder.ctx = ctx;
		builder.backfills = backfills;
		builder.forbids = forbids;
		return builder;
	}

	@Override
	public AssemblyResolvedPatterns parent(String description, int opCount) {
		return parentBuilder(description, opCount).build();
	}

	protected AbstractAssemblyResolvedPatternsBuilder<?> maskOutBuilder(ContextOp cop) {
		var builder = factory.newPatternsBuilder();
		builder.description = description;
		builder.cons = cons;
		builder.children = children;
		builder.right = right;
		builder.ins = ins;
		builder.ctx = ctx.maskOut(cop);
		builder.backfills = backfills;
		builder.forbids = forbids;
		return builder;
	}

	@Override
	public AssemblyResolvedPatterns maskOut(ContextOp cop) {
		return maskOutBuilder(cop).build();
	}

	@Override
	public AssemblyResolution backfill(RecursiveDescentSolver solver, Map<String, Long> vals) {
		if (!hasBackfills()) {
			return this;
		}

		AssemblyResolvedPatterns res = this;
		loop: while (true) {
			for (AssemblyResolvedBackfill bf : res.getBackfills()) {
				AssemblyResolution ar = bf.solve(solver, vals, this);
				if (ar.isError()) {
					continue;
				}
				AssemblyResolvedPatterns rc = (AssemblyResolvedPatterns) ar;
				AssemblyResolvedPatterns check = res.combineLessBackfill(rc, bf);
				if (check == null) {
					return factory.error("Conflict: Backfill " + bf.getDescription(), res);
				}
				res = check;
				continue loop;
			}
			return res;
		}
	}

	@Override
	public String lineToString() {
		return dumpConstructorTree() + ":" + INS + ins + SEP + CTX + ctx + " (" + description + ")";
	}

	@Override
	public boolean hasBackfills() {
		return !backfills.isEmpty();
	}

	/**
	 * Check if this resolution includes forbidden patterns
	 * 
	 * @return true if there are forbidden patterns
	 */
	private boolean hasForbids() {
		return !forbids.isEmpty();
	}

	protected AbstractAssemblyResolvedPatternsBuilder<?> solveContextChangesForForbidsBuilder(
			AssemblyConstructorSemantic sem, Map<String, Long> vals) {
		var builder = factory.newPatternsBuilder();
		builder.forbids = new HashSet<>();
		for (AssemblyResolvedPatterns f : forbids) {
			AssemblyResolution t = sem.solveContextChanges(f, vals);
			if (!(t instanceof AssemblyResolvedPatterns rp)) {
				// Can't be solved, so it can be dropped
				continue;
			}
			builder.forbids.add(rp);
		}
		builder.description = description;
		builder.cons = cons;
		builder.children = children;
		builder.right = right;
		builder.ins = ins;
		builder.ctx = ctx;
		builder.backfills = backfills;
		return builder;
	}

	@Override
	public AssemblyResolvedPatterns solveContextChangesForForbids(
			AssemblyConstructorSemantic sem, Map<String, Long> vals) {
		if (!hasForbids()) {
			return this;
		}
		return solveContextChangesForForbidsBuilder(sem, vals).build();
	}

	@Override
	public int getInstructionLength() {
		int inslen = ins.length();
		for (AssemblyResolvedBackfill bf : backfills) {
			inslen = Math.max(inslen, bf.getInstructionLength());
		}
		return inslen;
	}

	@Override
	public int getDefinedInstructionLength() {
		byte[] imsk = ins.getMask();
		int i;
		for (i = imsk.length - 1; i >= 0; i--) {
			if (imsk[i] != 0) {
				break;
			}
		}
		return ins.getOffset() + i + 1;
	}

	@Override
	public AssemblyPatternBlock getInstruction() {
		return ins;
	}

	@Override
	public AssemblyPatternBlock getContext() {
		return ctx;
	}

	@Override
	public MaskedLong readInstruction(int start, int len) {
		return ins.readBytes(start, len);
	}

	@Override
	public MaskedLong readContext(int start, int len) {
		return ctx.readBytes(start, len);
	}

	@Override
	public boolean isError() {
		return false;
	}

	@Override
	public boolean isBackfill() {
		return false;
	}

	@Override
	public boolean hasChildren() {
		return super.hasChildren() || hasBackfills() || hasForbids();
	}

	@Override
	protected String childrenToString(String indent) {
		StringBuilder sb = new StringBuilder();
		if (super.hasChildren()) {
			sb.append(super.childrenToString(indent) + "\n");
		}
		for (AssemblyResolvedBackfill bf : backfills) {
			sb.append(indent);
			sb.append("backfill: " + bf + "\n");
		}
		for (AssemblyResolvedPatterns f : forbids) {
			sb.append(indent);
			sb.append("forbidden: " + f + "\n");
		}
		return sb.substring(0, sb.length() - 1);
	}

	protected static final Pattern pat = Pattern.compile("line(\\d*)");

	@Override
	public String dumpConstructorTree() {
		StringBuilder sb = new StringBuilder();
		if (cons == null) {
			return null;
		}
		sb.append(cons.getSourceFile() + ":" + cons.getLineno());

		if (children == null) {
			return sb.toString();
		}

		List<String> subs = new ArrayList<>();
		for (AssemblyResolution c : children) {
			if (c instanceof AssemblyResolvedPatterns) {
				AssemblyResolvedPatterns rc = (AssemblyResolvedPatterns) c;
				String s = rc.dumpConstructorTree();
				if (s != null) {
					subs.add(s);
				}
			}
		}

		if (subs.isEmpty()) {
			return sb.toString();
		}
		sb.append('[');
		sb.append(StringUtils.join(subs, ","));
		sb.append(']');
		return sb.toString();
	}

	/**
	 * Count the number of bits specified in the resolution patterns
	 * 
	 * <p>
	 * Totals the specificity of the instruction and context pattern blocks.
	 * 
	 * @return the number of bits in the resulting patterns
	 * @see AssemblyPatternBlock#getSpecificity()
	 */
	public int getSpecificity() {
		return ins.getSpecificity() + ctx.getSpecificity();
	}

	@Override
	public Iterable<byte[]> possibleInsVals(AssemblyPatternBlock forCtx) {
		AssemblyPatternBlock ctxCompat = ctx.combine(forCtx);
		if (ctxCompat == null) {
			return List.of();
		}
		Predicate<byte[]> removeForbidden = (byte[] val) -> {
			for (AssemblyResolvedPatterns f : forbids) {
				// If the forbidden length is larger than us, we can ignore it
				if (f.getDefinedInstructionLength() > val.length) {
					continue;
				}
				// Check if the context matches, if not, we can let it pass
				if (null == f.getContext().combine(forCtx)) {
					continue;
				}
				// If the context matches, now check the instruction
				AssemblyPatternBlock i = f.getInstruction();
				AssemblyPatternBlock vi =
					AssemblyPatternBlock.fromBytes(ins.length() - val.length, val);
				if (null == i.combine(vi)) {
					continue;
				}
				return false;
			}
			return true;
		};
		return new Iterable<byte[]>() {
			@Override
			public Iterator<byte[]> iterator() {
				return IteratorUtils.filteredIterator(ins.possibleVals().iterator(),
					removeForbidden);
			}
		};
	}

	protected static int getOpIndex(String piece) {
		if (piece.charAt(0) != '\n') {
			return -1;
		}
		return piece.charAt(1) - 'A';
	}

	/**
	 * If the construct state is a {@code ^instruction} or other purely-recursive constructor, get
	 * its single child.
	 * 
	 * @param state the parent state
	 * @return the child state if recursive, or null
	 */
	protected static ConstructState getPureRecursion(ConstructState state) {
		// NB. There can be other operands, but only one can be printed
		// Furthermore, nothing else can be printed, whether an operand or not
		List<String> pieces = state.getConstructor().getPrintPieces();
		if (pieces.size() != 1) {
			return null;
		}
		int opIdx = getOpIndex(pieces.get(0));
		if (opIdx < 0) {
			return null;
		}
		ConstructState sub = state.getSubState(opIdx);
		if (sub == null || sub.getConstructor() == null ||
			sub.getConstructor().getParent() != state.getConstructor().getParent()) {
			// not recursive
			return null;
		}
		return sub;
	}

	@Override
	public boolean equivalentConstructState(ConstructState state) {
		ConstructState rec = getPureRecursion(state);
		if (rec != null) {
			if (state.getConstructor() == cons) {
				assert children.size() == 1;
				AssemblyResolvedPatterns recRes = (AssemblyResolvedPatterns) children.get(0);
				return recRes.equivalentConstructState(rec);
			}
			return equivalentConstructState(rec);
		}
		if (state.getConstructor() != cons) {
			return false;
		}
		int opCount = cons.getNumOperands();
		for (int opIdx = 0; opIdx < opCount; opIdx++) {
			OperandSymbol opSym = cons.getOperand(opIdx);
			Set<Integer> printed =
				Arrays.stream(cons.getOpsPrintOrder()).boxed().collect(Collectors.toSet());
			if (!(opSym.getDefiningSymbol() instanceof SubtableSymbol)) {
				AssemblyTreeResolver.DBG.println("Operand " + opSym + " is not a sub-table");
				continue;
			}
			if (!printed.contains(opIdx)) {
				AssemblyTreeResolver.DBG.println("Operand " + opSym + " is hidden");
				continue;
			}
			AssemblyResolvedPatterns child = (AssemblyResolvedPatterns) children.get(opIdx);
			ConstructState subState = state.getSubState(opIdx);
			if (!child.equivalentConstructState(subState)) {
				return false;
			}
		}
		return true;
	}

	public Constructor getConstructor() {
		return cons;
	}

	@Override
	public Set<AssemblyResolvedBackfill> getBackfills() {
		return backfills;
	}

	@Override
	public Set<AssemblyResolvedPatterns> getForbids() {
		return forbids;
	}
}
