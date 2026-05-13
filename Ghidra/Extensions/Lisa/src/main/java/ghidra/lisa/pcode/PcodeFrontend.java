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

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.lisa.gui.LisaOptions;
import ghidra.lisa.pcode.contexts.HighUnitContext;
import ghidra.lisa.pcode.contexts.UnitContext;
import ghidra.lisa.pcode.locations.PcodeLocation;
import ghidra.lisa.pcode.types.PcodeTypeSystem;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.task.TaskMonitor;
import it.unive.lisa.program.Program;
import it.unive.lisa.program.cfg.*;
import it.unive.lisa.program.cfg.Parameter;
import it.unive.lisa.program.cfg.statement.Statement;
import it.unive.lisa.type.Untyped;

/**
 * Instantiated {@link PcodeCodeMemberVisitor} that will parse the pcode building a
 * representation that can be analyzed through LiSA.
 */
public class PcodeFrontend {

	//private static final Logger log = LogManager.getLogger(PcodeFrontend.class);

	private PluginTool tool;
	private ToolOptions options;
	private final Program program;
	private Map<Address, Set<Statement>> nodeMap = new HashMap<>();
	private Map<Address, CFG> targets = new HashMap<>();
	private Set<CFG> cfgs = new HashSet<>();

	// High Pcode-only
	private final Map<Function, HighFunction> decompCache = new HashMap<>();
	private String simplificationStyle;

	public PcodeFrontend(PluginTool tool) {
		this.tool = tool;
		ToolOptions[] optionsList = tool.getOptions();
		for (ToolOptions opt : optionsList) {
			if (opt.getName().equals("Abstract Interpretation")) {
				this.options = opt;
				simplificationStyle =
					options.getString(LisaOptions.OP_KEY_LISA_ANALYSIS_SIMPLIFICATION_STYLE,
						LisaOptions.DEFAULT_LISA_ANALYSIS_SIMPLIFICATION_STYLE);
			}
		}
		program = new Program(new PcodeFeatures(), new PcodeTypeSystem());
	}

	public Program doWork(Listing listing, Address startAddress, boolean useHighPcode) {

		Program p = visitListing(listing, startAddress, useHighPcode);

		Collection<CFG> baseline = p.getAllCFGs();
		for (CFG cfg : cfgs) {
			if (baseline.contains(cfg)) {
				p.addEntryPoint(cfg);
			}
		}
		return p;
	}

	public Program visitListing(Listing listing, Address startAddress, boolean useHighPcode) {
		Program p = getProgram();
		for (Function f : listing.getFunctions(startAddress, false)) {
			CFG cfg = visitFunction(f, startAddress, useHighPcode);
			cfgs.add(cfg);
		}
		return p;
	}

	public CFG visitFunction(Function f, Address start, boolean useHighPcode) {
		Program p = getProgram();
		UnitContext ctx = getUnitContext(f, start, useHighPcode);

		CodeMemberDescriptor descr = mkDescriptor(ctx);
		PcodeCodeMemberVisitor visitor =
			new PcodeCodeMemberVisitor(descr, ctx.getListing());
		CFG cfg = visitor.visitCodeMember(ctx);
		Collection<Statement> nodes = cfg.getNodes();
		for (Statement statement : nodes) {
			Address addr = toAddr(statement.getLocation());
			nodeMap.computeIfAbsent(addr, a -> new HashSet<>()).add(statement);
		}

		targets.put(f.getEntryPoint(), cfg);
		cfgs.add(cfg);

		ctx.unit().addCodeMember(cfg);
		p.addUnit(ctx.unit());
		return cfg;
	}

	private UnitContext getUnitContext(Function f, Address start, boolean useHighPcode) {
		if (useHighPcode) {
			DecompInterface decomp = null;
			try {
				decomp = new DecompInterface();
				decomp.toggleSyntaxTree(true);
				decomp.setSimplificationStyle(simplificationStyle);

				DecompileOptions opts = DecompilerUtils.getDecompileOptions(tool, f.getProgram());
				decomp.setOptions(opts);

				decomp.openProgram(f.getProgram());
				DecompileResults results =
					decomp.decompileFunction(f, opts.getDefaultTimeout(), TaskMonitor.DUMMY);
				HighFunction hfunc = results.getHighFunction();
				return new HighUnitContext(this, program, f, hfunc, start);
			}
			finally {
				if (decomp != null) {
					decomp.closeProgram();
					decomp.dispose();
				}
			}
		}

		return new UnitContext(this, program, f, start);
	}

	private Address toAddr(CodeLocation location) {
		if (location instanceof PcodeLocation loc) {
			return loc.op.getSeqnum().getTarget();
		}
		return null;
	}

	private CodeMemberDescriptor mkDescriptor(UnitContext ctx) {
		Parameter[] params = computeParameters(ctx);
		CodeMemberDescriptor descriptor = new CodeMemberDescriptor(
			ctx.location(),
			ctx.unit(),
			false, ctx.getText(), Untyped.INSTANCE,
			params);

		descriptor.setOverridable(!ctx.isFinal());
		return descriptor;
	}

	private Parameter[] computeParameters(UnitContext ctx) {
		Function f = ctx.function();
		ProgramContext programContext = f.getProgram().getProgramContext();
		Set<Parameter> pset = new HashSet<>();
		for (Register r : programContext.getRegisters()) {
			RegisterValue rv = programContext.getRegisterValue(r, f.getEntryPoint());
			if (rv != null && rv.hasValue()) {
				Parameter p = new Parameter(ctx.location(), r.getAddress().toString());
				pset.add(p);
			}
		}
		Parameter[] params = new Parameter[pset.size() + 1];
		int index = 0;
		params[index++] = new Parameter(ctx.location(), ctx.getText());
		for (Parameter p : pset) {
			params[index++] = p;
		}
		return params;
	}

	public Program getProgram() {
		return program;
	}

	public Set<Statement> getStatement(Address addr) {
		return nodeMap.get(addr);
	}

	public boolean hasProcessed(Function f) {
		if (f == null) {
			return false;
		}
		return targets.containsKey(f.getEntryPoint());
	}

	public void clearTargets() {
		targets.clear();
	}

	public CFG getTarget(Address entryPoint) {
		return targets.get(entryPoint);
	}

	public Map<Address, CFG> getTargets() {
		return targets;
	}

}
