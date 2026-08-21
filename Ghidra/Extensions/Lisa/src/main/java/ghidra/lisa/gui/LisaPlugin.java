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
package ghidra.lisa.gui;

import java.util.*;

import db.Transaction;
import docking.action.builder.ActionBuilder;
import ghidra.GhidraOptions;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.location.DefaultDecompilerLocation;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompiler.absint.AbstractInterpretationService;
import ghidra.app.plugin.core.decompiler.taint.*;
import ghidra.app.plugin.core.decompiler.taint.TaintState.MarkType;
import ghidra.app.script.AskDialog;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.lisa.gui.LisaOptions.*;
import ghidra.lisa.pcode.PcodeFrontend;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.PcodeFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.DummyCancellableTaskMonitor;
import ghidra.util.task.TaskMonitor;
import it.unive.lisa.*;
import it.unive.lisa.interprocedural.InterproceduralAnalysis;
import it.unive.lisa.program.cfg.CFG;
import it.unive.lisa.program.cfg.statement.Statement;

/**
 * Plugin for tracking taint through the decompiler.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "LisaTest",
	description = "Plugin for abstract interpretation analysis via LiSA",
	servicesProvided = { AbstractInterpretationService.class },
	servicesRequired = {
		TaintService.class,
	},
	eventsConsumed = {
		ProgramActivatedPluginEvent.class, ProgramOpenedPluginEvent.class,
		ProgramLocationPluginEvent.class, ProgramSelectionPluginEvent.class,
		ProgramClosedPluginEvent.class
	})
//@formatter:on

public class LisaPlugin extends ProgramPlugin implements OptionsChangeListener, AbstractInterpretationService {
	
	private static final String OPTIONS_TITLE = "Abstract Interpretation";
	public HeapDomainOption heapOption = HeapDomainOption.DEFAULT;
	public TypeDomainOption typeOption = TypeDomainOption.DEFAULT;
	public ValueDomainOption valueOption = ValueDomainOption.DEFAULT;

	private Function currentFunction;

	private InterproceduralAnalysis<?> ipa;
	private PcodeFrontend frontend;
	private LiSA lisa;

	private LisaOptions options;
	private TaintPlugin taintPlugin;
	private LisaTaintState taintState;
	private TaskMonitor monitor = TaskMonitor.DUMMY;
	private String lastValue = "";

	public LisaPlugin(PluginTool tool) {
		super(tool);
		setOptions(new LisaOptions(this));
		createActions();
	}

	public Function getCurrentFunction() {
		return currentFunction;
	}

	@Override
	protected void programActivated(Program program) {
		currentProgram = program;
		initOptions();
	}


	public interface AddCfgsAction {
		String NAME = "Add CFG";
		String DESCRIPTION = "Compute called CFGs prior to analysis";
		String HELP_ANCHOR = "add_cfgs";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.popupMenuPath("Abstract Interpretation", NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	public interface ClearCfgsAction {
		String NAME = "Clear CFGs";
		String DESCRIPTION = "Clear CFGs prior to analysis";
		String HELP_ANCHOR = "clear_cfgs";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.popupMenuPath("Abstract Interpretation", NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	public interface SetTaintAction {
		String NAME = "Set Taint";
		String DESCRIPTION = "Set taint for given varnode";
		String HELP_ANCHOR = "set_taint";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.popupMenuPath("Abstract Interpretation", NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}


	private void createActions() {

		AddCfgsAction.builder(this)
			.withContext(ProgramLocationActionContext.class)
			.onAction(this::addCfgs)
			.buildAndInstall(tool);
		
		ClearCfgsAction.builder(this)
		.withContext(ProgramLocationActionContext.class)
		.onAction(this::clearCfgs)
		.buildAndInstall(tool);

		SetTaintAction.builder(this)
		.withContext(ProgramLocationActionContext.class)
		.onAction(this::setTaint)
		.buildAndInstall(tool);

	}


	@Override
	public Program getCurrentProgram() {
		return currentProgram;
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);

		//Msg.info(this, "TaintPlugin -> processEvent: " + event.toString() );

		if (event instanceof ProgramClosedPluginEvent closedEvent) {
			Program program = closedEvent.getProgram();
			if (currentProgram != null && currentProgram.equals(program)) {
				currentProgram = null;
			}
			return;
		}


		if (event instanceof ProgramActivatedPluginEvent activatedEvent) {
			currentProgram = activatedEvent.getActiveProgram();
			if (currentProgram != null) {
				SpecExtension.registerOptions(currentProgram);
			}

		}
		else if (event instanceof ProgramLocationPluginEvent locEvent) {

			// user changed their location in the program; this may be a function change.

			ProgramLocation location = locEvent.getLocation();
			Address address = location.getAddress();

			if (address.isExternalAddress()) {
				// ignore external functions when it comes to taint.
				return;
			}

			if (currentProgram != null) {
				// The user loaded a program for analysis.
				Listing listing = currentProgram.getListing();
				Function f = listing.getFunctionContaining(address);
				// We are in function f
				if (currentFunction == null || !currentFunction.equals(f)) {
					// In the PAST we were in a function and the program location moved us into a new function.
					String cfun = "NULL";
					String nfun = "NULL";

					if (currentFunction != null) {
						cfun = currentFunction.getEntryPoint().toString();
					}

					if (f != null) {
						nfun = f.getEntryPoint().toString();
					}

					Msg.info(this, "Changed from function: " + cfun + " to function " + nfun);
					currentFunction = f;
				}
			}
		}
	}

	private void addCfgs(ProgramLocationActionContext context) {
		Set<CFG> cfgs = new HashSet<>();
		Address addr = context.getAddress();
		FunctionManager functionManager = currentProgram.getFunctionManager();
		Function f = functionManager.getFunctionContaining(addr);
		addCfg(cfgs, f, true);
	}
	
	private void addCfg(Set<CFG> cfgs, Function f, boolean recurse) {
		if (frontend == null) {
			initProgram();
		}
		int depth = recurse ? getOptions().getCfgDepth() : 0;
		addFunction(cfgs, f);
		addCalledFunctions(cfgs, f, depth);
		
		it.unive.lisa.program.Program p = frontend.getProgram();
		Collection<CFG> baseline = p.getAllCFGs();
		for (CFG g : cfgs) {
			if (baseline.contains(g)) {
				p.addEntryPoint(g);
			}
		}
	}

	private void addFunction(Set<CFG> cfgs, Function f) {
		if (frontend.hasProcessed(f) || monitor.isCancelled()) {
			return;
		}
		Msg.info(this, "Adding "+f);
		CFG cfg = frontend.visitFunction(f, f.getEntryPoint(), options.isHighPcode());
		cfgs.add(cfg);
	}

	private void addCalledFunctions(Set<CFG> cfgs, Function f, int depth) {
		if (depth == 0 || frontend.hasProcessed(f) || monitor.isCancelled()) {
			return;
		}
		Set<Function> calledFunctions = f.getCalledFunctions(new DummyCancellableTaskMonitor());
		for (Function func : calledFunctions) {
			if (func.isThunk()) {
				continue;
			}
			Address entryPoint = func.getEntryPoint();
			if (entryPoint.getAddressSpace().equals(f.getEntryPoint().getAddressSpace())) {
				addFunction(cfgs, func);
				addCalledFunctions(cfgs, func, depth-1);
			}
		}
	}
	
	protected void clearCfgs(ProgramLocationActionContext context) {
		initProgram();
		frontend.clearTargets();
	}
	
	private void setTaint(ProgramLocationActionContext context) {
		if (!checkTaintState()) {
			return;
		}
		taintState.clearAnnotations();
		BookmarkManager bookmarkManager = currentProgram.getBookmarkManager();
		try (Transaction tx = currentProgram.openTransaction("clear bookmark")) {
			bookmarkManager.removeBookmarks(BookmarkType.INFO, "Taint Source", TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			throw new AssertionError("Unreachable code");
		}
		Address addr = context.getAddress();
		FunctionManager functionManager = currentProgram.getFunctionManager();
		Function f = functionManager.getFunctionContaining(addr);
		ProgramLocation location = context.getLocation();
		int row = location.getRow();
		int offset = location.getCharOffset();
		
		String tokenId = null;
		if (location instanceof PcodeFieldLocation pfl) {
			List<String> pcodeStrings = pfl.getPcodeStrings();
			String test = pcodeStrings.get(row);
			int lastSpace= test.lastIndexOf(" ");
			int index = offset > lastSpace ? 1 : 0;
			Instruction inst = currentProgram.getListing().getInstructionContaining(addr);
			PcodeOp[] pcode = inst.getPcode();
			PcodeOp op = pcode[row];
			if (index >= op.getNumInputs()) {
				index--;
			}
			Varnode vn = op.getInput(index);
			tokenId = vn.getAddress().toString();
		}
		else if (location instanceof DefaultDecompilerLocation ddl) {
			ClangToken token = ddl.getToken();
			taintPlugin.toggleIcon(MarkType.SOURCE, token, false);
			return;  // taint is set via the token
		}
		else {
			AskDialog<String> dialog = new AskDialog<>("Abstract Interpretation Taint", "Varnode address", AskDialog.STRING, lastValue);
			if (dialog.isCanceled()) {
				return;
			}
			tokenId = dialog.getValueAsString();
		}
		try (Transaction tx = currentProgram.openTransaction("set bookmark")) {
			bookmarkManager.setBookmark(addr, BookmarkType.INFO, "Taint Source", tokenId);
		}
		taintState.setTaint(MarkType.SOURCE, f, addr, tokenId);
	}
	
	private boolean checkTaintState() {
		if (taintState == null) {
			// ability to add custom margins to the decompiler view
			TaintService service = tool.getService(TaintService.class);
			if (service instanceof TaintPlugin taint) {
				this.taintPlugin = taint;
				TaintState state = taint.getTaintState();
				if (state instanceof LisaTaintState ts) {
					this.taintState = ts;
					return true;
				}
			}
		}
		else {
			return true;
		}
		return false;
	}

	public Map<Function, Collection<?>> performAnalysis(TaskMonitor tm) {
		this.monitor = tm;
		if (currentFunction == null) {
			Msg.error(this, "Not currently in a function");
			return null;
		}
		try {
			addCfg(new HashSet<>(), currentFunction, true);
			initLisa();
			it.unive.lisa.program.Program p = frontend.getProgram();
			Map<Function, Collection<?>> combined = new HashMap<>();
			if (monitor.isCancelled()) {
				return combined;
			}
			LiSAReport report = lisa.run(p);
			ipa = report.getConfiguration().interproceduralAnalysis;
			
			FunctionManager functionManager = currentProgram.getFunctionManager();
			Map<Address, CFG> targets = frontend.getTargets();
			for (Address entry : targets.keySet()) {
				if (monitor.isCancelled()) {
					break;
				}
				Function f = functionManager.getFunctionAt(entry);
				CFG cfg = targets.get(entry);
				Collection<?> res = ipa.getAnalysisResultsOf(cfg);
				combined.put(f, res);
			}
			return combined;
		} catch (AnalysisException e) {
			Msg.error(this, e.getMessage());
		}
		return null;
	}
	
	public Collection<Statement> getStatements(Function f) {
		addCfg(new HashSet<>(), f, false);
		CFG cfg = frontend.getTarget(f.getEntryPoint());
		return cfg.getNodes();
	}

	private void initProgram() {
		frontend = new PcodeFrontend(this.getTool());
	}
	
	@SuppressWarnings("unchecked")
	private void initLisa() {
		LisaOptions opt = getOptions();
		heapOption = opt.getHeapOption();
		typeOption = opt.getTypeOption();
		valueOption = opt.getValueOption();
		
		DefaultConfiguration conf = new DefaultConfiguration();
		conf.abstractState = DefaultConfiguration.simpleState(
				heapOption.getDomain(),
				valueOption.getDomain(currentProgram),
				typeOption.getDomain());
		conf.interproceduralAnalysis = opt.getInterproceduralOption().getAnalysis();
		conf.descendingPhaseType = opt.getDescendingPhaseOption().getType();
		conf.openCallPolicy = opt.getCallOption().getPolicy();
		conf.analysisGraphs = opt.getGraphOption().getType();
		conf.callGraph = opt.getCallGraphOption().getCallGraph();
		conf.serializeResults = opt.isSerialize();
		conf.optimize = opt.isOptimize();
		String outputDir = opt.getOutputDir();
		if (!outputDir.equals(LisaOptions.DEFAULT_LISA_ANALYSIS_OUTDIR)) {
			conf.workdir = outputDir;
		}

		lisa = new LiSA(conf);
	}

	private void initOptions() {
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		getOptions().registerOptions(this, opt, currentProgram);

		opt.addOptionsChangeListener(this);

		ToolOptions codeBrowserOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		codeBrowserOptions.addOptionsChangeListener(this);
	}
	
	@Override
	public void optionsChanged(ToolOptions opts, String optionName, Object oldValue,
			Object newValue) {
		if (opts.getName().equals(OPTIONS_TITLE) ||
			opts.getName().equals(GhidraOptions.CATEGORY_BROWSER_FIELDS)) {
			doRefresh();
		}
	}

	private void doRefresh() {
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		getOptions().grabFromToolAndProgram(this, opt, currentProgram);
	}
	
	@Override
	public String getActiveQueryName() {
		String queryName = valueOption.toString();
		if (!heapOption.equals(HeapDomainOption.DEFAULT)) {
			queryName += ":"+heapOption.toString();
		}
		if (!typeOption.equals(TypeDomainOption.DEFAULT)) {
			queryName += ":"+typeOption.toString();
		}
		if (currentFunction != null) {
			queryName += " @ " + currentFunction;
		}
		return queryName;
	}

	public LisaOptions getOptions() {
		return options;
	}

	public void setOptions(LisaOptions options) {
		this.options = options;
	}

}
