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
package ghidra.app.plugin.core.decompiler.taint;

import java.awt.Color;
import java.util.*;

import javax.swing.Icon;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import generic.theme.GIcon;
import ghidra.app.CorePluginPackage;
import ghidra.app.decompiler.*;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.plugin.core.decompiler.taint.TaintState.MarkType;
import ghidra.app.plugin.core.decompiler.taint.TaintState.TaskType;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import resources.Icons;
import sarif.SarifService;

/**
 * Plugin for tracking taint through the decompiler.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "DecompilerTaint",
	description = "Plugin for tracking taint through the decompiler",
	servicesProvided = { TaintService.class },
	servicesRequired = {
		DecompilerHighlightService.class, 
		DecompilerMarginService.class,
		ConsoleService.class,
		SarifService.class
	},
	eventsConsumed = {
		ProgramActivatedPluginEvent.class, ProgramOpenedPluginEvent.class,
		ProgramLocationPluginEvent.class, ProgramSelectionPluginEvent.class,
		ProgramClosedPluginEvent.class
	})
//@formatter:on

public class TaintPlugin extends ProgramPlugin implements TaintService {
	
	public final static String HELP_LOCATION = "DecompilerTaint";

	private Function currentFunction;
	private DecompilerMarginService marginService;
	private ConsoleService consoleService;
	private SarifService sarifService;

	// Source-Sink Specific.
	private TaintProvider taintProvider;
	private TaintDecompilerMarginProvider taintDecompMarginProvider;

	public static enum Highlighter {
		ALL("all", "variables"), LABELS("labels", "labels"), DEFAULT("default", "default");

		private String label;
		private String optionString;

		private Highlighter(String optString, String label) {
			this.label = label;
			this.optionString = optString;
		}

		public String getOptionString() {
			return optionString;
		}

		@Override
		public String toString() {
			return label;
		}
	}

	public static enum TaintFormat {
		ALL("all", "sarif+all"), 
		GRAPHS("graphs", "sarif+graphs"), 
		INSTS("insts", "sarif+instructions"),
		PATHS("paths", "sarif"),
		NONE("none", "none");

		private String label;
		private String optionString;

		private TaintFormat(String optString, String label) {
			this.label = label;
			this.optionString = optString;
		}

		public String getOptionString() {
			return optionString;
		}

		@Override
		public String toString() {
			return label;
		}
	}

	public static enum TaintDirection {
		BOTH("all", "both"), FORWARD("fwd", "forward"), BACKWARD("bwd", "backward"), DEFAULT("auto", "auto");

		private String label;
		private String optionString;

		private TaintDirection(String optString, String label) {
			this.label = label;
			this.optionString = optString;
		}

		public String getOptionString() {
			return optionString;
		}

		@Override
		public String toString() {
			return label;
		}
	}

	// shift over to multiple highlighters
	private DecompilerHighlightService highlightService;

	private TaintState state;

	// Taint Tree Provider Stuff
	static final String SHOW_TAINT_TREE_ACTION_NAME = "Taint Slice Tree";
	public static final Icon PROVIDER_ICON = Icons.ARROW_DOWN_RIGHT_ICON;
	public static final Icon FUNCTION_ICON = new GIcon("icon.plugin.calltree.function");
	public static final Icon RECURSIVE_ICON = new GIcon("icon.plugin.calltree.recursive");

	// You may want MANY slice tree gui elements to explore different slices within a program.
	// This list should keep track of them all.

	private Map<String, TaintSliceTreeProvider> taintTreeProviders = new HashMap<>();

	static final Logger log = LogManager.getLogger(TaintPlugin.class);

	public TaintPlugin(PluginTool tool) {
		super(tool);
		taintProvider = new TaintProvider(this);
		taintDecompMarginProvider = new TaintDecompilerMarginProvider(this);
		createActions();

		// No PRIMARY NEEDED.
	}

	public void showOrCreateNewSliceTree(Program program, ClangToken tokenAtCursor,
			HighVariable highVariable) {

		Msg.info(this, "showOrCreateNewSliceTree");

		if (program == null) {
			return;
		}

		String treeProviderKey =
			highVariable != null ? highVariable.toString() : tokenAtCursor.toString();

		// We will have a taint tree for each variable we are interested in.
		TaintSliceTreeProvider provider = taintTreeProviders.get(treeProviderKey);
		if (provider != null) {
			// Show a previous composed provider.
			tool.showComponentProvider(provider, true);
			return;
		}

		// did not find a provider for the key. 

		if (highVariable == null) {
			// just use the tokenAtCursor (must be a function??)
			createAndShowProvider(tokenAtCursor);
			return;
		}

		createAndShowProvider(highVariable);
	}

	// Taint Tree
	private void createAndShowProvider(ClangToken token) {
		TaintSliceTreeProvider provider = new TaintSliceTreeProvider(this, false);
		taintTreeProviders.put(token.toString(), provider);
		tool.showComponentProvider(provider, true);
	}

	// Taint Tree
	private void createAndShowProvider(HighVariable highVar) {
		TaintSliceTreeProvider provider = new TaintSliceTreeProvider(this, false);
		taintTreeProviders.put(highVar.toString(), provider);
		provider.initialize(currentProgram, currentLocation);
		tool.showComponentProvider(provider, true);
	}

	// Taint Tree
	public ProgramLocation getCurrentLocation() {
		return currentLocation;
	}

	// Taint Tree
	public void removeProvider(TaintSliceTreeProvider provider) {

		for (Map.Entry<String, TaintSliceTreeProvider> mapping : taintTreeProviders.entrySet()) {
			if (provider == mapping.getValue()) {
				taintTreeProviders.remove(mapping.getKey());
				tool.removeComponentProvider(mapping.getValue());
				mapping.getValue().dispose();
				return;
			}
		}

	}

	// Taint Tree
	@Override
	protected void programDeactivated(Program program) {
		for (TaintSliceTreeProvider provider : taintTreeProviders.values()) {
			provider.programDeactivated(program);
		}
	}

	// Taint Tree
	@Override
	protected void programClosed(Program program) {
		for (TaintSliceTreeProvider provider : taintTreeProviders.values()) {
			provider.programClosed(program);
		}
	}

	// Taint Tree
	public Function getFunction(ProgramLocation location) {
		FunctionManager functionManager = currentProgram.getFunctionManager();
		Address address = location.getAddress();
		Function function = functionManager.getFunctionContaining(address);
		function = resolveFunction(function, address);
		return function;
	}

	public Function getCurrentFunction() {
		return currentFunction;
	}

	/**
	 * Apparently, we create fake function markup for external functions.  Thus, there is no
	 * real function at that address and our plugin has to do some work to find out where
	 * we 'hang' references to the external function, which is itself a Function.  These 
	 * fake function will usually just be a pointer to another function.
	 * 
	 * @param function the function to resolve; if it is not null, then it will be used
	 * @param address the address for which to find a function
	 * @return either the given function if non-null, or a function being referenced from the
	 *         given address.
	 */
	Function resolveFunction(Function function, Address address) {
		if (function != null) {
			return function;
		}

		// maybe we point to another function?
		FunctionManager functionManager = currentProgram.getFunctionManager();
		ReferenceManager referenceManager = currentProgram.getReferenceManager();
		Reference[] references = referenceManager.getReferencesFrom(address);
		for (Reference reference : references) {
			Address toAddress = reference.getToAddress();
			Function toFunction = functionManager.getFunctionAt(toAddress);
			if (toFunction != null) {
				return toFunction;
			}
		}

		return null;
	}

	@Override
	protected void dispose() {
		List<TaintSliceTreeProvider> copy = new ArrayList<>(taintTreeProviders.values());
		for (TaintSliceTreeProvider provider : copy) {
			removeProvider(provider);
		}

	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		for (TaintSliceTreeProvider provider : taintTreeProviders.values()) {
			provider.setLocation(loc);
		}
	}

	@Override
	protected void programActivated(Program program) {
		currentProgram = program;
		for (TaintSliceTreeProvider provider : taintTreeProviders.values()) {
			provider.programActivated(program);
		}
	}

	@Override
	public void init() {
		// DO NOTHING
	}

	/*
	 * 1. Run the pcode extracter.
	 * 2. Run the indexer.
	 * 3. Run import a SarifFile and pop the table.
	 */
	private void createActions() {

		TaintPlugin plugin = this;

		DockingAction exportAllAction = new DockingAction("ExportFacts", HELP_LOCATION) {

			@Override
			public void actionPerformed(ActionContext context) {
				GhidraState ghidraState = new GhidraState(tool, null, currentProgram,
					currentLocation, currentHighlight, currentHighlight);
				GhidraScript exportScript = state.getExportScript(consoleService, false);
				if (exportScript != null) {
					RunPCodeExportScriptTask export_task =
						new RunPCodeExportScriptTask(tool, exportScript, ghidraState, consoleService);
					tool.execute(export_task);
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return plugin.getCurrentProgram() != null;
			}

		};

		exportAllAction.setMenuBarData(
			new MenuData(new String[] { "Tools", "Source-Sink", "Export PCode Facts" }));

		DockingAction saveTableDataAction = new DockingAction("InitializeIndex", HELP_LOCATION) {
			@Override
			public void actionPerformed(ActionContext context) {
				CreateTargetIndexTask index_task =
					new CreateTargetIndexTask(plugin, plugin.getCurrentProgram());
				tool.execute(index_task);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return plugin.getCurrentProgram() != null;
			}
		};

		saveTableDataAction.setMenuBarData(
			new MenuData(new String[] { "Tools", "Source-Sink", "Initialize Program Index" }));

		DockingAction deleteFactsAndIndex = new DockingAction("DeleteIndex", HELP_LOCATION) {
			@Override
			public void actionPerformed(ActionContext context) {
				PurgeIndexTask index_task = new PurgeIndexTask(plugin, plugin.getCurrentProgram());
				tool.execute(index_task);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return plugin.getCurrentProgram() != null;
			}
		};

		deleteFactsAndIndex.setMenuBarData(
			new MenuData(new String[] { "Tools", "Source-Sink", "Delete Facts and Index" }));

		DockingAction exportFuncAction = new DockingAction("ReexportFacts", HELP_LOCATION) {

			@Override
			public void actionPerformed(ActionContext context) {
				GhidraState ghidraState = new GhidraState(tool, null, currentProgram,
					currentLocation, currentHighlight, currentHighlight);
				GhidraScript exportScript = state.getExportScript(consoleService, true);
				RunPCodeExportScriptTask export_task =
					new RunPCodeExportScriptTask(tool, exportScript, ghidraState, consoleService);
				tool.execute(export_task);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return plugin.getCurrentProgram() != null;
			}

		};

		exportFuncAction.setMenuBarData(
			new MenuData(new String[] { "Tools", "Source-Sink", "Re-export Function Facts" }));

		tool.addAction(deleteFactsAndIndex);
		tool.addAction(exportAllAction);
		tool.addAction(exportFuncAction);
		tool.addAction(saveTableDataAction);
	}

	public TaintState getTaintState() {
		return state;
	}

	public void setTaintState(TaintState state) {
		this.state = state;
	}

	public TaintProvider getProvider() {
		return taintProvider;
	}

	public TaintOptions getOptions() {
		return taintProvider.getOptions();
	}

	@Override
	public Program getCurrentProgram() {
		return currentProgram;
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);

		//Msg.info(this, "TaintPlugin -> processEvent: " + event.toString() );

		if (event instanceof ProgramClosedPluginEvent) {
			Program program = ((ProgramClosedPluginEvent) event).getProgram();
			if (currentProgram != null && currentProgram.equals(program)) {
				currentProgram = null;
				taintProvider.doSetProgram(null);
			}
			return;
		}

		if (taintProvider == null) {
			return;
		}

		if (event instanceof ProgramActivatedPluginEvent) {
			currentProgram = ((ProgramActivatedPluginEvent) event).getActiveProgram();
			taintProvider.doSetProgram(currentProgram);
			if (currentProgram != null) {
				SpecExtension.registerOptions(currentProgram);
			}

		}
		else if (event instanceof ProgramLocationPluginEvent) {

			// user changed their location in the program; this may be a function change.

			taintProvider.contextChanged();
			ProgramLocation location = ((ProgramLocationPluginEvent) event).getLocation();
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
					taintDecompMarginProvider.functionChanged();
					taintProvider.setTaint();
				}
			}
		}
	}

	private class VertexHighlighter implements CTokenHighlightMatcher {

		@Override
		public Color getTokenHighlight(ClangToken token) {
			if (currentFunction == null || token == null) {
				//log.info("Highlighter> currentFunction == null || token == null");
				return null;
			}

			HighFunction highFunction = token.getClangFunction().getHighFunction();
			if (highFunction == null) {
				return null;
			}

			if (!currentFunction.getEntryPoint()
					.equals(highFunction.getFunction().getEntryPoint())) {
				return null;
			}

			if (taintProvider.matchOn(token)) {
				log.info("Highlighter> MATCHED Token: '{}'", token.getText());
				state.augmentAddressSet(token);
				return taintProvider.getHighlightColor(token);
			}

			return null;
		}

	}

	private class TaintLabelHighlighter implements CTokenHighlightMatcher {

		@Override
		public Color getTokenHighlight(ClangToken token) {
			if (currentFunction == null || token == null) {
				//log.info("Highlighter> currentFunction == null || token == null");
				return null;
			}

			assert (currentFunction.getEntryPoint()
					.equals(
						token.getClangFunction().getHighFunction().getFunction().getEntryPoint()));

			if (taintProvider.matchOn(token)) {
				log.info("Highlighter> MATCHED Token: '{}'", token.getText());
				return taintProvider.getHighlightColor(token);
			}

			return null;
		}

	}

	/**
	 * The concrete highlighter instances created by Ghidra are ClangDecompilerHighlighters. This class applyHighlights and clearHighlights
	 * using our installed matcher. We are currently caching the query items and the colors that are being applied to maintain consistency in the matcher. There
	 * is no way to reach in to the matcher to clear that cache; this may be useful.  This needs some thought.  One may to do this is to create a completely new highlighter
	 * with a new matcher.  This seems like a bad solution.  The matching itself is done in the TaintProvider which uses TaintState to maintain the current
	 * list of ClangTokens we want to match on based on the query results and filter.
	 * 
	 * <p>
	 * We create a map of highlighters that can be changed via the gui.  This provides different strategies for a user to highlight the taint results.
	 */
	private void initHighlighters() {
		// ability to highlight (with many different colors) the source in the decompiler.
		highlightService = tool.getService(DecompilerHighlightService.class);

		// Start with the ALL highlighter
		CTokenHighlightMatcher matcher = new VertexHighlighter();
		taintProvider.setHighlighter(highlightService, matcher);
	}

	/**
	 * Change the highlighter (token matcher and colors used) to the designated highlighter IF:
	 * <ul><li>
	 * the highlight service has been established.
	 * </li><li>
	 * the highlighter instance has been instantiated and added to the decompHighlighters map.
	 * </li></ul>
	 * 
	 * @param hl - highlighter
	 */
	public void changeHighlighter(Highlighter hl) {
		if (highlightService == null) {
			// if not setup, ignore the change request.
			return;
		}

		CTokenHighlightMatcher matcher =
			hl.equals(Highlighter.LABELS) ? new TaintLabelHighlighter() : new VertexHighlighter();
		taintProvider.setHighlighter(highlightService, matcher);
	}

	/**
	 * Gets several services and sets instance variables to those services.
	 * 
	 * @return The DecompilerMarginService with a TaintDecompilerMarginProvider
	 */
	public DecompilerProvider getDecompilerProvider() {

		if (marginService == null) {
			// ability to add custom margins to the decompiler view
			marginService = tool.getService(DecompilerMarginService.class);
			marginService.addMarginProvider(taintDecompMarginProvider);
		}

		if (highlightService == null) {
			initHighlighters();
		}

		if (consoleService == null) {
			consoleService = tool.getService(ConsoleService.class);
		}

		return (DecompilerProvider) marginService;
	}

	public void toggleIcon(MarkType mtype, ClangToken token, boolean bySymbol) {
		TaintLabel label;
		try {
			label = state.toggleMark(mtype, token);
			label.setBySymbol(bySymbol);
		}
		catch (PcodeException e) {
			e.printStackTrace();
			return;
		}
		taintDecompMarginProvider.toggleIcon(label); // mtype, label.isActive());
		Msg.info(this, "Mark Toggle: " + label.toString());
		consoleMessage("Mark Toggle: " + label.toString());
	}

	public void clearIcons() {
		taintDecompMarginProvider.clearIcons();
	}

	public void toggleMarginIcon(TaintLabel label) {
		taintDecompMarginProvider.toggleIcon(label);
	}

	@Override
	public void clearTaint() {
		taintProvider.clearTaint();
	}

	public void consoleMessage(String msg) {
		consoleService.addMessage(this.getName(), msg);
	}

	public void makeSelection(List<Address> addrs) {
		AddressSet selection = new AddressSet();
		for (Address addr : addrs) {
			if (addr == null)
				continue;
			selection.add(addr);
		}
		this.setSelection(selection);
	}

	public SarifService getSarifService() {
		if (sarifService == null) {
			sarifService = tool.getService(SarifService.class);
		}
		return sarifService;
	}

	@Override
	public void setAddressSet(AddressSet set, boolean clear) {
		if (clear) {
			taintProvider.clearTaint();
		}
		state.setTaintAddressSet(set);
		taintProvider.setTaint();
	}

	@Override
	public void setVarnodeMap(Map<Address, Set<TaintQueryResult>> vmap, boolean clear, TaskType delta) {
		if (clear) {
			taintProvider.clearTaint();
		}
		state.setTaintVarnodeMap(vmap, delta);
		taintProvider.setTaint(delta);
	}

	@Override
	public AddressSet getAddressSet() {
		return state.getTaintAddressSet();
	}

	@Override
	public Map<Address, Set<TaintQueryResult>> getVarnodeMap() {
		return state.getTaintVarnodeMap();
	}

}
