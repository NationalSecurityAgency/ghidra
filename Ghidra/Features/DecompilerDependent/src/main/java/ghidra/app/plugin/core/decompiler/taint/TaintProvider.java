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
import javax.swing.JComponent;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.*;
import generic.theme.GIcon;
import ghidra.GhidraOptions;
import ghidra.app.decompiler.*;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.plugin.core.decompiler.taint.TaintPlugin.Highlighter;
import ghidra.app.plugin.core.decompiler.taint.actions.*;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.Swing;

public class TaintProvider extends ComponentProviderAdapter implements OptionsChangeListener {

	private static final Logger log = LogManager.getLogger(TaintProvider.class);

	private static final String OPTIONS_TITLE = "Decompiler";

	private TaintPlugin plugin;
	private TaintOptions taintOptions;
	private Program program;

	private DecompilerProvider decompilerProvider;
	private Navigatable navigatable;

	private TaintState state;

	private DecompilerHighlighter highlighter;

	private Boolean allAccess;

	private TaintCTokenHighlighterPalette highlightPalette;
	private int paletteIndex;

	private int matchCount = 0;

	// Use the string and not high token to match on the string shown in the decomp.
	private Map<String, Color> cachedHighlightsByToken;

	// Use the string and not high variable to match on the string shown in the
	// decomp.
	private Map<Address, TaintHighlight> cachedHighlightByAddress;

	private static String showTaintLabelEditTableIcoString = "icon.dialog.error.expandable.stack";
	private static Icon showTaintLabelEditTableIcon = new GIcon(showTaintLabelEditTableIcoString);

	public TaintProvider(TaintPlugin plugin) {
		super(plugin.getTool(), "TaintProvider", plugin.getName(), DecompilerActionContext.class);
		this.plugin = plugin;
		this.taintOptions = new TaintOptions(this);
		this.state = plugin.getTaintState();
		this.cachedHighlightsByToken = new HashMap<>();
		this.cachedHighlightByAddress = new HashMap<>();
		this.highlightPalette = new TaintCTokenHighlighterPalette(256);
		this.paletteIndex = 0;
		initializeDecompilerOptions();
	}

	public TaintOptions getOptions() {
		return taintOptions;
	}

	@Override
	public JComponent getComponent() {
		decompilerProvider = plugin.getDecompilerProvider();
		return decompilerProvider.getComponent();
	}

	private void createActions(ComponentProvider provider, boolean isConnected) {
		String variableGroup = "2 - Variable Group";
		int subGroupPosition = 0; // reset for the next group

		// These actions are only available in the drop-down window

		TaintSourceAction taintSourceAction = new TaintSourceAction(plugin, state);
		setGroupInfo(taintSourceAction, variableGroup, subGroupPosition++);

		TaintSourceBySymbolAction taintSourceBySymbolAction =
			new TaintSourceBySymbolAction(plugin, state);
		setGroupInfo(taintSourceBySymbolAction, variableGroup, subGroupPosition++);

		TaintSinkAction taintSinkAction = new TaintSinkAction(plugin, state);
		setGroupInfo(taintSinkAction, variableGroup, subGroupPosition++);

		TaintSinkBySymbolAction taintSinkBySymbolAction =
			new TaintSinkBySymbolAction(plugin, state);
		setGroupInfo(taintSinkBySymbolAction, variableGroup, subGroupPosition++);

		TaintGateAction taintGateAction = new TaintGateAction(plugin, state);
		setGroupInfo(taintGateAction, variableGroup, subGroupPosition++);

		TaintClearAction taintClearAction = new TaintClearAction(plugin, state);
		setGroupInfo(taintClearAction, variableGroup, subGroupPosition++);

		// These actions have an icon and a drop-down menu option in the decompiler window.
		TaintQueryAction taintQueryAction = new TaintQueryAction(plugin, state);
		TaintQueryDefaultAction taintQueryDefaultAction =
			new TaintQueryDefaultAction(plugin, state);
		TaintQueryCustomAction taintQueryCustomAction = new TaintQueryCustomAction(plugin, state);
		TaintLoadAction taintLoadAction = new TaintLoadAction(plugin, state);

		TaintSliceTreeAction taintSliceTreeAction = new TaintSliceTreeAction(plugin, state);

		DockingAction taintLabelTableAction = new DockingAction("TaintShowLabels", TaintPlugin.HELP_LOCATION) {

			@Override
			public void actionPerformed(ActionContext context) {

				TaintLabelsDataFrame df = new TaintLabelsDataFrame(plugin);
				df.loadData();

				TaintLabelsTableProvider table_provider =
					new TaintLabelsTableProvider(getName(), plugin, df);
				table_provider.addToTool();
				table_provider.setVisible(true);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return state.hasMarks();
			}

		};

		taintLabelTableAction
				.setMenuBarData(
					new MenuData(new String[] { "Source-Sink", taintLabelTableAction.getName() }));
		taintLabelTableAction.setToolBarData(new ToolBarData(showTaintLabelEditTableIcon));

		provider.addLocalAction(taintSliceTreeAction);
		provider.addLocalAction(taintLabelTableAction);
		provider.addLocalAction(taintSourceAction);
		provider.addLocalAction(taintSourceBySymbolAction);
		provider.addLocalAction(taintSinkAction);
		provider.addLocalAction(taintSinkBySymbolAction);
		provider.addLocalAction(taintGateAction);
		provider.addLocalAction(taintQueryAction);
		provider.addLocalAction(taintQueryDefaultAction);
		provider.addLocalAction(taintQueryCustomAction);
		provider.addLocalAction(taintLoadAction);
		provider.addLocalAction(taintClearAction);
	}

	/**
	 * Sets the group and subgroup information for the given action.
	 */
	private void setGroupInfo(DockingAction action, String group, int subGroupPosition) {
		MenuData popupMenuData = action.getPopupMenuData();
		popupMenuData.setMenuGroup(group);
		popupMenuData.setMenuSubGroup(Integer.toString(subGroupPosition));
	}

	@Override
	public void componentShown() {
		if (program != null) {
			ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
			taintOptions.grabFromToolAndProgram(plugin, opt, program);
		}
	}

	/*
	 * Sets the current program and adds/removes itself as a domainObjectListener
	 *
	 * @param newProgram the new program or null to clear out the current program.
	 */
	public void doSetProgram(Program newProgram) {
		program = newProgram;
		if (program != null) {
			ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
			taintOptions.grabFromToolAndProgram(plugin, opt, program);
		}
	}

	private void initializeDecompilerOptions() {
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		taintOptions.registerOptions(plugin, opt, program);

		opt.addOptionsChangeListener(this);

		ToolOptions codeBrowserOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		codeBrowserOptions.addOptionsChangeListener(this);
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		if (options.getName().equals(OPTIONS_TITLE) ||
			options.getName().equals(GhidraOptions.CATEGORY_BROWSER_FIELDS)) {
			doRefresh();
		}
	}

	private void doRefresh() {
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		taintOptions.grabFromToolAndProgram(plugin, opt, program);
	}

	public void programClosed(Program closedProgram) {
		program = null;
	}

	@Override
	public void contextChanged() {
		if (decompilerProvider == null) {
			decompilerProvider = plugin.getDecompilerProvider();
			createActions(decompilerProvider, true);
		}
		tool.contextChanged(decompilerProvider);
	}

	/**
	 * This is called every time we CHANGE FUNCTIONS and have a new decompilation.
	 * <p>
	 * TODO: We could limit our taint addresses to those in this function...? TODO:
	 * We should reset the palette cache to start coloring from the start.
	 */
	public void setTaint() {
		if (navigatable == null) {
			navigatable = tool.getService(CodeViewerService.class).getNavigatable();
		}

		AddressSet taintAddressSet = state.getTaintAddressSet();
		Msg.info(this, "setTaint(): " + taintAddressSet.toString());

		// sets the selection in the LISTING?
		// TODO: should we not set select and only highlight in the decompilation.
		Swing.runIfSwingOrRunLater(() -> {
			navigatable.setSelection(new ProgramSelection(taintAddressSet));
		});

		// Ditch the previous token string to highlight map, so we can restart.
		highlighter.clearHighlights();

		if (!taintOptions.getTaintHighlightStyle().equals(Highlighter.LABELS)) {
			this.paletteIndex = 0;
		}

		// apply highlights to the decompiler window.
		highlighter.applyHighlights();
	}

	public boolean matchOn(ClangToken token) {

		Map<Address, Set<TaintQueryResult>> taintVarnodeMap = state.getTaintVarnodeMap();

		if (taintVarnodeMap == null || taintVarnodeMap.isEmpty() ||
			token instanceof ClangBreak ||
			token instanceof ClangTypeToken ||
			token instanceof ClangSyntaxToken ||
			token instanceof ClangCommentToken) {
			return false;
		}

		HighFunction hf = token.getClangFunction().getHighFunction();

		if (hf == null) {
			log.info("\tHighlighter> HighFunction null -- not associated with a function.");
			return false;
		}

		Address tokenFuncEntryAddr = hf.getFunction().getEntryPoint();

		// Just the tainted elements that are in this function.
		Set<TaintQueryResult> funcTaintSet = taintVarnodeMap.get(tokenFuncEntryAddr);
		if (funcTaintSet == null || funcTaintSet.isEmpty()) {
			return false;
		}

		if (token instanceof ClangVariableToken vtoken) {

			if (matchNodeHighVariable(vtoken, hf, funcTaintSet)) {
				matchCount++;
				return true;
			}

		}
		else if (token instanceof ClangFieldToken ftoken) {

			if (matchNodeHighVariable(ftoken, hf, funcTaintSet)) {
				matchCount++;
				return true;
			}

		}
		else if (token instanceof ClangFuncNameToken fntoken) {

			if (matchNodeFuncName(fntoken.getText(), tokenFuncEntryAddr, funcTaintSet)) {
				matchCount++;
				return true;
			}
		}

		return false;
	}

	private boolean matchNodeHighVariable(ClangToken token, HighFunction hf,
			Set<TaintQueryResult> taintSet) {
		for (TaintQueryResult taintedVarnode : taintSet) {
			addHighlightColor(taintedVarnode);
			String match = taintedVarnode.matches(token);
			if (match != null) {
				log.info("\t\tHighlighter> LOC Match on {}", match);
				return true;
			}
		}
		return false;
	}

	private boolean matchNodeFuncName(String funcName, Address faddr,
			Set<TaintQueryResult> taintSet) {
		for (TaintQueryResult taintedVarnode : taintSet) {
			if (taintedVarnode.matchesFunction(funcName, faddr)) {
				log.info("\t\tHighlighter> FUN LOC Match on {} at addr: {}", funcName, faddr);
				return true;
			}
		}
		return false;
	}

	public void setHighlighter(DecompilerHighlightService highlightService,
			CTokenHighlightMatcher matcher) {
		if (highlighter != null) {
			highlighter.dispose();
		}
		DecompilerHighlighter dhl = highlightService.createHighlighter(matcher);
		this.highlighter = dhl;
	}

	public void clearTaint() {
		Msg.info(this,
			"TaintProvider: clearTaint() - state clearTaint() and highligher apply highlights.");
		matchCount = 0;
		state.clearTaint();
		highlighter.clearHighlights();
		cachedHighlightByAddress.clear();
		cachedHighlightsByToken.clear();
		highlighter.applyHighlights();
	}

	/**
	 * Applies highlights to the tainted labels.
	 */
	public void repaint() {
		highlighter.applyHighlights();
	}

	public void setOption(String option, String path) {
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		opt.setString(option, path);
	}

	public void setOption(String name, Boolean option) {
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		opt.setBoolean(name, option);
	}

	public void setColor(String option, Color color) {
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		opt.setColor(option, color);
	}

	public Color getDefaultHighlightColor() {
		return highlightPalette.getDefaultColor();
	}

	/**
	 * Returns the currently cached color for a ClangToken, or takes the next color
	 * from the color palette and assigns it to this token.
	 * <p>
	 * NOTE: token is assumed to not be null 
	 * NOTE 2: this highlights individual variables NOT labels on taint; that should be something we need to do.
	 * 
	 * @param token - the token we wish to highlight.
	 * @return the color currently assigned to this specific token.
	 */
	public Color getHighlightColor(ClangToken token) {
		Color hl = null;

		TaintOptions options = getOptions();
		Highlighter style = options.getTaintHighlightStyle();
		if (style.equals(Highlighter.LABELS)) {
			Address addr = token.getMinAddress();
			if (addr != null) {
				TaintHighlight tl = cachedHighlightByAddress.get(addr);
				return tl == null ? null : tl.getColor();
			}
			return null;
		}
		hl = this.cachedHighlightsByToken.get(token.toString());

		if (hl == null) {
			// Color has not been cached, so get a new color.
			hl = this.highlightPalette.getColor(this.paletteIndex);
			this.cachedHighlightsByToken.put(token.toString(), hl);
			this.paletteIndex = (this.paletteIndex + 10) % this.highlightPalette.getSize();
		}

		return hl;
	}

	public void addHighlightColor(TaintQueryResult result) {
		Address addr = result.getInsnAddr();
		String label = result.getLabel();
		TaintHighlight labelHighlight = TaintHighlight.byLabel(label);
		TaintHighlight addrHighlight = cachedHighlightByAddress.get(addr);

		if (addrHighlight == null) {
			addrHighlight = labelHighlight;
			this.cachedHighlightByAddress.put(addr, addrHighlight);
		}
		else {
			if (!labelHighlight.equals(addrHighlight)) {
				if (labelHighlight.getPriority() > addrHighlight.getPriority()) {
					this.cachedHighlightByAddress.put(addr, labelHighlight);
				}
			}
		}
	}

	public void changeHighlighter(Highlighter hl) {
		plugin.changeHighlighter(hl);
	}

	public boolean isAllAccess() {
		return allAccess;
	}

	public void setAllAccess(String taintAllAccess, Boolean allAccess) {
		this.allAccess = allAccess;
	}

	public int getTokenCount() {
		return matchCount;
	}

}
