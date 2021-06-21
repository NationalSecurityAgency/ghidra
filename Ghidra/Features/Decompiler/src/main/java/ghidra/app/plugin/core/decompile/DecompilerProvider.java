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
package ghidra.app.plugin.core.decompile;

import java.awt.Color;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;

import javax.swing.*;

import docking.*;
import docking.action.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.ViewerPosition;
import ghidra.GhidraOptions;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.*;
import ghidra.app.nav.*;
import ghidra.app.plugin.core.decompile.actions.*;
import ghidra.app.services.*;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.HighlightProvider;
import ghidra.framework.model.*;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.NavigatableComponentProviderAdapter;
import ghidra.framework.plugintool.util.ServiceListener;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;
import ghidra.util.bean.field.AnnotatedTextFieldElement;
import ghidra.util.task.SwingUpdateManager;
import resources.Icons;
import resources.ResourceManager;
import utility.function.Callback;

public class DecompilerProvider extends NavigatableComponentProviderAdapter
		implements DomainObjectListener, OptionsChangeListener, DecompilerCallbackHandler,
		DecompilerHighlightService {
	final static String OPTIONS_TITLE = "Decompiler";

	private static Icon REFRESH_ICON = Icons.REFRESH_ICON;
	static final ImageIcon C_SOURCE_ICON =
		ResourceManager.loadImage("images/decompileFunction.gif");

	private DockingAction defUseHighlightAction;
	private DockingAction forwardSliceAction;
	private DockingAction forwardSliceToOpsAction;
	private DockingAction backwardSliceAction;
	private DockingAction backwardSliceToOpsAction;
	private DockingAction lockProtoAction;
	private DockingAction lockLocalAction;
	private DockingAction renameLocalAction;
	private DockingAction renameGlobalAction;
	private DockingAction renameFieldAction;
	private DockingAction retypeLocalAction;
	private DockingAction retypeGlobalAction;
	private DockingAction retypeReturnAction;
	private DockingAction retypeFieldAction;
	private DockingAction isolateVarAction;
	private DockingAction specifyCProtoAction;
	private DockingAction overrideSigAction;
	private DockingAction deleteSigAction;
	private DockingAction debugFunctionAction;
	private DockingAction convertAction;
	private DockingAction graphASTControlFlowAction;
	private DockingAction findAction;
	private DockingAction propertiesAction;
	private DockingAction editDataTypeAction;
	private DockingAction decompilerCreateStructureAction;
	private DockingAction listingCreateStructureAction;
	private DockingAction renameFunctionAction;
	private DockingAction findReferencesAction;

	private CloneDecompilerAction cloneDecompilerAction;

	private SelectAllAction selectAllAction;

	private SetSecondaryHighlightAction setSecondaryHighlightAction;
	private SetSecondaryHighlightColorChooserAction setSecondaryHighlightColorChooserAction;
	private RemoveAllSecondaryHighlightsAction removeAllSecondadryHighlightsAction;
	private RemoveSecondaryHighlightAction removeSecondaryHighlightAction;

	private final DecompilePlugin plugin;
	private ClipboardService clipboardService;
	private DecompilerClipboardProvider clipboardProvider;
	private DecompileOptions decompilerOptions;

	private Program program;
	private ProgramLocation currentLocation;
	private ProgramSelection currentSelection;

	private DecompilerController controller;
	private DecoratorPanel decorationPanel;
	private ClangHighlightController highlightController;

	private ViewerPosition pendingViewerPosition;

	private SwingUpdateManager redecompileUpdater;

	// Follow-up work can be items that need to happen after a pending decompile is finished, such
	// as updating highlights after a variable rename
	private SwingUpdateManager followUpWorkUpdater;
	private Queue<Callback> followUpWork = new ConcurrentLinkedQueue<>();

	private ServiceListener serviceListener = new ServiceListener() {

		@Override
		public void serviceRemoved(Class<?> interfaceClass, Object service) {
			if (interfaceClass.equals(GraphDisplayBroker.class)) {
				graphServiceRemoved();
			}
		}

		@Override
		public void serviceAdded(Class<?> interfaceClass, Object service) {
			if (interfaceClass.equals(GraphDisplayBroker.class)) {
				graphServiceAdded();
			}
		}
	};

	public DecompilerProvider(DecompilePlugin plugin, boolean isConnected) {
		super(plugin.getTool(), "Decompiler", plugin.getName(), DecompilerActionContext.class);

		this.plugin = plugin;
		this.clipboardProvider = new DecompilerClipboardProvider(plugin, this);

		setConnected(isConnected);

		decompilerOptions = new DecompileOptions();
		initializeDecompilerOptions();
		controller = new DecompilerController(this, decompilerOptions, clipboardProvider);
		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();

		// TODO move the hl controller into the panel
		highlightController = new LocationClangHighlightController();
		decompilerPanel.setHighlightController(highlightController);
		decorationPanel = new DecoratorPanel(decompilerPanel, isConnected);

		if (!isConnected) {
			setTransient();
		}
		else {
			addToToolbar();
			setKeyBinding(
				new KeyBindingData(KeyEvent.VK_E, DockingUtils.CONTROL_KEY_MODIFIER_MASK));
		}

		setIcon(C_SOURCE_ICON);
		setTitle("Decompile");

		setWindowMenuGroup("Decompile");
		setDefaultWindowPosition(WindowPosition.RIGHT);
		createActions(isConnected);
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "DecompilerIntro"));
		addToTool();

		redecompileUpdater = new SwingUpdateManager(500, 5000, () -> doRefresh());
		followUpWorkUpdater = new SwingUpdateManager(() -> doFollowUpWork());

		plugin.getTool().addServiceListener(serviceListener);
	}

//==================================================================================================
// Component Provider methods
//==================================================================================================

	@Override
	public boolean isSnapshot() {
		// we are a snapshot when we are 'disconnected' 
		return !isConnected();
	}

	@Override
	public void closeComponent() {
		controller.clear();
		plugin.closeProvider(this);
	}

	@Override
	public String getWindowGroup() {
		if (isConnected()) {
			return "";
		}
		return "disconnected";
	}

	@Override
	public void componentShown() {
		if (program != null && currentLocation != null) {
			ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
			decompilerOptions.grabFromToolAndProgram(plugin, opt, program);
			controller.setOptions(decompilerOptions);
			controller.display(program, currentLocation, null);
		}
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (program == null) {
			return null;
		}
		Function function = controller.getFunction();
		if (function == null) {
			return null;
		}
		if (!controller.hasDecompileResults()) {
			return null;
		}

		Address entryPoint = function.getEntryPoint();
		boolean isDecompiling = controller.isDecompiling();
		return new DecompilerActionContext(this, entryPoint, isDecompiling);
	}

	@Override
	public JComponent getComponent() {
		return decorationPanel;
	}

//==================================================================================================
// Navigatable interface methods
//==================================================================================================

	@Override
	public Program getProgram() {
		return program;
	}

	@Override
	public ProgramLocation getLocation() {
		if (currentLocation instanceof DecompilerLocation) {
			return currentLocation;
		}
		return controller.getDecompilerPanel().getCurrentLocation();
	}

	@Override
	public boolean goTo(Program gotoProgram, ProgramLocation location) {

		if (!isConnected()) {
			if (program == null) {
				// Special Case: this 'disconnected' provider is waiting to be initialized 
				// with the first goTo() callback
				doSetProgram(gotoProgram);
			}
			else if (gotoProgram != program) {
				// this disconnected provider only works with its given program
				tool.setStatusInfo("Program location not applicable for this provider!");
				return false;
			}
		}

		ProgramManager programManagerService = tool.getService(ProgramManager.class);
		if (programManagerService != null) {
			programManagerService.setCurrentProgram(gotoProgram);
		}

		setLocation(location, null);
		pendingViewerPosition = null;
		plugin.locationChanged(this, location);
		return true;
	}

	@Override
	public LocationMemento getMemento() {
		ViewerPosition vp = controller.getDecompilerPanel().getViewerPosition();
		return new DecompilerLocationMemento(program, currentLocation, vp);
	}

	@Override
	public void setMemento(LocationMemento memento) {
		DecompilerLocationMemento decompMemento = (DecompilerLocationMemento) memento;
		pendingViewerPosition = decompMemento.getViewerPosition();
	}

	@Override
	public void requestFocus() {
		controller.getDecompilerPanel().requestFocus();
		tool.toFront(this);
	}

//==================================================================================================
// DomainObjectListener methods
//==================================================================================================

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		// Check for events that signal that a decompiler process' data is stale
		// and if so force a new process to be spawned
		if (ev.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_ADDED) ||
			ev.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_REMOVED) ||
			ev.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
			controller.resetDecompiler();
		}
		else if (ev.containsEvent(DomainObject.DO_PROPERTY_CHANGED)) {
			Iterator<DomainObjectChangeRecord> iter = ev.iterator();
			while (iter.hasNext()) {
				DomainObjectChangeRecord record = iter.next();
				if (record.getEventType() == DomainObject.DO_PROPERTY_CHANGED) {
					if (record.getOldValue() instanceof String) {
						String value = (String) record.getOldValue();
						if (value.startsWith(SpecExtension.SPEC_EXTENSION)) {
							controller.resetDecompiler();
							break;
						}
					}
				}
			}
		}

		// Trigger a redecompile an any program change if the window is active
		if (isVisible()) {
			redecompileUpdater.update();
		}
	}

	private void doRefresh() {
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		decompilerOptions.grabFromToolAndProgram(plugin, opt, program);
		controller.setOptions(decompilerOptions);
		if (currentLocation != null) {
			controller.refreshDisplay(program, currentLocation, null);
		}
	}

	private void doFollowUpWork() {
		if (isBusy()) {
			// try again later
			followUpWorkUpdater.updateLater();
			return;
		}

		Callback work = followUpWork.poll();
		while (work != null) {
			work.call();
			work = followUpWork.poll();
		}
	}

//==================================================================================================
// OptionsListener methods
//==================================================================================================

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		if (!isVisible()) {
			return;
		}

		if (options.getName().equals(OPTIONS_TITLE) ||
			options.getName().equals(GhidraOptions.CATEGORY_BROWSER_FIELDS)) {
			doRefresh();
		}
	}

//==================================================================================================
// methods called from the plugin
//==================================================================================================

	void setClipboardService(ClipboardService service) {
		clipboardService = service;
		if (clipboardService != null) {
			clipboardService.registerClipboardContentProvider(clipboardProvider);
		}
	}

	@Override
	public void dispose() {
		super.dispose();

		redecompileUpdater.dispose();
		followUpWorkUpdater.dispose();

		if (clipboardService != null) {
			clipboardService.deRegisterClipboardContentProvider(clipboardProvider);
		}
		controller.dispose();
		program = null;
		currentLocation = null;
		currentSelection = null;
	}

	/**
	 * Sets the current program and adds/removes itself as a domainObjectListener
	 * @param newProgram the new program or null to clear out the current program.
	 */
	void doSetProgram(Program newProgram) {
		controller.clear();
		if (program != null) {
			program.removeListener(this);
		}
		program = newProgram;
		currentLocation = null;
		currentSelection = null;
		if (program != null) {
			program.addListener(this);
			ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
			decompilerOptions.grabFromToolAndProgram(plugin, opt, program);
		}
	}

	@Override
	public void setSelection(ProgramSelection selection) {
		currentSelection = selection;
		if (isVisible()) {
			contextChanged();
			controller.setSelection(selection);
		}
	}

	@Override
	public void setHighlight(ProgramSelection highlight) {
		// do nothing for now
	}

	@Override
	public boolean supportsHighlight() {
		return false;
	}

	/**
	 * sets the current location for this provider. If the provider is not visible, it does not
	 * pass it on to the controller.  When the component is later shown, the current location
	 * will then be passed to the controller.
	 * @param loc the location to compile and set the cursor.
	 * @param viewerPosition if non-null the position at which to scroll the view.
	 */
	void setLocation(ProgramLocation loc, ViewerPosition viewerPosition) {
		Address currentAddress = currentLocation != null ? currentLocation.getAddress() : null;
		currentLocation = loc;
		Address newAddress = currentLocation != null ? currentLocation.getAddress() : null;
		if (viewerPosition == null) {
			viewerPosition = pendingViewerPosition;
		}
		if (isVisible() && newAddress != null && !newAddress.equals(currentAddress)) {
			controller.display(program, loc, viewerPosition);
		}
		contextChanged();
		pendingViewerPosition = null;

	}

	/**
	 * Re-decompile the currently displayed location
	 */
	void refresh() {
		controller.refreshDisplay(program, currentLocation, null);
	}

	@Override
	public ProgramSelection getSelection() {
		return currentSelection;
	}

	@Override
	public ProgramSelection getHighlight() {
		return null;
	}

	@Override
	public String getTextSelection() {
		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		return decompilerPanel.getTextSelection();
	}

	boolean isBusy() {
		return redecompileUpdater.isBusy() || controller.isDecompiling();
	}

	/**
	 * Returns a string that shows the current line with the field under the cursor in between
	 * '[]' chars.
	 *
	 * @return the string
	 */
	String currentTokenToString() {

		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		FieldLocation cursor = decompilerPanel.getCursorPosition();
		List<ClangLine> lines = decompilerPanel.getLines();
		ClangLine line = lines.get(cursor.getRow());
		ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
		List<ClangToken> tokens = Arrays.asList(tokenAtCursor);
		String string = line.toDebugString(tokens);
		return string;
	}

	/**
	 * Set the cursor location of the decompiler.
	 *
	 * @param lineNumber the 1-based line number
	 * @param offset the character offset into line; the offset is from the start of the line
	 */
	void setCursorLocation(int lineNumber, int offset) {

		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		int row = lineNumber - 1; // 1-based number
		BigInteger index = BigInteger.valueOf(row);
		FieldLocation location = new FieldLocation(index, 0, 0, offset);
		decompilerPanel.setCursorPosition(location);
	}

	DecompilerController getController() {
		return controller;
	}

//==================================================================================================
// methods called from the controller
//==================================================================================================

	@Override
	public void setStatusMessage(String message) {
		tool.setStatusInfo(message);
	}

	@Override
	public void decompileDataChanged(DecompileData decompileData) {
		updateTitle();
		contextChanged();
		controller.setSelection(currentSelection);
	}

	@Override
	public void locationChanged(ProgramLocation programLocation) {
		if (programLocation.equals(currentLocation)) {
			return;
		}
		currentLocation = programLocation;
		contextChanged();
		plugin.locationChanged(this, programLocation);
	}

	@Override
	public void selectionChanged(ProgramSelection programSelection) {
		currentSelection = programSelection;
		contextChanged();
		plugin.selectionChanged(this, programSelection);
	}

	@Override
	public void annotationClicked(AnnotatedTextFieldElement annotation, boolean newWindow) {

		Navigatable navigatable = this;
		if (newWindow) {
			DecompilerProvider newProvider = plugin.createNewDisconnectedProvider();
			navigatable = newProvider;
		}

		annotation.handleMouseClicked(navigatable, tool);
	}

	@Override
	public void goToLabel(String symbolName, boolean newWindow) {

		GoToService service = tool.getService(GoToService.class);
		if (service == null) {
			return;
		}

		SymbolIterator symbolIterator = program.getSymbolTable().getSymbols(symbolName);
		if (!symbolIterator.hasNext()) {
			tool.setStatusInfo(symbolName + " not found.");
			return;
		}

		Navigatable navigatable = this;
		if (newWindow) {
			DecompilerProvider newProvider = plugin.createNewDisconnectedProvider();
			navigatable = newProvider;
		}

		QueryData queryData = new QueryData(symbolName, true);
		service.goToQuery(navigatable, null, queryData, null, null);
	}

	@Override
	public void goToScalar(long value, boolean newWindow) {

		GoToService service = tool.getService(GoToService.class);
		if (service == null) {
			return;
		}

		try {
			// try space/overlay which contains function
			AddressSpace space = controller.getFunction().getEntryPoint().getAddressSpace();
			goToAddress(space.getAddress(value), newWindow);
			return;
		}
		catch (AddressOutOfBoundsException e) {
			// ignore
		}
		try {
			AddressSpace space = controller.getFunction().getEntryPoint().getAddressSpace();
			space.getAddress(value);
			goToAddress(program.getAddressFactory().getDefaultAddressSpace().getAddress(value),
				newWindow);
		}
		catch (AddressOutOfBoundsException e) {
			tool.setStatusInfo("Invalid address: " + value);
		}
	}

	@Override
	public void goToAddress(Address address, boolean newWindow) {

		GoToService service = tool.getService(GoToService.class);
		if (service == null) {
			return;
		}

		Navigatable navigatable = this;
		if (newWindow) {
			DecompilerProvider newProvider = plugin.createNewDisconnectedProvider();
			navigatable = newProvider;
		}

		service.goTo(navigatable, new ProgramLocation(program, address), program);
	}

	@Override
	public void goToFunction(Function function, boolean newWindow) {

		GoToService service = tool.getService(GoToService.class);
		if (service == null) {
			return;
		}

		Navigatable navigatable = this;
		if (newWindow) {
			DecompilerProvider newProvider = plugin.createNewDisconnectedProvider();
			navigatable = newProvider;
		}

		if (function.isExternal()) {
			Symbol symbol = function.getSymbol();
			ExternalManager externalManager = program.getExternalManager();
			ExternalLocation externalLocation = externalManager.getExternalLocation(symbol);
			service.goToExternalLocation(navigatable, externalLocation, true);
		}
		else {
			Address address = function.getEntryPoint();
			service.goTo(navigatable, new ProgramLocation(program, address), program);
		}
	}

	@Override
	public void doWheNotBusy(Callback c) {
		followUpWork.offer(c);
		followUpWorkUpdater.update();
	}

//==================================================================================================
// methods called from other members
//==================================================================================================

	DecompilerPanel getDecompilerPanel() {
		return controller.getDecompilerPanel();
	}

	public void cloneWindow() {
		DecompilerProvider newProvider = plugin.createNewDisconnectedProvider();

		// invoke later to give the window manage a chance to create the new window
		// (its done in an invoke later)
		Swing.runLater(() -> {

			ViewerPosition myViewPosition = controller.getDecompilerPanel().getViewerPosition();
			newProvider.doSetProgram(program);

			// Any change in the HighlightTokens should be delivered to the new panel
			DecompilerPanel myPanel = getDecompilerPanel();
			TokenHighlights myHighlights = myPanel.getSecondaryHighlightedTokens();
			newProvider.setLocation(currentLocation, myPanel.getViewerPosition());

			// transfer any state after the new decompiler is initialized 
			DecompilerPanel newPanel = newProvider.getDecompilerPanel();
			Map<String, Color> highlightsByName = myHighlights.copyHighlightsByName();
			newProvider.doWheNotBusy(() -> {

				newPanel.setViewerPosition(myViewPosition);
				newPanel.applySecondaryHighlights(highlightsByName);
			});
		});
	}

	@Override
	public void contextChanged() {
		tool.contextChanged(this);
	}

//==================================================================================================
// private methods
//==================================================================================================
	/**
	 * Updates the windows title and subtitle to reflect the currently decompiled function
	 */
	private void updateTitle() {
		Function function = controller.getDecompileData().getFunction();
		String programName = (program != null) ? program.getDomainFile().getName() : "";
		String title = "Decompiler";
		String subTitle = "";
		if (function != null) {
			title = "Decompile: " + function.getName();
			subTitle = " (" + programName + ")";
		}
		if (!isConnected()) {
			title = "[" + title + "]";
		}
		setTitle(title);
		setSubTitle(subTitle);
	}

	private void initializeDecompilerOptions() {
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		HelpLocation helpLocation = new HelpLocation(HelpTopics.DECOMPILER, "GeneralOptions");
		opt.setOptionsHelpLocation(helpLocation);
		opt.getOptions("Analysis")
				.setOptionsHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "AnalysisOptions"));
		opt.getOptions("Display")
				.setOptionsHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "DisplayOptions"));
		decompilerOptions.registerOptions(plugin, opt, program);

		opt.addOptionsChangeListener(this);

		ToolOptions codeBrowserOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		codeBrowserOptions.addOptionsChangeListener(this);
	}

	private void createActions(boolean isConnected) {
		String owner = plugin.getName();

		selectAllAction = new SelectAllAction(owner, controller.getDecompilerPanel());

		DockingAction refreshAction = new DockingAction("Refresh", owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				refresh();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				DecompileData decompileData = controller.getDecompileData();
				if (decompileData == null) {
					return false;
				}
				return decompileData.hasDecompileResults();
			}
		};
		refreshAction.setToolBarData(new ToolBarData(REFRESH_ICON, "A" /* first on toolbar */));
		refreshAction.setDescription("Push at any time to trigger a re-decompile");
		refreshAction
				.setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ToolBarRedecompile")); // just use the default

		//
		// Below are actions along with their groups and subgroup information.  The comments
		// for each section indicates the logical group for the actions that follow.
		// The actual group String used is for ordering the groups.  The int position is
		// used to specify a position *within* each group for each action.
		//
		// Group naming note:  We can control the ordering of our groups.  We cannot, however,
		// control the grouping of the dynamically inserted actions, such as the 'comment' actions.
		// In order to organize our groups around the comment actions, we have
		// to make our group names based upon the comment group name.
		// Below you will see group names that will trigger group sorting by number for those
		// groups before the comments group and then group sorting using the known comment group
		// name for those groups after the comments.
		//

		//
		// Function
		//
		String functionGroup = "1 - Function Group";
		int subGroupPosition = 0;

		specifyCProtoAction = new SpecifyCPrototypeAction();
		setGroupInfo(specifyCProtoAction, functionGroup, subGroupPosition++);

		overrideSigAction = new OverridePrototypeAction();
		setGroupInfo(overrideSigAction, functionGroup, subGroupPosition++);

		deleteSigAction = new DeletePrototypeOverrideAction();
		setGroupInfo(deleteSigAction, functionGroup, subGroupPosition++);

		renameFunctionAction = new RenameFunctionAction();
		setGroupInfo(renameFunctionAction, functionGroup, subGroupPosition++);

		//
		// Variables
		//
		String variableGroup = "2 - Variable Group";
		subGroupPosition = 0; // reset for the next group

		renameLocalAction = new RenameLocalAction();
		setGroupInfo(renameLocalAction, variableGroup, subGroupPosition++);

		renameGlobalAction = new RenameGlobalAction();
		setGroupInfo(renameGlobalAction, variableGroup, subGroupPosition++);

		renameFieldAction = new RenameFieldAction();
		setGroupInfo(renameFieldAction, variableGroup, subGroupPosition++);

		retypeLocalAction = new RetypeLocalAction();
		setGroupInfo(retypeLocalAction, variableGroup, subGroupPosition++);

		retypeGlobalAction = new RetypeGlobalAction();
		setGroupInfo(retypeGlobalAction, variableGroup, subGroupPosition++);

		retypeReturnAction = new RetypeReturnAction();
		setGroupInfo(retypeReturnAction, variableGroup, subGroupPosition++);

		retypeFieldAction = new RetypeFieldAction();
		setGroupInfo(retypeFieldAction, variableGroup, subGroupPosition++);

		isolateVarAction = new IsolateVariableAction();
		setGroupInfo(isolateVarAction, variableGroup, subGroupPosition++);

		decompilerCreateStructureAction =
			new DecompilerStructureVariableAction(owner, tool, controller);
		setGroupInfo(decompilerCreateStructureAction, variableGroup, subGroupPosition++);

		editDataTypeAction = new EditDataTypeAction();
		setGroupInfo(editDataTypeAction, variableGroup, subGroupPosition++);

		//
		// Listing action for Creating Structure on a Variable
		//
		listingCreateStructureAction = new ListingStructureVariableAction(owner, tool, controller);

		//
		// Commit
		//
		String commitGroup = "3 - Commit Group";
		subGroupPosition = 0; // reset for the next group

		lockProtoAction = new CommitParamsAction();
		setGroupInfo(lockProtoAction, commitGroup, subGroupPosition++);

		lockLocalAction = new CommitLocalsAction();
		setGroupInfo(lockLocalAction, commitGroup, subGroupPosition++);

		subGroupPosition = 0; // reset for the next group

		//
		// Highlight
		//
		String highlightGroup = "4a - Highlight Group";
		tool.setMenuGroup(new String[] { "Highlight" }, highlightGroup);
		defUseHighlightAction = new HighlightDefinedUseAction();
		setGroupInfo(defUseHighlightAction, highlightGroup, subGroupPosition++);

		forwardSliceAction = new ForwardSliceAction();
		setGroupInfo(forwardSliceAction, highlightGroup, subGroupPosition++);

		backwardSliceAction = new BackwardsSliceAction();
		setGroupInfo(backwardSliceAction, highlightGroup, subGroupPosition++);

		forwardSliceToOpsAction = new ForwardSliceToPCodeOpsAction();
		setGroupInfo(forwardSliceToOpsAction, highlightGroup, subGroupPosition++);

		backwardSliceToOpsAction = new BackwardsSliceToPCodeOpsAction();
		setGroupInfo(backwardSliceToOpsAction, highlightGroup, subGroupPosition++);

		tool.setMenuGroup(new String[] { "Secondary Highlight" }, highlightGroup);
		setSecondaryHighlightAction = new SetSecondaryHighlightAction();
		setGroupInfo(setSecondaryHighlightAction, highlightGroup, subGroupPosition++);

		setSecondaryHighlightColorChooserAction = new SetSecondaryHighlightColorChooserAction();
		setGroupInfo(setSecondaryHighlightColorChooserAction, highlightGroup, subGroupPosition++);

		removeSecondaryHighlightAction = new RemoveSecondaryHighlightAction();
		setGroupInfo(removeSecondaryHighlightAction, highlightGroup, subGroupPosition++);

		removeAllSecondadryHighlightsAction = new RemoveAllSecondaryHighlightsAction();
		setGroupInfo(removeAllSecondadryHighlightsAction, highlightGroup, subGroupPosition++);

		//
		// Comments
		//
		// NOTE: this is just a placeholder to represent where the comment actions should appear
		//       in relation to our local actions.  
		//

		//
		// Search
		//
		String searchGroup = "comment2 - Search Group";
		subGroupPosition = 0; // reset for the next group

		findAction = new FindAction();
		setGroupInfo(findAction, searchGroup, subGroupPosition++);

		//
		// References 
		// 

		// note: set the menu group so that the 'References' group is with the 'Find' action
		String referencesParentGroup = searchGroup;

		findReferencesAction = new FindReferencesToDataTypeAction(owner, tool, controller);
		setGroupInfo(findReferencesAction, searchGroup, subGroupPosition++);
		findReferencesAction.getPopupMenuData().setParentMenuGroup(referencesParentGroup);

		FindReferencesToSymbolAction findReferencesToSymbolAction =
			new FindReferencesToSymbolAction();
		setGroupInfo(findReferencesToSymbolAction, searchGroup, subGroupPosition++);
		findReferencesToSymbolAction.getPopupMenuData().setParentMenuGroup(referencesParentGroup);
		addLocalAction(findReferencesToSymbolAction);

		FindReferencesToAddressAction findReferencesToAdressAction =
			new FindReferencesToAddressAction(tool, owner);
		setGroupInfo(findReferencesToAdressAction, searchGroup, subGroupPosition++);
		findReferencesToAdressAction.getPopupMenuData().setParentMenuGroup(referencesParentGroup);
		addLocalAction(findReferencesToAdressAction);

		//
		// Options
		//
		String optionsGroup = "comment6 - Options Group";
		subGroupPosition = 0; // reset for the next group

		propertiesAction = new EditPropertiesAction(owner, tool);
		setGroupInfo(propertiesAction, optionsGroup, subGroupPosition++);

		//
		// These actions are not in the popup menu
		//
		debugFunctionAction = new DebugDecompilerAction(controller);
		convertAction = new ExportToCAction();
		cloneDecompilerAction = new CloneDecompilerAction();

		addLocalAction(refreshAction);
		addLocalAction(selectAllAction);
		addLocalAction(defUseHighlightAction);
		addLocalAction(forwardSliceAction);
		addLocalAction(backwardSliceAction);
		addLocalAction(forwardSliceToOpsAction);
		addLocalAction(backwardSliceToOpsAction);
		addLocalAction(lockProtoAction);
		addLocalAction(lockLocalAction);
		addLocalAction(renameLocalAction);
		addLocalAction(renameGlobalAction);
		addLocalAction(renameFieldAction);
		addLocalAction(setSecondaryHighlightAction);
		addLocalAction(setSecondaryHighlightColorChooserAction);
		addLocalAction(removeSecondaryHighlightAction);
		addLocalAction(removeAllSecondadryHighlightsAction);
		addLocalAction(retypeLocalAction);
		addLocalAction(retypeGlobalAction);
		addLocalAction(retypeReturnAction);
		addLocalAction(retypeFieldAction);
		addLocalAction(isolateVarAction);
		addLocalAction(decompilerCreateStructureAction);
		tool.addAction(listingCreateStructureAction);
		addLocalAction(editDataTypeAction);
		addLocalAction(specifyCProtoAction);
		addLocalAction(overrideSigAction);
		addLocalAction(deleteSigAction);
		addLocalAction(renameFunctionAction);
		addLocalAction(debugFunctionAction);
		addLocalAction(convertAction);
		addLocalAction(findAction);
		addLocalAction(findReferencesAction);
		addLocalAction(propertiesAction);
		addLocalAction(cloneDecompilerAction);

		graphServiceAdded();
	}

	/**
	 * Sets the group and subgroup information for the given action.
	 */
	private void setGroupInfo(DockingAction action, String group, int subGroupPosition) {
		MenuData popupMenuData = action.getPopupMenuData();
		popupMenuData.setMenuGroup(group);
		popupMenuData.setMenuSubGroup(Integer.toString(subGroupPosition));
	}

	private void graphServiceRemoved() {
		if (graphASTControlFlowAction == null) {
			return;
		}
		if (tool.getService(GraphDisplayBroker.class) == null) {
			tool.removeAction(graphASTControlFlowAction);
			graphASTControlFlowAction.dispose();
			graphASTControlFlowAction = null;
		}
	}

	private void graphServiceAdded() {
		GraphDisplayBroker service = tool.getService(GraphDisplayBroker.class);
		if (service != null && service.getDefaultGraphDisplayProvider() != null) {
			graphASTControlFlowAction = new GraphASTControlFlowAction();
			addLocalAction(graphASTControlFlowAction);
		}
	}

	@Override
	public void exportLocation() {
		if (program != null && currentLocation != null) {
			plugin.exportLocation(program, currentLocation);
		}
	}

	@Override
	public void writeDataState(SaveState saveState) {
		super.writeDataState(saveState);
		if (currentLocation != null) {
			currentLocation.saveState(saveState);
		}
		ViewerPosition vp = controller.getDecompilerPanel().getViewerPosition();
		saveState.putInt("INDEX", vp.getIndexAsInt());
		saveState.putInt("Y_OFFSET", vp.getYOffset());

	}

	@Override
	public void readDataState(SaveState saveState) {
		super.readDataState(saveState);
		int index = saveState.getInt("INDEX", 0);
		int yOffset = saveState.getInt("Y_OFFSET", 0);
		ViewerPosition vp = new ViewerPosition(index, 0, yOffset);
		if (program != null && isVisible()) {
			currentLocation = ProgramLocation.getLocation(program, saveState);
			if (currentLocation != null) {
				controller.display(program, currentLocation, vp);
			}
		}
	}

	@Override
	public void removeHighlightProvider(HighlightProvider highlightProvider, Program p) {
		// currently unsupported
	}

	@Override
	public void setHighlightProvider(HighlightProvider highlightProvider, Program p) {
		// currently unsupported
	}

	public void programClosed(Program closedProgram) {
		controller.programClosed(closedProgram);
	}

	@Deprecated // to be removed post 9.2; replace with an API to manipulate primary highlights
	@Override
	public ClangLayoutController getLayoutModel() {
		return (ClangLayoutController) getDecompilerPanel().getLayoutModel();
	}

	@Deprecated // to be removed post 9.2; replace with an API to manipulate primary highlights
	@Override
	public void clearHighlights() {
		getDecompilerPanel().clearPrimaryHighlights();
	}

}
