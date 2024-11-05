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

import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;

import javax.swing.Icon;
import javax.swing.JComponent;

import docking.*;
import docking.action.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.ViewerPosition;
import generic.theme.GIcon;
import ghidra.GhidraOptions;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.*;
import ghidra.app.decompiler.component.margin.DecompilerMarginProvider;
import ghidra.app.nav.*;
import ghidra.app.plugin.core.decompile.actions.*;
import ghidra.app.services.*;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.NavigatableComponentProviderAdapter;
import ghidra.framework.plugintool.util.ServiceListener;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;
import ghidra.util.bean.field.AnnotatedTextFieldElement;
import ghidra.util.task.SwingUpdateManager;
import resources.Icons;
import resources.MultiIconBuilder;
import utility.function.Callback;

public class DecompilerProvider extends NavigatableComponentProviderAdapter
		implements OptionsChangeListener, DecompilerCallbackHandler, DecompilerHighlightService,
		DecompilerMarginService {

	private static final String OPTIONS_TITLE = "Decompiler";

	private static final Icon REFRESH_ICON = Icons.REFRESH_ICON;
	private static final Icon C_SOURCE_ICON = new GIcon("icon.decompiler.action.provider");

	private static final Icon SLASH_ICON = new GIcon("icon.decompiler.action.slash");

	private static final Icon TOGGLE_UNREACHABLE_CODE_ICON =
		new GIcon("icon.decompiler.action.provider.unreachable");

	private static final Icon TOGGLE_UNREACHABLE_CODE_DISABLED_ICON =
		new MultiIconBuilder(TOGGLE_UNREACHABLE_CODE_ICON).addCenteredIcon(SLASH_ICON).build();

	private static final Icon TOGGLE_READ_ONLY_ICON =
		new GIcon("icon.decompiler.action.provider.readonly");

	private static final Icon TOGGLE_READ_ONLY_DISABLED_ICON =
		new MultiIconBuilder(TOGGLE_READ_ONLY_ICON).addCenteredIcon(SLASH_ICON).build();

	private DockingAction pcodeGraphAction;
	private DockingAction astGraphAction;

	private ToggleDockingAction displayUnreachableCodeToggle;
	private ToggleDockingAction respectReadOnlyFlags;

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
	private DecompilerProgramListener programListener;

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
		registerAdjustableFontId(DecompileOptions.DEFAULT_FONT_ID);
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

		redecompileUpdater = new SwingUpdateManager(500, 5000, () -> doRefresh(false));
		followUpWorkUpdater = new SwingUpdateManager(() -> doFollowUpWork());

		plugin.getTool().addServiceListener(serviceListener);
		programListener = new DecompilerProgramListener(controller, redecompileUpdater);
		setDefaultFocusComponent(controller.getDecompilerPanel());
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
		super.closeComponent();
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
			ToolOptions fieldOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
			ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
			decompilerOptions.grabFromToolAndProgram(fieldOptions, opt, program);
			controller.setOptions(decompilerOptions);

			refreshToggleButtons();

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
		int lineNumber =
			event != null & !isDecompiling ? getDecompilerPanel().getLineNumber(event.getY()) : 0;
		return new DecompilerActionContext(this, entryPoint, isDecompiling, lineNumber);
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

//==================================================================================================
// DecompilerHighlightService interface methods
//==================================================================================================

	@Override
	public DecompilerHighlighter createHighlighter(CTokenHighlightMatcher tm) {
		return getDecompilerPanel().createHighlighter(tm);
	}

	@Override
	public DecompilerHighlighter createHighlighter(String id, CTokenHighlightMatcher tm) {
		return getDecompilerPanel().createHighlighter(id, tm);
	}

//==================================================================================================
// DomainObjectListener methods
//==================================================================================================

	private void doRefresh(boolean optionsChanged) {
		if (!isVisible()) {
			return;
		}
		ToolOptions fieldOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);

		// Current values of toggle buttons
		boolean decompilerEliminatesUnreachable = decompilerOptions.isEliminateUnreachable();
		boolean decompilerRespectsReadOnlyFlags = decompilerOptions.isRespectReadOnly();

		decompilerOptions.grabFromToolAndProgram(fieldOptions, opt, program);

		// If the tool options were not changed
		if (!optionsChanged) {
			// Keep these analysis options the same
			decompilerOptions.setEliminateUnreachable(decompilerEliminatesUnreachable);
			decompilerOptions.setRespectReadOnly(decompilerRespectsReadOnlyFlags);
		}
		else {
			// Otherwise, keep the new analysis options and update the state of the toggle buttons
			refreshToggleButtons();
		}

		controller.setOptions(decompilerOptions);

		if (currentLocation != null) {
			controller.refreshDisplay(program, currentLocation, null);
		}
	}

	private void refreshToggleButtons() {
		displayUnreachableCodeToggle.setSelected(!decompilerOptions.isEliminateUnreachable());
		respectReadOnlyFlags.setSelected(!decompilerOptions.isRespectReadOnly());
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
			doRefresh(true);
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
	 *
	 * @param newProgram the new program or null to clear out the current program.
	 */
	void doSetProgram(Program newProgram) {
		controller.clear();
		if (program != null) {
			program.removeListener(programListener);
		}

		program = newProgram;
		currentLocation = null;
		currentSelection = null;
		if (program != null) {
			program.addListener(programListener);
			ToolOptions fieldOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
			ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
			decompilerOptions.grabFromToolAndProgram(fieldOptions, opt, program);
		}

		clipboardProvider.setProgram(program);
	}

	@Override
	public void setSelection(ProgramSelection selection) {
		currentSelection = selection;
		if (isVisible()) {
			contextChanged();
			controller.setSelection(selection);
		}

		clipboardProvider.setSelection(selection);
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
	 * sets the current location for this provider. If the provider is not visible, it does not pass
	 * it on to the controller. When the component is later shown, the current location will then be
	 * passed to the controller.
	 *
	 * @param loc the location to compile and set the cursor.
	 * @param viewerPosition if non-null the position at which to scroll the view.
	 */
	void setLocation(ProgramLocation loc, ViewerPosition viewerPosition) {
		Address currentAddress = currentLocation != null ? currentLocation.getAddress() : null;
		currentLocation = loc;
		clipboardProvider.setLocation(currentLocation);
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

	/**
	 * Update the options from decompilerOptions
	 */
	void updateOptionsAndRefresh() {
		controller.setOptions(decompilerOptions);

		refresh();
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
		return decompilerPanel.getSelectedText();
	}

	boolean isBusy() {
		return redecompileUpdater.isBusy() || controller.isDecompiling();
	}

	/**
	 * Returns a string that shows the current line with the field under the cursor in between '[]'
	 * chars.
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

	public DecompilerController getController() {
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
	public void doWhenNotBusy(Callback c) {
		followUpWork.offer(c);
		followUpWorkUpdater.update();
	}

	@Override
	public DecompilerPanel getDecompilerPanel() {
		return controller.getDecompilerPanel();
	}

//==================================================================================================
// methods called from other members
//==================================================================================================

	// snapshot callback
	public void cloneWindow() {
		DecompilerProvider newProvider = plugin.createNewDisconnectedProvider();

		// invoke later to give the window manage a chance to create the new window
		// (its done in an invoke later)
		Swing.runLater(() -> {

			ViewerPosition myViewPosition = controller.getDecompilerPanel().getViewerPosition();
			newProvider.doSetProgram(program);

			// Any change in the HighlightTokens should be delivered to the new panel
			DecompilerPanel myPanel = getDecompilerPanel();
			newProvider.setLocation(currentLocation, myPanel.getViewerPosition());

			// transfer any state after the new decompiler is initialized
			DecompilerPanel newPanel = newProvider.getDecompilerPanel();
			newProvider.doWhenNotBusy(() -> {
				newPanel.setViewerPosition(myViewPosition);
				newPanel.cloneHighlights(myPanel);
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
		ToolOptions fieldOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		HelpLocation helpLocation = new HelpLocation(HelpTopics.DECOMPILER, "GeneralOptions");
		opt.setOptionsHelpLocation(helpLocation);
		opt.getOptions("Analysis")
				.setOptionsHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "AnalysisOptions"));
		opt.getOptions("Display")
				.setOptionsHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "DisplayOptions"));
		decompilerOptions.registerOptions(fieldOptions, opt, program);

		opt.addOptionsChangeListener(this);

		ToolOptions codeBrowserOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		codeBrowserOptions.addOptionsChangeListener(this);
	}

	private void createActions(boolean isConnected) {
		String owner = plugin.getName();

		SelectAllAction selectAllAction =
			new SelectAllAction(owner, controller.getDecompilerPanel());

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

		displayUnreachableCodeToggle = new ToggleDockingAction("Toggle Unreachable Code", owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				boolean isSelected = this.isSelected();

				// Set the option based on the button state
				decompilerOptions.setEliminateUnreachable(!isSelected);

				updateOptionsAndRefresh();
			}

			@Override
			public void setSelected(boolean isSelected) {
				super.setSelected(isSelected);

				// Update the icon to have a slash or not
				if (!isSelected) {
					displayUnreachableCodeToggle
							.setToolBarData(new ToolBarData(TOGGLE_UNREACHABLE_CODE_ICON, "A"));
				}
				else {
					displayUnreachableCodeToggle.setToolBarData(
						new ToolBarData(TOGGLE_UNREACHABLE_CODE_DISABLED_ICON, "A"));
				}
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
		displayUnreachableCodeToggle.setDescription("Toggle off to eliminate unreachable code");
		displayUnreachableCodeToggle.setHelpLocation(
			new HelpLocation(HelpTopics.DECOMPILER, "ToolBarEliminateUnreachableCode"));

		respectReadOnlyFlags = new ToggleDockingAction("Toggle Respecting Read-only Flags", owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				boolean isSelected = this.isSelected();

				// Set the option based on the button state
				decompilerOptions.setRespectReadOnly(!isSelected);

				updateOptionsAndRefresh();
			}

			@Override
			public void setSelected(boolean isSelected) {
				super.setSelected(isSelected);

				// Update the icon to have a slash or not
				if (!isSelected) {
					respectReadOnlyFlags
							.setToolBarData(new ToolBarData(TOGGLE_READ_ONLY_ICON, "A"));
				}
				else {
					respectReadOnlyFlags
							.setToolBarData(new ToolBarData(TOGGLE_READ_ONLY_DISABLED_ICON, "A"));
				}
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
		respectReadOnlyFlags.setDescription("Toggle off to respect readonly flags set on memory");
		respectReadOnlyFlags
				.setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ToolBarRespectReadOnly"));

		// Set the selected state and icon for the above two toggle icons
		refreshToggleButtons();

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

		SpecifyCPrototypeAction specifyCProtoAction = new SpecifyCPrototypeAction();
		setGroupInfo(specifyCProtoAction, functionGroup, subGroupPosition++);

		OverridePrototypeAction overrideSigAction = new OverridePrototypeAction();
		setGroupInfo(overrideSigAction, functionGroup, subGroupPosition++);

		EditPrototypeOverrideAction editOverrideSigAction = new EditPrototypeOverrideAction();
		setGroupInfo(editOverrideSigAction, functionGroup, subGroupPosition++);

		DeletePrototypeOverrideAction deleteSigAction = new DeletePrototypeOverrideAction();
		setGroupInfo(deleteSigAction, functionGroup, subGroupPosition++);

		RenameFunctionAction renameFunctionAction = new RenameFunctionAction();
		setGroupInfo(renameFunctionAction, functionGroup, subGroupPosition++);

		// not function actions, but they fit nicely in this group
		RenameLabelAction renameLabelAction = new RenameLabelAction();
		setGroupInfo(renameLabelAction, functionGroup, subGroupPosition++);

		RemoveLabelAction removeLabelAction = new RemoveLabelAction();
		setGroupInfo(removeLabelAction, functionGroup, subGroupPosition++);

		//
		// Variables
		//
		String variableGroup = "2 - Variable Group";
		subGroupPosition = 0; // reset for the next group

		RenameLocalAction renameLocalAction = new RenameLocalAction();
		setGroupInfo(renameLocalAction, variableGroup, subGroupPosition++);

		RenameGlobalAction renameGlobalAction = new RenameGlobalAction();
		setGroupInfo(renameGlobalAction, variableGroup, subGroupPosition++);

		RenameFieldAction renameFieldAction = new RenameFieldAction();
		setGroupInfo(renameFieldAction, variableGroup, subGroupPosition++);

		ForceUnionAction forceUnionAction = new ForceUnionAction();
		setGroupInfo(forceUnionAction, variableGroup, subGroupPosition++);

		RetypeLocalAction retypeLocalAction = new RetypeLocalAction();
		setGroupInfo(retypeLocalAction, variableGroup, subGroupPosition++);

		CreatePointerRelative createRelativeAction = new CreatePointerRelative();
		setGroupInfo(createRelativeAction, variableGroup, subGroupPosition++);

		RetypeGlobalAction retypeGlobalAction = new RetypeGlobalAction();
		setGroupInfo(retypeGlobalAction, variableGroup, subGroupPosition++);

		RetypeReturnAction retypeReturnAction = new RetypeReturnAction();
		setGroupInfo(retypeReturnAction, variableGroup, subGroupPosition++);

		RetypeFieldAction retypeFieldAction = new RetypeFieldAction();
		setGroupInfo(retypeFieldAction, variableGroup, subGroupPosition++);

		IsolateVariableAction isolateVarAction = new IsolateVariableAction();
		setGroupInfo(isolateVarAction, variableGroup, subGroupPosition++);

		DecompilerStructureVariableAction decompilerCreateStructureAction =
			new DecompilerStructureVariableAction(owner, tool, controller);
		setGroupInfo(decompilerCreateStructureAction, variableGroup, subGroupPosition++);

		EditDataTypeAction editDataTypeAction = new EditDataTypeAction();
		setGroupInfo(editDataTypeAction, variableGroup, subGroupPosition++);

		//
		// Listing action for Creating Structure on a Variable
		//
		ListingStructureVariableAction listingCreateStructureAction =
			new ListingStructureVariableAction(owner, tool, controller);

		//
		// Commit
		//
		String commitGroup = "3 - Commit Group";
		subGroupPosition = 0; // reset for the next group

		CommitParamsAction lockProtoAction = new CommitParamsAction();
		setGroupInfo(lockProtoAction, commitGroup, subGroupPosition++);

		CommitLocalsAction lockLocalAction = new CommitLocalsAction();
		setGroupInfo(lockLocalAction, commitGroup, subGroupPosition++);

		subGroupPosition = 0; // reset for the next group

		//
		// Highlight
		//
		String highlightGroup = "4a - Highlight Group";
		tool.setMenuGroup(new String[] { "Highlight" }, highlightGroup);
		HighlightDefinedUseAction defUseHighlightAction = new HighlightDefinedUseAction();
		setGroupInfo(defUseHighlightAction, highlightGroup, subGroupPosition++);

		ForwardSliceAction forwardSliceAction = new ForwardSliceAction();
		setGroupInfo(forwardSliceAction, highlightGroup, subGroupPosition++);

		BackwardsSliceAction backwardSliceAction = new BackwardsSliceAction();
		setGroupInfo(backwardSliceAction, highlightGroup, subGroupPosition++);

		ForwardSliceToPCodeOpsAction forwardSliceToOpsAction = new ForwardSliceToPCodeOpsAction();
		setGroupInfo(forwardSliceToOpsAction, highlightGroup, subGroupPosition++);

		BackwardsSliceToPCodeOpsAction backwardSliceToOpsAction =
			new BackwardsSliceToPCodeOpsAction();
		setGroupInfo(backwardSliceToOpsAction, highlightGroup, subGroupPosition++);

		tool.setMenuGroup(new String[] { "Secondary Highlight" }, highlightGroup);
		SetSecondaryHighlightAction setSecondaryHighlightAction = new SetSecondaryHighlightAction();
		setGroupInfo(setSecondaryHighlightAction, highlightGroup, subGroupPosition++);

		SetSecondaryHighlightColorChooserAction setSecondaryHighlightColorChooserAction =
			new SetSecondaryHighlightColorChooserAction();
		setGroupInfo(setSecondaryHighlightColorChooserAction, highlightGroup, subGroupPosition++);

		RemoveSecondaryHighlightAction removeSecondaryHighlightAction =
			new RemoveSecondaryHighlightAction();
		setGroupInfo(removeSecondaryHighlightAction, highlightGroup, subGroupPosition++);

		RemoveAllSecondaryHighlightsAction removeAllSecondadryHighlightsAction =
			new RemoveAllSecondaryHighlightsAction();
		setGroupInfo(removeAllSecondadryHighlightsAction, highlightGroup, subGroupPosition++);

		PreviousHighlightedTokenAction previousHighlightedTokenAction =
			new PreviousHighlightedTokenAction();
		setGroupInfo(previousHighlightedTokenAction, highlightGroup, subGroupPosition++);

		NextHighlightedTokenAction nextHighlightedTokenAction = new NextHighlightedTokenAction();
		setGroupInfo(nextHighlightedTokenAction, highlightGroup, subGroupPosition++);

		String convertGroup = "7 - Convert Group";
		subGroupPosition = 0;
		RemoveEquateAction removeEquateAction = new RemoveEquateAction();
		setGroupInfo(removeEquateAction, convertGroup, subGroupPosition++);

		SetEquateAction setEquateAction = new SetEquateAction(plugin);
		setGroupInfo(setEquateAction, convertGroup, subGroupPosition++);

		ConvertBinaryAction convertBinaryAction = new ConvertBinaryAction(plugin);
		setGroupInfo(convertBinaryAction, convertGroup, subGroupPosition++);

		ConvertDecAction convertDecAction = new ConvertDecAction(plugin);
		setGroupInfo(convertDecAction, convertGroup, subGroupPosition++);

		ConvertFloatAction convertFloatAction = new ConvertFloatAction(plugin);
		setGroupInfo(convertFloatAction, convertGroup, subGroupPosition++);

		ConvertDoubleAction convertDoubleAction = new ConvertDoubleAction(plugin);
		setGroupInfo(convertDoubleAction, convertGroup, subGroupPosition++);

		ConvertHexAction convertHexAction = new ConvertHexAction(plugin);
		setGroupInfo(convertHexAction, convertGroup, subGroupPosition++);

		ConvertOctAction convertOctAction = new ConvertOctAction(plugin);
		setGroupInfo(convertOctAction, convertGroup, subGroupPosition++);

		ConvertCharAction convertCharAction = new ConvertCharAction(plugin);
		setGroupInfo(convertCharAction, convertGroup, subGroupPosition++);

		//
		// Comments
		//
		// NOTE: this is just a placeholder to represent where the comment actions should appear
		//       in relation to our local actions.
		//

		//
		// Search
		//
		String searchGroup = "Comment2 - Search Group";
		subGroupPosition = 0; // reset for the next group

		FindAction findAction = new FindAction();
		setGroupInfo(findAction, searchGroup, subGroupPosition++);

		//
		// References
		//

		// note: set the menu group so that the 'References' group is with the 'Find' action
		String referencesParentGroup = searchGroup;

		FindReferencesToDataTypeAction findReferencesAction =
			new FindReferencesToDataTypeAction(owner, tool, controller);
		setGroupInfo(findReferencesAction, searchGroup, subGroupPosition++);
		findReferencesAction.getPopupMenuData().setParentMenuGroup(referencesParentGroup);

		FindReferencesToHighSymbolAction findReferencesToSymbolAction =
			new FindReferencesToHighSymbolAction();
		setGroupInfo(findReferencesToSymbolAction, searchGroup, subGroupPosition++);
		findReferencesToSymbolAction.getPopupMenuData().setParentMenuGroup(referencesParentGroup);
		addLocalAction(findReferencesToSymbolAction);

		FindReferencesToAddressAction findReferencesToAddressAction =
			new FindReferencesToAddressAction(tool, owner);
		setGroupInfo(findReferencesToAddressAction, searchGroup, subGroupPosition++);
		findReferencesToAddressAction.getPopupMenuData().setParentMenuGroup(referencesParentGroup);
		addLocalAction(findReferencesToAddressAction);

		//
		// Options
		//
		String optionsGroup = "comment6 - Options Group";
		subGroupPosition = 0; // reset for the next group

		EditPropertiesAction propertiesAction = new EditPropertiesAction(owner, tool);
		setGroupInfo(propertiesAction, optionsGroup, subGroupPosition++);

		//
		// These actions are not in the popup menu
		//
		DebugDecompilerAction debugFunctionAction = new DebugDecompilerAction(controller);
		ExportToCAction convertAction = new ExportToCAction();
		CloneDecompilerAction cloneDecompilerAction = new CloneDecompilerAction();
		GoToNextBraceAction goToNextBraceAction = new GoToNextBraceAction();
		GoToPreviousBraceAction goToPreviousBraceAction = new GoToPreviousBraceAction();

		addLocalAction(refreshAction);
		addLocalAction(displayUnreachableCodeToggle);
		addLocalAction(respectReadOnlyFlags);
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
		addLocalAction(forceUnionAction);
		addLocalAction(setSecondaryHighlightAction);
		addLocalAction(setSecondaryHighlightColorChooserAction);
		addLocalAction(removeSecondaryHighlightAction);
		addLocalAction(removeAllSecondadryHighlightsAction);
		addLocalAction(nextHighlightedTokenAction);
		addLocalAction(previousHighlightedTokenAction);
		addLocalAction(convertBinaryAction);
		addLocalAction(convertDecAction);
		addLocalAction(convertFloatAction);
		addLocalAction(convertDoubleAction);
		addLocalAction(convertHexAction);
		addLocalAction(convertOctAction);
		addLocalAction(convertCharAction);
		addLocalAction(setEquateAction);
		addLocalAction(removeEquateAction);
		addLocalAction(retypeLocalAction);
		addLocalAction(createRelativeAction);
		addLocalAction(retypeGlobalAction);
		addLocalAction(retypeReturnAction);
		addLocalAction(retypeFieldAction);
		addLocalAction(isolateVarAction);
		addLocalAction(decompilerCreateStructureAction);
		tool.addAction(listingCreateStructureAction);
		addLocalAction(editDataTypeAction);
		addLocalAction(specifyCProtoAction);
		addLocalAction(overrideSigAction);
		addLocalAction(editOverrideSigAction);
		addLocalAction(deleteSigAction);
		addLocalAction(renameFunctionAction);
		addLocalAction(renameLabelAction);
		addLocalAction(removeLabelAction);
		addLocalAction(debugFunctionAction);
		addLocalAction(convertAction);
		addLocalAction(findAction);
		addLocalAction(findReferencesAction);
		addLocalAction(propertiesAction);
		addLocalAction(cloneDecompilerAction);
		addLocalAction(goToNextBraceAction);
		addLocalAction(goToPreviousBraceAction);

		graphServiceAdded();
	}

	/**
	 * Sets the group and subgroup information for the given action.
	 */
	private void setGroupInfo(DockingAction action, String group, int subGroupPosition) {
		MenuData popupMenuData = action.getPopupMenuData();
		popupMenuData.setMenuGroup(group);

		// Some groups have numbers reach double-digits.  These will not compare correctly unless
		// padded.  Ensure all string numbers are at least 2 digits.
		String numberString = Integer.toString(subGroupPosition);
		if (numberString.length() == 1) {
			numberString = '0' + numberString;
		}
		popupMenuData.setMenuSubGroup(numberString);
	}

	private void graphServiceRemoved() {
		if (pcodeGraphAction == null) {
			return;
		}
		if (tool.getService(GraphDisplayBroker.class) == null) {
			tool.removeAction(pcodeGraphAction);
			tool.removeAction(astGraphAction);
			astGraphAction.dispose();
			pcodeGraphAction.dispose();
			pcodeGraphAction = null;
			astGraphAction = null;
		}
	}

	private void graphServiceAdded() {
		GraphDisplayBroker service = tool.getService(GraphDisplayBroker.class);
		if (service != null && service.getDefaultGraphDisplayProvider() != null) {
			pcodeGraphAction = new PCodeCfgAction();
			addLocalAction(pcodeGraphAction);
			astGraphAction = new PCodeDfgAction();
			addLocalAction(astGraphAction);
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
	public void removeHighlightProvider(ListingHighlightProvider highlightProvider, Program p) {
		// currently unsupported
	}

	@Override
	public void setHighlightProvider(ListingHighlightProvider highlightProvider, Program p) {
		// currently unsupported
	}

	public void programClosed(Program closedProgram) {
		controller.programClosed(closedProgram);
	}

	public void tokenRenamed(ClangToken tokenAtCursor, String newName) {
		plugin.handleTokenRenamed(tokenAtCursor, newName);
	}

	void handleTokenRenamed(ClangToken tokenAtCursor, String newName) {
		controller.getDecompilerPanel().tokenRenamed(tokenAtCursor, newName);
	}

	@Override
	public void addMarginProvider(DecompilerMarginProvider provider) {
		getDecompilerPanel().addMarginProvider(provider);
	}

	@Override
	public void removeMarginProvider(DecompilerMarginProvider provider) {
		getDecompilerPanel().removeMarginProvider(provider);
	}
}
