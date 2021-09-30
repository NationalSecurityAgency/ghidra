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
package ghidra.app.plugin.core.codebrowser;

import java.awt.Color;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.ImageIcon;
import javax.swing.JComponent;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import docking.widgets.fieldpanel.*;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.GhidraOptions;
import ghidra.app.context.ListingActionContext;
import ghidra.app.events.ProgramHighlightPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.codebrowser.hover.ListingHoverService;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.services.*;
import ghidra.app.util.*;
import ghidra.app.util.query.TableService;
import ghidra.app.util.viewer.field.ListingField;
import ghidra.app.util.viewer.field.ListingTextField;
import ghidra.app.util.viewer.format.*;
import ghidra.app.util.viewer.listingpanel.*;
import ghidra.app.util.viewer.options.ListingDisplayOptionsEditor;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.framework.model.*;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.*;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.*;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

public abstract class AbstractCodeBrowserPlugin<P extends CodeViewerProvider> extends Plugin
		implements CodeViewerService, CodeFormatService, OptionsChangeListener,
		FormatModelListener, DomainObjectListener, CodeBrowserPluginInterface {

	private static final Color CURSOR_LINE_COLOR = GhidraOptions.DEFAULT_CURSOR_LINE_COLOR;
	private static final String CURSOR_COLOR = "Cursor.Cursor Color - Focused";
	private static final String UNFOCUSED_CURSOR_COLOR = "Cursor.Cursor Color - Unfocused";
	private static final String BLINK_CURSOR = "Cursor.Blink Cursor";
	private static final String MOUSE_WHEEL_HORIZONTAL_SCROLLING = "Mouse.Horizontal Scrolling";

	// - Icon -
	private ImageIcon CURSOR_LOC_ICON =
		ResourceManager.loadImage("images/cursor_arrow_flipped.gif");
	protected final P connectedProvider;
	protected List<P> disconnectedProviders = new ArrayList<>();
	protected FormatManager formatMgr;
	protected ViewManagerService viewManager;
	private MarkerService markerService;
	protected AddressSetView currentView;
	protected Program currentProgram;
	private boolean selectionChanging;
	private MarkerSet currentSelectionMarkers;
	private MarkerSet currentHighlightMarkers;
	private MarkerSet currentCursorMarkers;
	private ChangeListener markerChangeListener;
	private FocusingMouseListener focusingMouseListener = new FocusingMouseListener();

	private DockingAction tableFromSelectionAction;
	private DockingAction showXrefsAction;

	private Color cursorHighlightColor;
	private boolean isHighlightCursorLine;
	private ProgramDropProvider dndProvider;

	public AbstractCodeBrowserPlugin(PluginTool tool) {
		super(tool);

		ToolOptions displayOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_DISPLAY);
		ToolOptions fieldOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		displayOptions.registerOptionsEditor(new ListingDisplayOptionsEditor(displayOptions));
		displayOptions.setOptionsHelpLocation(
			new HelpLocation(getName(), GhidraOptions.CATEGORY_BROWSER_DISPLAY));
		fieldOptions.setOptionsHelpLocation(
			new HelpLocation(getName(), GhidraOptions.CATEGORY_BROWSER_DISPLAY));

		formatMgr = new FormatManager(displayOptions, fieldOptions);
		formatMgr.addFormatModelListener(this);
		formatMgr.setServiceProvider(tool);
		connectedProvider = createProvider(formatMgr, true);
		tool.showComponentProvider(connectedProvider, true);
		initOptions(fieldOptions);
		initDisplayOptions(displayOptions);
		initMiscellaneousOptions();
		initActions();
		displayOptions.addOptionsChangeListener(this);
		fieldOptions.addOptionsChangeListener(this);
		tool.setDefaultComponent(connectedProvider);
		markerChangeListener = new MarkerChangeListener(connectedProvider);
		createActions();
	}

	protected abstract P createProvider(FormatManager formatManager, boolean isConnected);

	private void createActions() {
		new ActionBuilder("Select All", getName())
				.menuPath(ToolConstants.MENU_SELECTION, "&All in View")
				.menuGroup("Select Group", "a")
				.keyBinding("ctrl A")
				.supportsDefaultToolContext(true)
				.helpLocation(new HelpLocation(HelpTopics.SELECTION, "Select All"))
				.withContext(CodeViewerActionContext.class)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.onAction(c -> ((CodeViewerProvider) c.getComponentProvider()).selectAll())
				.buildAndInstall(tool);

		new ActionBuilder("Clear Selection", getName())
				.menuPath(ToolConstants.MENU_SELECTION, "&Clear Selection")
				.menuGroup("Select Group", "b")
				.supportsDefaultToolContext(true)
				.helpLocation(new HelpLocation(HelpTopics.SELECTION, "Clear Selection"))
				.withContext(CodeViewerActionContext.class)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.onAction(c -> ((CodeViewerProvider) c.getComponentProvider())
						.setSelection(new ProgramSelection()))
				.buildAndInstall(tool);

		new ActionBuilder("Select Complement", getName())
				.menuPath(ToolConstants.MENU_SELECTION, "&Complement")
				.menuGroup("Select Group", "c")
				.supportsDefaultToolContext(true)
				.helpLocation(new HelpLocation(HelpTopics.SELECTION, "Select Complement"))
				.withContext(CodeViewerActionContext.class)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.onAction(c -> ((CodeViewerProvider) c.getComponentProvider()).selectComplement())
				.buildAndInstall(tool);

	}

	protected void viewChanged(AddressSetView addrSet) {
		ProgramLocation currLoc = getCurrentLocation();
		currentView = addrSet;
		if (addrSet != null && !addrSet.isEmpty()) {
			connectedProvider.setView(addrSet);
			if (currLoc != null && addrSet.contains(currLoc.getAddress())) {
				goTo(currLoc, true);
			}
		}
		else {
			connectedProvider.setView(new AddressSet());
		}
		updateBackgroundColorModel();

		setHighlight(connectedProvider.getHighlight());
		setSelection(connectedProvider.getSelection());
	}

	@Override
	protected void init() {
		markerService = tool.getService(MarkerService.class);
		if (markerService != null) {
			markerService.addChangeListener(markerChangeListener);
		}
		updateBackgroundColorModel();

		if (viewManager == null) {
			viewManager = tool.getService(ViewManagerService.class);
		}

		ClipboardService clipboardService = tool.getService(ClipboardService.class);
		if (clipboardService != null) {
			connectedProvider.setClipboardService(clipboardService);
			for (CodeViewerProvider provider : disconnectedProviders) {
				provider.setClipboardService(clipboardService);
			}
		}
	}

	protected void updateBackgroundColorModel() {
		ListingPanel listingPanel = connectedProvider.getListingPanel();
		if (markerService != null) {
			AddressIndexMap indexMap = connectedProvider.getListingPanel().getAddressIndexMap();
			listingPanel.setBackgroundColorModel(
				new MarkerServiceBackgroundColorModel(markerService, indexMap));
		}
		else {
			listingPanel.setBackgroundColorModel(null);
		}

		// TODO: update all providers, not just the connected provider
	}

	@Override
	public P createNewDisconnectedProvider() {
		P newProvider = createProvider(formatMgr.createClone(), false);
		newProvider.setClipboardService(tool.getService(ClipboardService.class));
		disconnectedProviders.add(newProvider);
		if (dndProvider != null) {
			newProvider.addProgramDropProvider(dndProvider);
		}
		tool.showComponentProvider(newProvider, true);
		ListingHoverService[] hoverServices = tool.getServices(ListingHoverService.class);
		for (ListingHoverService hoverService : hoverServices) {
			newProvider.getListingPanel().addHoverService(hoverService);
		}
		return newProvider;
	}

	protected void setHighlight(FieldSelection highlight) {
		MarkerSet highlightMarkers = getHighlightMarkers(currentProgram);

		if (highlight != null && !highlight.isEmpty()) {
			ListingPanel listingPanel = connectedProvider.getListingPanel();
			ProgramSelection programHighlight = listingPanel.getProgramSelection(highlight);
			connectedProvider.setHighlight(programHighlight);

			firePluginEvent(
				new ProgramHighlightPluginEvent(this.getName(), programHighlight, currentProgram));

			if (highlightMarkers != null) {
				highlightMarkers.clearAll();
				highlightMarkers.add(programHighlight);
			}
		}
		else {
			connectedProvider.setHighlight(new ProgramSelection());
			if (highlightMarkers != null) {
				highlightMarkers.clearAll();
			}
		}
	}

	protected void removeProvider(CodeViewerProvider provider) {
		tool.removeComponentProvider(provider);
		provider.dispose();
	}

	@Override
	public void serviceAdded(Class<?> interfaceClass, Object service) {
		if (interfaceClass == TableService.class) {
			tool.addAction(tableFromSelectionAction);
			tool.addAction(showXrefsAction);
		}
		if (interfaceClass == ViewManagerService.class && viewManager == null) {
			viewManager = (ViewManagerService) service;
			viewChanged(viewManager.getCurrentView());
		}
		if (interfaceClass == MarkerService.class && markerService == null) {
			markerService = tool.getService(MarkerService.class);
			markerService.addChangeListener(markerChangeListener);
			updateBackgroundColorModel();
			if (viewManager != null) {
				viewChanged(viewManager.getCurrentView());
			}
		}
		if (interfaceClass == ListingHoverService.class) {
			ListingHoverService hoverService = (ListingHoverService) service;
			connectedProvider.getListingPanel().addHoverService(hoverService);
			for (CodeViewerProvider provider : disconnectedProviders) {
				provider.getListingPanel().addHoverService(hoverService);
			}
			ListingPanel otherPanel = connectedProvider.getOtherPanel();
			if (otherPanel != null) {
				otherPanel.addHoverService(hoverService);
			}
		}
	}

	@Override
	public void serviceRemoved(Class<?> interfaceClass, Object service) {
		if (interfaceClass == TableService.class) {
			if (tool != null) {
				tool.removeAction(tableFromSelectionAction);
				tool.removeAction(showXrefsAction);
			}
		}
		if ((service == viewManager) && (currentProgram != null)) {
			viewManager = null;
			viewChanged(currentProgram.getMemory());
		}
		if (service == markerService) {
			markerService.removeChangeListener(markerChangeListener);
			clearMarkers(currentProgram);
			markerService = null;
			updateBackgroundColorModel();
		}
		if (interfaceClass == ListingHoverService.class) {
			ListingHoverService hoverService = (ListingHoverService) service;
			connectedProvider.getListingPanel().removeHoverService(hoverService);
			for (CodeViewerProvider provider : disconnectedProviders) {
				provider.getListingPanel().removeHoverService(hoverService);
			}
			ListingPanel otherPanel = connectedProvider.getOtherPanel();
			if (otherPanel != null) {
				otherPanel.removeHoverService(hoverService);
			}
		}
	}

	@Override
	public void addOverviewProvider(OverviewProvider overviewProvider) {
		JComponent component = overviewProvider.getComponent();

		// just in case we get repeated calls
		component.removeMouseListener(focusingMouseListener);
		component.addMouseListener(focusingMouseListener);
		connectedProvider.getListingPanel().addOverviewProvider(overviewProvider);
	}

	@Override
	public void addMarginProvider(MarginProvider marginProvider) {
		JComponent component = marginProvider.getComponent();

		// just in case we get repeated calls
		component.removeMouseListener(focusingMouseListener);
		component.addMouseListener(focusingMouseListener);
		connectedProvider.getListingPanel().addMarginProvider(marginProvider);
	}

	@Override
	public void removeOverviewProvider(OverviewProvider overviewProvider) {
		JComponent component = overviewProvider.getComponent();
		component.removeMouseListener(focusingMouseListener);
		connectedProvider.getListingPanel().removeOverviewProvider(overviewProvider);
	}

	@Override
	public void removeMarginProvider(MarginProvider marginProvider) {
		JComponent component = marginProvider.getComponent();
		component.removeMouseListener(focusingMouseListener);
		connectedProvider.getListingPanel().removeMarginProvider(marginProvider);
	}

	@Override
	public void addLocalAction(DockingAction action) {
		tool.addLocalAction(connectedProvider, action);
	}

	@Override
	public void removeLocalAction(DockingAction action) {
		if (tool != null) {
			tool.removeLocalAction(connectedProvider, action);
		}
	}

	@Override
	public void addProgramDropProvider(ProgramDropProvider dnd) {
		this.dndProvider = dnd;
		connectedProvider.addProgramDropProvider(dnd);
		for (CodeViewerProvider provider : disconnectedProviders) {
			provider.addProgramDropProvider(dnd);
		}
	}

	@Override
	public void addButtonPressedListener(ButtonPressedListener listener) {
		connectedProvider.getListingPanel().addButtonPressedListener(listener);
	}

	@Override
	public void removeButtonPressedListener(ButtonPressedListener listener) {
		connectedProvider.getListingPanel().removeButtonPressedListener(listener);
	}

	@Override
	public void removeHighlightProvider(HighlightProvider highlightProvider,
			Program highlightProgram) {
		connectedProvider.removeHighlightProvider(highlightProvider, highlightProgram);
	}

	@Override
	public void setHighlightProvider(HighlightProvider highlightProvider,
			Program highlightProgram) {
		connectedProvider.setHighlightProvider(highlightProvider, highlightProgram);
	}

	protected void updateHighlightProvider() {
		connectedProvider.updateHighlightProvider();
	}

	@Override
	public void setListingPanel(ListingPanel lp) {
		connectedProvider.setPanel(lp);
		viewChanged(currentView);
	}

	@Override
	public void setCoordinatedListingPanelListener(CoordinatedListingPanelListener listener) {
		connectedProvider.setCoordinatedListingPanelListener(listener);
	}

	@Override
	public void setNorthComponent(JComponent comp) {
		connectedProvider.setNorthComponent(comp);

	}

	@Override
	public void removeListingPanel(ListingPanel lp) {
		if (isDisposed()) {
			return;
		}
		if (connectedProvider.getOtherPanel() == lp) {
			connectedProvider.clearPanel();
			viewChanged(currentView);
		}
	}

	@Override
	protected void dispose() {
		if (currentProgram != null) {
			currentProgram.removeListener(this);
		}
		clearMarkers(currentProgram);
		formatMgr.dispose();
		removeProvider(connectedProvider);
		for (CodeViewerProvider provider : disconnectedProviders) {
			removeProvider(provider);
		}
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {

		ListingPanel listingPanel = connectedProvider.getListingPanel();
		if (options.getName().equals(GhidraOptions.CATEGORY_BROWSER_DISPLAY)) {
			if (optionName.equals(OptionsGui.BACKGROUND.getColorOptionName())) {
				Color c = (Color) newValue;
				listingPanel.setTextBackgroundColor(c);
			}
		}
		else if (options.getName().equals(GhidraOptions.CATEGORY_BROWSER_FIELDS)) {

			FieldPanel fieldPanel = listingPanel.getFieldPanel();
			if (optionName.equals(GhidraOptions.OPTION_SELECTION_COLOR)) {
				Color color = ((Color) newValue);
				fieldPanel.setSelectionColor(color);
				MarkerSet selectionMarkers = getSelectionMarkers(currentProgram);
				if (selectionMarkers != null) {
					selectionMarkers.setMarkerColor(color);
				}
				ListingPanel otherPanel = connectedProvider.getOtherPanel();
				if (otherPanel != null) {
					otherPanel.getFieldPanel().setSelectionColor(color);
				}
			}
			else if (optionName.equals(GhidraOptions.OPTION_HIGHLIGHT_COLOR)) {
				Color color = ((Color) newValue);
				fieldPanel.setHighlightColor(color);
				MarkerSet highlightMarkers = getHighlightMarkers(currentProgram);
				if (highlightMarkers != null) {
					highlightMarkers.setMarkerColor(color);
				}
			}
			else if (optionName.equals(CURSOR_COLOR)) {
				Color color = ((Color) newValue);
				fieldPanel.setFocusedCursorColor(color);
			}
			else if (optionName.equals(UNFOCUSED_CURSOR_COLOR)) {
				Color color = ((Color) newValue);
				fieldPanel.setNonFocusCursorColor(color);
			}
			else if (optionName.equals(BLINK_CURSOR)) {
				Boolean isBlinkCursor = ((Boolean) newValue);
				fieldPanel.setBlinkCursor(isBlinkCursor);
			}
			else if (optionName.equals(GhidraOptions.HIGHLIGHT_CURSOR_LINE_COLOR)) {
				cursorHighlightColor = (Color) newValue;
				if (currentCursorMarkers != null) {
					currentCursorMarkers.setMarkerColor(cursorHighlightColor);
				}
			}
			else if (optionName.equals(GhidraOptions.HIGHLIGHT_CURSOR_LINE)) {
				isHighlightCursorLine = (Boolean) newValue;
				if (currentCursorMarkers != null) {
					currentCursorMarkers.setColoringBackground(isHighlightCursorLine);
				}
			}
			else if (optionName.equals(MOUSE_WHEEL_HORIZONTAL_SCROLLING)) {
				fieldPanel.setHorizontalScrollingEnabled((Boolean) newValue);
			}

			connectedProvider.fieldOptionChanged(optionName, newValue);
		}

	}

	@Override
	public void selectionChanged(CodeViewerProvider provider, ProgramSelection selection) {
		if (provider == connectedProvider) {
			MarkerSet selectionMarkers = getSelectionMarkers(currentProgram);
			if (selectionMarkers != null) {
				selectionMarkers.clearAll();
			}
			if (selection != null) {
				if (selectionMarkers != null) {
					selectionMarkers.add(selection);
				}
			}
			if (!selectionChanging) {
				tool.firePluginEvent(new ProgramSelectionPluginEvent(getName(), selection,
					connectedProvider.getProgram()));
			}
		}
	}

	protected void setHighlight(ProgramSelection highlight) {
		connectedProvider.setHighlight(highlight);
	}

	protected void setSelection(ProgramSelection sel) {
		selectionChanging = true;
		connectedProvider.setSelection(sel);
		selectionChanging = false;
	}

	protected void clearMarkers(Program program) {
		if (markerService == null) {
			return;
		}

		if (program == null) {
			return; // can happen during dispose after a programDeactivated()
		}

		if (currentSelectionMarkers != null) {
			markerService.removeMarker(currentSelectionMarkers, program);
			currentSelectionMarkers = null;
		}

		if (currentHighlightMarkers != null) {
			markerService.removeMarker(currentHighlightMarkers, program);
			currentHighlightMarkers = null;
		}

		if (currentCursorMarkers != null) {
			markerService.removeMarker(currentCursorMarkers, program);
			currentCursorMarkers = null;
		}
	}

	private MarkerSet getSelectionMarkers(Program program) {
		if (markerService == null || program == null) {
			return null;
		}

		// already created
		if (currentSelectionMarkers != null) {
			return currentSelectionMarkers;
		}

		FieldPanel fp = connectedProvider.getListingPanel().getFieldPanel();
		currentSelectionMarkers = markerService.createAreaMarker("Selection", "Selection Display",
			program, MarkerService.SELECTION_PRIORITY, false, true, false, fp.getSelectionColor());
		return currentSelectionMarkers;
	}

	protected MarkerSet getHighlightMarkers(Program program) {
		if (markerService == null || program == null) {
			return null;
		}

		// already created
		if (currentHighlightMarkers != null) {
			return currentHighlightMarkers;
		}

		FieldPanel fp = connectedProvider.getListingPanel().getFieldPanel();
		currentHighlightMarkers = markerService.createAreaMarker("Highlight", "Highlight Display ",
			program, MarkerService.HIGHLIGHT_PRIORITY, false, true, false, fp.getHighlightColor());
		return currentHighlightMarkers;
	}

	protected MarkerSet getCursorMarkers(Program program) {
		if (markerService == null || program == null) {
			return null;
		}

		// already created
		if (currentCursorMarkers != null) {
			return currentCursorMarkers;
		}

		currentCursorMarkers = markerService.createPointMarker("Cursor", "Cursor Location", program,
			MarkerService.CURSOR_PRIORITY, true, true, isHighlightCursorLine, cursorHighlightColor,
			CURSOR_LOC_ICON);

		return currentCursorMarkers;
	}

	private void initOptions(Options fieldOptions) {

		HelpLocation helpLocation = new HelpLocation(getName(), "Selection Colors");
		fieldOptions.getOptions("Selection Colors").setOptionsHelpLocation(helpLocation);

		fieldOptions.registerOption(GhidraOptions.OPTION_SELECTION_COLOR,
			GhidraOptions.DEFAULT_SELECTION_COLOR, helpLocation,
			"The selection color in the browser.");
		fieldOptions.registerOption(GhidraOptions.OPTION_HIGHLIGHT_COLOR,
			GhidraOptions.DEFAULT_HIGHLIGHT_COLOR, helpLocation,
			"The highlight color in the browser.");

		fieldOptions.registerOption(CURSOR_COLOR, Color.RED, helpLocation,
			"The color of the cursor in the browser.");
		fieldOptions.registerOption(UNFOCUSED_CURSOR_COLOR, Color.PINK, helpLocation,
			"The color of the cursor in the browser when the browser does not have focus.");
		fieldOptions.registerOption(BLINK_CURSOR, true, helpLocation,
			"When selected, the cursor will blink when the containing window is focused.");
		fieldOptions.registerOption(GhidraOptions.HIGHLIGHT_CURSOR_LINE_COLOR, CURSOR_LINE_COLOR,
			helpLocation, "The background color of the line where the cursor is located");
		fieldOptions.registerOption(GhidraOptions.HIGHLIGHT_CURSOR_LINE, true, helpLocation,
			"Toggles highlighting background color of line containing the cursor");

		helpLocation = new HelpLocation(getName(), "Keyboard_Controls_Shift");
		fieldOptions.registerOption(MOUSE_WHEEL_HORIZONTAL_SCROLLING, true, helpLocation,
			"Enables horizontal scrolling by holding the Shift key while " +
				"using the mouse scroll wheel");

		Color color = fieldOptions.getColor(GhidraOptions.OPTION_SELECTION_COLOR,
			GhidraOptions.DEFAULT_SELECTION_COLOR);

		FieldPanel fieldPanel = connectedProvider.getListingPanel().getFieldPanel();
		fieldPanel.setSelectionColor(color);
		MarkerSet selectionMarkers = getSelectionMarkers(currentProgram);
		if (selectionMarkers != null) {
			selectionMarkers.setMarkerColor(color);
		}

		color =
			fieldOptions.getColor(GhidraOptions.OPTION_HIGHLIGHT_COLOR, new Color(255, 255, 180));
		MarkerSet highlightMarkers = getHighlightMarkers(currentProgram);
		fieldPanel.setHighlightColor(color);
		if (highlightMarkers != null) {
			highlightMarkers.setMarkerColor(color);
		}

		color = fieldOptions.getColor(CURSOR_COLOR, Color.RED);
		fieldPanel.setFocusedCursorColor(color);

		color = fieldOptions.getColor(UNFOCUSED_CURSOR_COLOR, Color.PINK);
		fieldPanel.setNonFocusCursorColor(color);

		Boolean isBlinkCursor = fieldOptions.getBoolean(BLINK_CURSOR, true);
		fieldPanel.setBlinkCursor(isBlinkCursor);

		boolean horizontalScrollingEnabled =
			fieldOptions.getBoolean(MOUSE_WHEEL_HORIZONTAL_SCROLLING, true);
		fieldPanel.setHorizontalScrollingEnabled(horizontalScrollingEnabled);

		cursorHighlightColor =
			fieldOptions.getColor(GhidraOptions.HIGHLIGHT_CURSOR_LINE_COLOR, CURSOR_LINE_COLOR);

		isHighlightCursorLine = fieldOptions.getBoolean(GhidraOptions.HIGHLIGHT_CURSOR_LINE, true);
	}

	private void initDisplayOptions(Options displayOptions) {
		Color color = displayOptions.getColor(OptionsGui.BACKGROUND.getColorOptionName(),
			OptionsGui.BACKGROUND.getDefaultColor());
		connectedProvider.getListingPanel().setTextBackgroundColor(color);
	}

	private void initMiscellaneousOptions() {
		// make sure the following options are registered
		HelpLocation helpLocation =
			new HelpLocation("ShowInstructionInfoPlugin", "Processor_Manual_Options");
		Options options = tool.getOptions(ManualViewerCommandWrappedOption.OPTIONS_CATEGORY_NAME);
		options.registerOption(ManualViewerCommandWrappedOption.MANUAL_VIEWER_OPTIONS,
			OptionType.CUSTOM_TYPE,
			ManualViewerCommandWrappedOption.getDefaultBrowserLoaderOptions(), helpLocation,
			"Options for running manual viewer", new ManualViewerCommandEditor());

	}

	public void initActions() {

		// note: these actions gets added later when the TableService is added

		tableFromSelectionAction = new DockingAction("Create Table From Selection", getName()) {
			ImageIcon markerIcon = ResourceManager.loadImage("images/searchm_obj.gif");

			@Override
			public void actionPerformed(ActionContext context) {
				Listing listing = currentProgram.getListing();
				ProgramSelection selection = connectedProvider.getSelection();
				CodeUnitIterator codeUnits = listing.getCodeUnits(selection, true);
				TableService tableService = tool.getService(TableService.class);
				if (!codeUnits.hasNext()) {
					tool.setStatusInfo(
						"Unable to create table from selection: no " + "code units in selection");
					return;
				}

				GhidraProgramTableModel<Address> model = createTableModel(codeUnits, selection);
				String title = "Selection Table";
				TableComponentProvider<Address> tableProvider =
					tableService.showTableWithMarkers(title + " " + model.getName(), "Selection",
						model, PluginConstants.SEARCH_HIGHLIGHT_COLOR, markerIcon, title, null);
				tableProvider.installRemoveItemsAction();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				ProgramSelection programSelection = connectedProvider.getSelection();
				return programSelection != null && !programSelection.isEmpty();
			}
		};

		tableFromSelectionAction.setEnabled(false);
		tableFromSelectionAction.setMenuBarData(new MenuData(
			new String[] { ToolConstants.MENU_SELECTION, "Create Table From Selection" }, null,
			"SelectUtils"));
		tableFromSelectionAction
				.setHelpLocation(new HelpLocation("CodeBrowserPlugin", "Selection_Table"));

		showXrefsAction = new ActionBuilder("Show Xrefs", getName())
				.description("Show the Xrefs to the code unit containing the cursor")
				.validContextWhen(context -> context instanceof ListingActionContext)
				.onAction(context -> showXrefs(context))
				.build();
	}

	private void showXrefs(ActionContext context) {

		TableService service = tool.getService(TableService.class);
		if (service == null) {
			return;
		}

		ListingActionContext lac = (ListingActionContext) context;
		ProgramLocation location = lac.getLocation();
		if (location == null) {
			return; // not sure if this can happen
		}

		Set<Reference> refs = XReferenceUtil.getAllXrefs(location);
		XReferenceUtil.showAllXrefs(connectedProvider, tool, service, location, refs);
	}

	private GhidraProgramTableModel<Address> createTableModel(CodeUnitIterator iterator,
			ProgramSelection selection) {

		CodeUnitFromSelectionTableModelLoader loader =
			new CodeUnitFromSelectionTableModelLoader(iterator, selection);

		return new CustomLoadingAddressTableModel(" - from " + selection.getMinAddress(), tool,
			currentProgram, loader, null, true);
	}

	@Override
	public void updateDisplay() {
		connectedProvider.getListingPanel().updateDisplay(false);
	}

	@Override
	public FieldPanel getFieldPanel() {
		return connectedProvider.getListingPanel().getFieldPanel();
	}

	@Override
	public Navigatable getNavigatable() {
		return connectedProvider;
	}

//==================================================================================================
// Testing Methods
//==================================================================================================

	public void updateNow() {
		SystemUtilities.runSwingNow(() -> connectedProvider.getListingPanel().updateDisplay(true));
	}

	/**
	 * Positions the cursor to the given location
	 * 
	 * @param address the address to goto
	 * @param fieldName the name of the field to
	 * @param row the row within the given field
	 * @param col the col within the given row
	 * @return true if the specified location was found, false otherwise
	 */
	public boolean goToField(Address address, String fieldName, int row, int col) {
		return goToField(address, fieldName, 0, row, col, true);
	}

	/**
	 * Positions the cursor to the given location
	 * 
	 * @param addr the address to goto
	 * @param fieldName the name of the field to
	 * @param occurrence specifies the which occurrence for multiple fields of same type
	 * @param row the row within the given field
	 * @param col the col within the given row
	 * @return true if the specified location was found, false otherwise
	 */
	public boolean goToField(Address addr, String fieldName, int occurrence, int row, int col) {
		return goToField(addr, fieldName, occurrence, row, col, true);
	}

	/**
	 * Positions the cursor to the given location
	 *
	 * @param a the address to goto
	 * @param fieldName the name of the field to
	 * @param occurrence specifies the which occurrence for multiple fields of same type
	 * @param row the row within the given field
	 * @param col the col within the given row
	 * @param scroll specifies if the field panel to scroll the position to the center of the screen
	 * @return true if the specified location was found, false otherwise
	 */
	public boolean goToField(Address a, String fieldName, int occurrence, int row, int col,
			boolean scroll) {

		boolean result = SystemUtilities
				.runSwingNow(() -> doGoToField(a, fieldName, occurrence, row, col, scroll));
		return result;
	}

	private boolean doGoToField(Address a, String fieldName, int occurrence, int row, int col,
			boolean scroll) {

		Swing.assertSwingThread("'Go To' must be performed on the Swing thread");

		// make sure that the code browser is ready to go--sometimes it is not, due to timing
		// during the testing process, like when the tool is first loaded.
		updateNow();

		ListingPanel panel = connectedProvider.getListingPanel();
		if (a == null) {
			a = getCurrentAddress();
		}

		BigInteger index = panel.getAddressIndexMap().getIndex(a);
		FieldPanel fieldPanel = panel.getFieldPanel();
		int fieldNum = getFieldNumber(fieldName, occurrence, index, fieldPanel);
		if (fieldNum < 0) {
			return false;
		}

		if (scroll) {
			fieldPanel.goTo(index, fieldNum, row, col, true);
		}
		else {
			fieldPanel.setCursorPosition(index, fieldNum, row, col);
		}

		return true;
	}

	private int getFieldNumber(String fieldName, int occurrence, final BigInteger index,
			FieldPanel fieldPanel) {

		if (fieldName == null) {
			return -1;
		}

		int fieldNum = -1;
		LayoutModel model = fieldPanel.getLayoutModel();
		Layout layout = model.getLayout(index);
		if (layout == null) {
			return -1;
		}

		int instanceNum = 0;
		for (int i = 0; i < layout.getNumFields(); i++) {
			ListingField bf = (ListingField) layout.getField(i);
			if (bf.getFieldFactory().getFieldName().equals(fieldName)) {
				if (instanceNum++ == occurrence) {
					fieldNum = i;
					break;
				}
			}
		}
		return fieldNum;
	}

	public Address getCurrentAddress() {
		ProgramLocation loc = getCurrentLocation();
		if (loc == null) {
			return null;
		}
		return getCurrentLocation().getAddress();
	}

	@Override
	public ProgramSelection getCurrentSelection() {
		return connectedProvider.getListingPanel().getProgramSelection();
	}

	Program getCurrentProgram() {
		return currentProgram;
	}

	public CodeViewerProvider getProvider() {
		return connectedProvider;
	}

	public boolean goTo(ProgramLocation location) {
		return goTo(location, true);
	}

	@Override
	public boolean goTo(ProgramLocation location, boolean centerOnScreen) {

		AtomicBoolean didGoTo = new AtomicBoolean();
		SystemUtilities.runSwingNow(() -> {
			boolean success = connectedProvider.getListingPanel().goTo(location, centerOnScreen);
			didGoTo.set(success);
		});
		return didGoTo.get();
	}

	@Override
	public ProgramLocation getCurrentLocation() {
		return connectedProvider.getListingPanel().getProgramLocation();
	}

	public FieldLocation getCurrentFieldLoction() {
		return getFieldPanel().getCursorLocation();
	}

	@Override
	public String getCurrentFieldTextSelection() {
		return connectedProvider.getStringSelection();
	}

	@Override
	public ListingField getCurrentField() {
		Field f = getFieldPanel().getCurrentField();
		if (f instanceof ListingField) {
			return (ListingField) f;
		}
		return null;
	}

	@Override
	public void addListingDisplayListener(AddressSetDisplayListener listener) {
		connectedProvider.addDisplayListener(listener);
	}

	@Override
	public void removeListingDisplayListener(AddressSetDisplayListener listener) {
		connectedProvider.removeDisplayListener(listener);
	}

	public String getCurrentFieldText() {
		ListingField lf = getCurrentField();
		if (lf instanceof ListingTextField) {
			return ((ListingTextField) lf).getText();
		}
		return "";
	}

	@Override
	public AddressSetView getView() {
		return currentView;
	}

	@Override
	public FormatManager getFormatManager() {
		return formatMgr;
	}

	public void toggleOpen(Data data) {
		connectedProvider.getListingPanel().getListingModel().toggleOpen(data);
	}

	@Override
	public AddressIndexMap getAddressIndexMap() {
		return getListingPanel().getAddressIndexMap();
	}

	@Override
	public ListingPanel getListingPanel() {
		return connectedProvider.getListingPanel();
	}

	Address getAddressTopOfScreen() {
		BigInteger index = getFieldPanel().getViewerPosition().getIndex();
		return getAddressIndexMap().getAddress(index);
	}

	@Override
	public void formatModelAdded(FieldFormatModel model) {
		// uninterested
	}

	@Override
	public void formatModelRemoved(FieldFormatModel model) {
		// uninterested
	}

	@Override
	public void formatModelChanged(FieldFormatModel model) {
		tool.setConfigChanged(true);
	}

	@Override
	public ListingModel getListingModel() {
		return connectedProvider.getListingPanel().getListingModel().copy();
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (ev.containsEvent(DomainObject.DO_DOMAIN_FILE_CHANGED)) {
			connectedProvider.updateTitle();
		}

		if (viewManager != null) {
			return;
		}
		if (ev.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
			viewChanged(currentProgram.getMemory());
		}
	}

	@Override
	public void providerClosed(CodeViewerProvider codeViewerProvider) {
		removeProvider(codeViewerProvider);
		if (!codeViewerProvider.isConnected()) {
			disconnectedProviders.remove(codeViewerProvider);
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	static class MarkerChangeListener implements ChangeListener {
		private FieldPanel fieldPanel;

		MarkerChangeListener(CodeViewerProvider provider) {
			this.fieldPanel = provider.getListingPanel().getFieldPanel();
		}

		@Override
		public void stateChanged(ChangeEvent e) {
			fieldPanel.repaint();
		}
	}

	private class FocusingMouseListener extends MouseAdapter {
		@Override
		public void mousePressed(MouseEvent e) {
			connectedProvider.getListingPanel().getFieldPanel().requestFocus();
		}
	}

	private class CodeUnitFromSelectionTableModelLoader implements TableModelLoader<Address> {

		private CodeUnitIterator iterator;
		private ProgramSelection selection;

		CodeUnitFromSelectionTableModelLoader(CodeUnitIterator iterator,
				ProgramSelection selection) {
			this.iterator = iterator;
			this.selection = selection;
		}

		@Override
		public void load(Accumulator<Address> accumulator, TaskMonitor monitor)
				throws CancelledException {

			long size = selection.getNumAddresses();
			monitor.initialize(size);

			while (iterator.hasNext()) {
				monitor.checkCanceled();
				CodeUnit cu = iterator.next();
				accumulator.add(cu.getMinAddress());
				monitor.incrementProgress(cu.getLength());
			}
		}
	}
}
