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
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;
import javax.swing.JComponent;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.action.DockingAction;
import docking.widgets.fieldpanel.*;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.FieldSelection;
import generic.theme.GColor;
import generic.theme.GIcon;
import ghidra.GhidraOptions;
import ghidra.app.events.ProgramHighlightPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.codebrowser.hover.ListingHoverService;
import ghidra.app.services.*;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.ProgramDropProvider;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.format.*;
import ghidra.app.util.viewer.listingpanel.*;
import ghidra.app.util.viewer.options.ListingDisplayOptionsEditor;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.framework.model.*;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.*;

public abstract class AbstractCodeBrowserPlugin<P extends CodeViewerProvider> extends Plugin
		implements CodeViewerService, CodeFormatService, OptionsChangeListener, FormatModelListener,
		DomainObjectListener, CodeBrowserPluginInterface {

	private static final String CURSOR_COLOR_OPTIONS_NAME = "Cursor.Cursor Color - Focused";
	private static final String UNFOCUSED_CURSOR_COLOR_OPTIONS_NAME =
		"Cursor.Cursor Color - Unfocused";
	private static final String MOUSE_WHEEL_HORIZONTAL_SCROLLING_OPTIONS_NAME =
		"Mouse.Horizontal Scrolling";

	//@formatter:off
	private static final GColor FOCUSED_CURSOR_COLOR = new GColor("color.cursor.focused.listing");
	private static final GColor UNFOCUSED_CURSOR_COLOR = new GColor("color.cursor.unfocused.listing");
	private static final GColor CURRENT_LINE_HIGHLIGHT_COLOR = new GColor("color.bg.currentline.listing");
	//@formatter:on

	// - Icon -
	private static final Icon CURSOR_LOC_ICON =
		new GIcon("icon.plugin.codebrowser.cursor.location");
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

	private Color cursorHighlightColor;
	private boolean isHighlightCursorLine;
	private ProgramDropProvider dndProvider;

	public AbstractCodeBrowserPlugin(PluginTool tool) {
		super(tool);

		ToolOptions displayOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_DISPLAY);
		ToolOptions fieldOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		displayOptions.registerOptionsEditor(() -> new ListingDisplayOptionsEditor(displayOptions));
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
		connectedProvider.getListingPanel().setTextBackgroundColor(ListingColors.BACKGROUND);
		initMiscellaneousOptions();
		displayOptions.addOptionsChangeListener(this);
		fieldOptions.addOptionsChangeListener(this);
		markerChangeListener = new MarkerChangeListener(connectedProvider);
	}

	protected abstract P createProvider(FormatManager formatManager, boolean isConnected);

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
		connectedProvider.addOverviewProvider(overviewProvider);
	}

	@Override
	public void addMarginProvider(MarginProvider marginProvider) {
		connectedProvider.addMarginProvider(marginProvider);
	}

	@Override
	public void removeOverviewProvider(OverviewProvider overviewProvider) {
		connectedProvider.removeOverviewProvider(overviewProvider);
	}

	@Override
	public void removeMarginProvider(MarginProvider marginProvider) {
		connectedProvider.removeMarginProvider(marginProvider);
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
	public void removeHighlightProvider(ListingHighlightProvider highlightProvider,
			Program highlightProgram) {
		connectedProvider.removeHighlightProvider(highlightProvider, highlightProgram);
	}

	@Override
	public void setHighlightProvider(ListingHighlightProvider highlightProvider,
			Program highlightProgram) {
		connectedProvider.setHighlightProvider(highlightProvider, highlightProgram);
	}

	protected void updateHighlightProvider() {
		connectedProvider.updateHighlightProvider();
	}

	@Override
	public void setListingPanel(ListingPanel lp) {
		connectedProvider.setOtherPanel(lp);
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
	public void requestFocus() {
		connectedProvider.requestFocus();
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
		if (options.getName().equals(GhidraOptions.CATEGORY_BROWSER_FIELDS)) {

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
			else if (optionName.equals(CURSOR_COLOR_OPTIONS_NAME)) {
				Color color = ((Color) newValue);
				fieldPanel.setFocusedCursorColor(color);
			}
			else if (optionName.equals(UNFOCUSED_CURSOR_COLOR_OPTIONS_NAME)) {
				Color color = ((Color) newValue);
				fieldPanel.setNonFocusCursorColor(color);
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
			else if (optionName.equals(MOUSE_WHEEL_HORIZONTAL_SCROLLING_OPTIONS_NAME)) {
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

		fieldOptions.registerThemeColorBinding(GhidraOptions.OPTION_SELECTION_COLOR,
			GhidraOptions.DEFAULT_SELECTION_COLOR.getId(), helpLocation,
			"The selection color in the browser.");
		fieldOptions.registerThemeColorBinding(GhidraOptions.OPTION_HIGHLIGHT_COLOR,
			GhidraOptions.DEFAULT_HIGHLIGHT_COLOR.getId(), helpLocation,
			"The highlight color in the browser.");

		fieldOptions.registerThemeColorBinding(CURSOR_COLOR_OPTIONS_NAME,
			FOCUSED_CURSOR_COLOR.getId(), helpLocation, "The color of the cursor in the browser.");
		fieldOptions.registerThemeColorBinding(UNFOCUSED_CURSOR_COLOR_OPTIONS_NAME,
			UNFOCUSED_CURSOR_COLOR.getId(), helpLocation,
			"The color of the cursor in the browser when the browser does not have focus.");
		fieldOptions.registerThemeColorBinding(GhidraOptions.HIGHLIGHT_CURSOR_LINE_COLOR,
			CURRENT_LINE_HIGHLIGHT_COLOR.getId(), helpLocation,
			"The background color of the line where the cursor is located");
		fieldOptions.registerOption(GhidraOptions.HIGHLIGHT_CURSOR_LINE, true, helpLocation,
			"Toggles highlighting background color of line containing the cursor");

		helpLocation = new HelpLocation(getName(), "Keyboard_Controls_Shift");
		fieldOptions.registerOption(MOUSE_WHEEL_HORIZONTAL_SCROLLING_OPTIONS_NAME, true,
			helpLocation, "Enables horizontal scrolling by holding the Shift key while " +
				"using the mouse scroll wheel");

		Color color = fieldOptions.getColor(GhidraOptions.OPTION_SELECTION_COLOR,
			GhidraOptions.DEFAULT_SELECTION_COLOR);

		FieldPanel fieldPanel = connectedProvider.getListingPanel().getFieldPanel();
		fieldPanel.setSelectionColor(color);
		MarkerSet selectionMarkers = getSelectionMarkers(currentProgram);
		if (selectionMarkers != null) {
			selectionMarkers.setMarkerColor(color);
		}

		color = fieldOptions.getColor(GhidraOptions.OPTION_HIGHLIGHT_COLOR,
			GhidraOptions.DEFAULT_HIGHLIGHT_COLOR);
		MarkerSet highlightMarkers = getHighlightMarkers(currentProgram);
		fieldPanel.setHighlightColor(color);
		if (highlightMarkers != null) {
			highlightMarkers.setMarkerColor(color);
		}

		color = fieldOptions.getColor(CURSOR_COLOR_OPTIONS_NAME, FOCUSED_CURSOR_COLOR);
		fieldPanel.setFocusedCursorColor(color);

		color = fieldOptions.getColor(UNFOCUSED_CURSOR_COLOR_OPTIONS_NAME, UNFOCUSED_CURSOR_COLOR);
		fieldPanel.setNonFocusCursorColor(color);

		boolean horizontalScrollingEnabled =
			fieldOptions.getBoolean(MOUSE_WHEEL_HORIZONTAL_SCROLLING_OPTIONS_NAME, true);
		fieldPanel.setHorizontalScrollingEnabled(horizontalScrollingEnabled);

		cursorHighlightColor = fieldOptions.getColor(GhidraOptions.HIGHLIGHT_CURSOR_LINE_COLOR,
			CURRENT_LINE_HIGHLIGHT_COLOR);

		isHighlightCursorLine = fieldOptions.getBoolean(GhidraOptions.HIGHLIGHT_CURSOR_LINE, true);
	}

	private void initMiscellaneousOptions() {
		// make sure the following options are registered
		HelpLocation helpLocation =
			new HelpLocation("ShowInstructionInfoPlugin", "Processor_Manual_Options");
		Options options = tool.getOptions(ManualViewerCommandWrappedOption.OPTIONS_CATEGORY_NAME);
		options.registerOption(ManualViewerCommandWrappedOption.MANUAL_VIEWER_OPTIONS,
			OptionType.CUSTOM_TYPE,
			ManualViewerCommandWrappedOption.getDefaultBrowserLoaderOptions(), helpLocation,
			"Options for running manual viewer", () -> new ManualViewerCommandEditor());

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

		return Swing.runNow(() -> doGoToField(a, fieldName, occurrence, row, col, scroll));
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
			Field f = layout.getField(i);
			if ((f instanceof ListingField bf) &&
				bf.getFieldFactory().getFieldName().equals(fieldName)) {
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

		return Swing
				.runNow(() -> connectedProvider.getListingPanel().goTo(location, centerOnScreen));
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
	public void formatModelChanged(FieldFormatModel model) {
		tool.setConfigChanged(true);
	}

	@Override
	public ListingModel getListingModel() {
		return connectedProvider.getListingPanel().getListingModel().copy();
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (ev.contains(DomainObjectEvent.FILE_CHANGED)) {
			connectedProvider.updateTitle();
		}

		if (viewManager != null) {
			return;
		}
		if (ev.contains(DomainObjectEvent.RESTORED)) {
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
}
