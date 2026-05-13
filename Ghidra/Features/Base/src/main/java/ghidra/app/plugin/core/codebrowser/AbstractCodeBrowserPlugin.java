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
import java.util.function.Consumer;

import javax.swing.JComponent;

import docking.action.DockingAction;
import docking.widgets.fieldpanel.*;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.FieldSelection;
import generic.theme.GColor;
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

	protected final P connectedProvider;
	protected List<P> disconnectedProviders = new ArrayList<>();
	protected FormatManager formatMgr;
	protected ViewManagerService viewManager;

	protected AddressSetView currentView = ImmutableAddressSet.EMPTY_SET;
	protected Program currentProgram;
	private boolean selectionChanging;

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
	}

	protected abstract P createProvider(FormatManager formatManager, boolean isConnected);

	protected void setView(AddressSetView newView) {

		if (currentView.hasSameAddresses(newView)) {
			return;
		}

		ProgramLocation location = getCurrentLocation();
		currentView = ImmutableAddressSet.asImmutable(newView);

		connectedProvider.setView(currentView);

		if (location != null && currentView.contains(location.getAddress())) {
			goTo(location, true);
		}

		viewUpdated();
	}

	private void viewUpdated() {
		updateBackgroundColorModel();
		connectedProvider.setHighlight(connectedProvider.getHighlight());
		setConnectedProviderSelection(connectedProvider.getSelection());
	}

	@Override
	protected void init() {
		MarkerService markerService = tool.getService(MarkerService.class);
		setMarkerService(markerService);
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

		ListingMarginProviderService[] marginServices =
			tool.getServices(ListingMarginProviderService.class);
		for (ListingMarginProviderService marginService : marginServices) {
			connectedProvider.addMarginService(marginService);
		}

		ListingOverviewProviderService[] overviewServices =
			tool.getServices(ListingOverviewProviderService.class);
		for (ListingOverviewProviderService service : overviewServices) {
			connectedProvider.addOverviewService(service);
		}
	}

	protected void updateBackgroundColorModel() {

		updateBackgroundColorModel(connectedProvider);
		for (CodeViewerProvider provider : disconnectedProviders) {
			updateBackgroundColorModel(provider);
		}
	}

	protected void updateBackgroundColorModel(CodeViewerProvider provider) {
		ListingPanel listingPanel = provider.getListingPanel();
		listingPanel.updateBackgroundColorModel();
	}

	@Override
	public P createNewDisconnectedProvider() {
		P newProvider = createProvider(formatMgr.createClone(), false);
		newProvider.setClipboardService(tool.getService(ClipboardService.class));

		ListingPanel listingPanel = newProvider.getListingPanel();
		FieldPanel fieldPanel = listingPanel.getFieldPanel();
		List<ListingPanel> listingPanels = List.of(listingPanel);
		List<FieldPanel> fieldPanels = List.of(fieldPanel);
		initPanelOptions(listingPanels, fieldPanels);

		disconnectedProviders.add(newProvider);
		if (dndProvider != null) {
			newProvider.addProgramDropProvider(dndProvider);
		}

		ListingHoverService[] hoverServices = tool.getServices(ListingHoverService.class);
		for (ListingHoverService hoverService : hoverServices) {
			listingPanel.addHoverService(hoverService);
		}

		ListingMarginProviderService[] marginServices =
			tool.getServices(ListingMarginProviderService.class);
		for (ListingMarginProviderService service : marginServices) {
			newProvider.addMarginService(service);
		}

		ListingOverviewProviderService[] overviewServices =
			tool.getServices(ListingOverviewProviderService.class);
		for (ListingOverviewProviderService service : overviewServices) {
			newProvider.addOverviewService(service);
		}

		MarkerService markerService = tool.getService(MarkerService.class);
		listingPanel.setMarkerService(markerService);

		updateBackgroundColorModel(newProvider);

		tool.showComponentProvider(newProvider, true);

		return newProvider;
	}

	// this is for tool highlights coming in to the plugin
	protected void setConnectedProviderHighlight(FieldSelection highlight) {

		if (highlight != null && !highlight.isEmpty()) {
			ListingPanel listingPanel = connectedProvider.getListingPanel();
			ProgramSelection programHighlight = listingPanel.getProgramSelection(highlight);
			connectedProvider.setHighlight(programHighlight);

			firePluginEvent(
				new ProgramHighlightPluginEvent(this.getName(), programHighlight, currentProgram));
		}
		else {
			connectedProvider.setHighlight(new ProgramSelection());
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
			setView(viewManager.getCurrentView());
		}
		if (interfaceClass == MarkerService.class) {
			MarkerService markerService = tool.getService(MarkerService.class);
			setMarkerService(markerService);
			updateBackgroundColorModel();

			if (viewManager != null) {
				viewUpdated();
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
		if (interfaceClass == ListingMarginProviderService.class) {
			ListingMarginProviderService marginService = (ListingMarginProviderService) service;
			connectedProvider.addMarginService(marginService);

			for (CodeViewerProvider provider : disconnectedProviders) {
				provider.addMarginService(marginService);
			}
		}
		if (interfaceClass == ListingOverviewProviderService.class) {
			ListingOverviewProviderService overviewService =
				(ListingOverviewProviderService) service;
			connectedProvider.addOverviewService(overviewService);

			for (CodeViewerProvider provider : disconnectedProviders) {
				provider.addOverviewService(overviewService);
			}
		}
	}

	private void setMarkerService(MarkerService markerService) {
		ListingPanel listingPanel = connectedProvider.getListingPanel();
		listingPanel.setMarkerService(markerService);
		for (CodeViewerProvider provider : disconnectedProviders) {
			listingPanel = provider.getListingPanel();
			listingPanel.setMarkerService(markerService);
		}
	}

	@Override
	public void serviceRemoved(Class<?> interfaceClass, Object service) {
		if ((service == viewManager) && (currentProgram != null)) {
			viewManager = null;
			setView(currentProgram.getMemory());
		}
		if (interfaceClass == MarkerService.class) {
			setMarkerService(null);
			connectedProvider.clearMarkers(currentProgram);
			updateBackgroundColorModel();
		}
		if (interfaceClass == ListingHoverService.class) {
			ListingHoverService hoverService = (ListingHoverService) service;
			connectedProvider.removeHoverService(hoverService);

			for (CodeViewerProvider provider : disconnectedProviders) {
				provider.removeHoverService(hoverService);
			}
		}
		if (interfaceClass == ListingMarginProviderService.class) {
			ListingMarginProviderService marginService = (ListingMarginProviderService) service;
			connectedProvider.removeMarginService(marginService);

			for (CodeViewerProvider provider : disconnectedProviders) {
				provider.removeMarginService(marginService);
			}
		}
		if (interfaceClass == ListingOverviewProviderService.class) {
			ListingOverviewProviderService overviewService =
				(ListingOverviewProviderService) service;
			connectedProvider.removeOverviewService(overviewService);

			for (CodeViewerProvider provider : disconnectedProviders) {
				provider.removeOverviewService(overviewService);
			}
		}
	}

	@Override
	public void addOverviewProvider(ListingOverviewProvider overviewProvider) {
		connectedProvider.addOverviewProvider(overviewProvider);
	}

	@Override
	public void addMarginProvider(ListingMarginProvider marginProvider) {
		connectedProvider.addMarginProvider(marginProvider);
	}

	@Override
	public void removeOverviewProvider(ListingOverviewProvider overviewProvider) {
		connectedProvider.removeOverviewProvider(overviewProvider);
	}

	@Override
	public void removeMarginProvider(ListingMarginProvider marginProvider) {
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

	@Override
	public void setListingPanel(ListingPanel lp) {
		connectedProvider.setOtherPanel(lp);
		viewUpdated();
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
			viewUpdated();
		}
	}

	@Override
	protected void dispose() {
		if (currentProgram != null) {
			currentProgram.removeListener(this);
		}
		connectedProvider.clearMarkers(currentProgram);
		formatMgr.dispose();
		removeProvider(connectedProvider);
		for (CodeViewerProvider provider : disconnectedProviders) {
			removeProvider(provider);
		}
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {

		if (!options.getName().equals(GhidraOptions.CATEGORY_BROWSER_FIELDS)) {
			return;
		}

		List<ListingPanel> listingPanels = allListingPanels();
		List<FieldPanel> fieldPanels = allFieldPanels();
		if (optionName.equals(GhidraOptions.OPTION_SELECTION_COLOR)) {
			Color color = ((Color) newValue);
			onListingPanels(listingPanels, lp -> lp.setSelectionColor(color));
		}
		else if (optionName.equals(GhidraOptions.OPTION_HIGHLIGHT_COLOR)) {
			Color color = ((Color) newValue);
			onListingPanels(listingPanels, lp -> lp.setHighlightColor(color));
		}
		else if (optionName.equals(CURSOR_COLOR_OPTIONS_NAME)) {
			Color color = ((Color) newValue);
			onFieldPanels(fieldPanels, fp -> fp.setFocusedCursorColor(color));
		}
		else if (optionName.equals(UNFOCUSED_CURSOR_COLOR_OPTIONS_NAME)) {
			Color color = ((Color) newValue);
			onFieldPanels(fieldPanels, fp -> fp.setNonFocusCursorColor(color));
		}
		else if (optionName.equals(GhidraOptions.HIGHLIGHT_CURSOR_LINE_COLOR)) {
			Color color = (Color) newValue;
			onListingPanels(listingPanels, lp -> lp.setCursorHighlightColor(color));
		}
		else if (optionName.equals(GhidraOptions.HIGHLIGHT_CURSOR_LINE)) {
			Boolean doHighlight = (Boolean) newValue;
			onListingPanels(listingPanels, lp -> lp.setHighlightCursorLineEnabled(doHighlight));
		}
		else if (optionName.equals(MOUSE_WHEEL_HORIZONTAL_SCROLLING_OPTIONS_NAME)) {
			Boolean doScroll = (Boolean) newValue;
			onFieldPanels(fieldPanels, fp -> fp.setHorizontalScrollingEnabled(doScroll));
		}
	}

	protected void onFieldPanels(List<FieldPanel> panels, Consumer<FieldPanel> c) {
		for (FieldPanel fp : panels) {
			c.accept(fp);
		}
	}

	protected void onListingPanels(List<ListingPanel> listingPanels, Consumer<ListingPanel> c) {
		for (ListingPanel lp : listingPanels) {
			c.accept(lp);
		}
	}

	private List<ListingPanel> allListingPanels() {

		List<ListingPanel> results = new ArrayList<>();
		results.add(connectedProvider.getListingPanel());

		ListingPanel otherPanel = connectedProvider.getOtherPanel();
		if (otherPanel != null) {
			results.add(otherPanel);
		}

		for (CodeViewerProvider provider : disconnectedProviders) {
			results.add(provider.getListingPanel());
		}

		return results;
	}

	private List<FieldPanel> allFieldPanels() {
		List<FieldPanel> results = new ArrayList<>();

		FieldPanel fieldPanel = connectedProvider.getListingPanel().getFieldPanel();
		results.add(fieldPanel);

		ListingPanel otherPanel = connectedProvider.getOtherPanel();
		if (otherPanel != null) {
			FieldPanel otherFieldPanel = otherPanel.getFieldPanel();
			results.add(otherFieldPanel);
		}

		for (CodeViewerProvider provider : disconnectedProviders) {
			fieldPanel = provider.getListingPanel().getFieldPanel();
			results.add(fieldPanel);
		}

		return results;
	}

	@Override
	public void broadcastSelectionChanged(CodeViewerProvider provider, ProgramSelection selection) {
		if (provider == connectedProvider) {
			if (!selectionChanging) {
				tool.firePluginEvent(new ProgramSelectionPluginEvent(getName(), selection,
					connectedProvider.getProgram()));
			}
		}
	}

	protected void setConnectedProviderSelection(ProgramSelection sel) {
		selectionChanging = true;
		connectedProvider.setSelection(sel);
		selectionChanging = false;
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

		List<ListingPanel> listingPanels = allListingPanels();
		List<FieldPanel> fieldPanels = allFieldPanels();
		initPanelOptions(listingPanels, fieldPanels);
	}

	private void initPanelOptions(List<ListingPanel> listingPanels, List<FieldPanel> fieldPanels) {

		ToolOptions fieldOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);

		Color selectionColor = fieldOptions.getColor(GhidraOptions.OPTION_SELECTION_COLOR,
			GhidraOptions.DEFAULT_SELECTION_COLOR);
		onListingPanels(listingPanels, lp -> lp.setSelectionColor(selectionColor));

		Color hlColor = fieldOptions.getColor(GhidraOptions.OPTION_HIGHLIGHT_COLOR,
			GhidraOptions.DEFAULT_HIGHLIGHT_COLOR);
		onListingPanels(listingPanels, lp -> lp.setHighlightColor(hlColor));

		Color focusedCursorColor =
			fieldOptions.getColor(CURSOR_COLOR_OPTIONS_NAME, FOCUSED_CURSOR_COLOR);
		onFieldPanels(fieldPanels, fp -> fp.setFocusedCursorColor(focusedCursorColor));

		Color unfocusedCursorColor =
			fieldOptions.getColor(UNFOCUSED_CURSOR_COLOR_OPTIONS_NAME, UNFOCUSED_CURSOR_COLOR);
		onFieldPanels(fieldPanels, fp -> fp.setNonFocusCursorColor(unfocusedCursorColor));

		boolean scrollingEnabled =
			fieldOptions.getBoolean(MOUSE_WHEEL_HORIZONTAL_SCROLLING_OPTIONS_NAME, true);
		onFieldPanels(fieldPanels, fp -> fp.setHorizontalScrollingEnabled(scrollingEnabled));

		Color cursorHighlightColor =
			fieldOptions.getColor(GhidraOptions.HIGHLIGHT_CURSOR_LINE_COLOR,
				CURRENT_LINE_HIGHLIGHT_COLOR);
		onListingPanels(listingPanels, lp -> lp.setCursorHighlightColor(cursorHighlightColor));

		boolean isHighlightCursorLine =
			fieldOptions.getBoolean(GhidraOptions.HIGHLIGHT_CURSOR_LINE, true);
		onListingPanels(listingPanels,
			lp -> lp.setHighlightCursorLineEnabled(isHighlightCursorLine));
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

		if (ev.contains(DomainObjectEvent.RESTORED)) {
			if (viewManager == null) {
				setView(currentProgram.getMemory());
				viewUpdated();
			}
		}
	}

	@Override
	public void providerClosed(CodeViewerProvider codeViewerProvider) {
		removeProvider(codeViewerProvider);
		if (!codeViewerProvider.isConnected()) {
			disconnectedProviders.remove(codeViewerProvider);
		}
	}
}
