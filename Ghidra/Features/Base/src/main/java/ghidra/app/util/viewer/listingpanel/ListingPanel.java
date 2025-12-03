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
package ghidra.app.util.viewer.listingpanel;

import java.awt.*;
import java.awt.event.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.action.DockingActionIf;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.*;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.listener.*;
import docking.widgets.fieldpanel.support.*;
import docking.widgets.indexedscrollpane.IndexedScrollPane;
import generic.theme.GIcon;
import generic.theme.GThemeDefaults.Colors;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.codebrowser.LayeredColorModel;
import ghidra.app.plugin.core.codebrowser.MarkerServiceBackgroundColorModel;
import ghidra.app.plugin.core.codebrowser.hover.ListingHoverService;
import ghidra.app.services.*;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.format.FieldHeader;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.util.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.layout.HorizontalLayout;

public class ListingPanel extends JPanel implements FieldMouseListener, FieldLocationListener,
		FieldSelectionListener, LayoutListener {

	public static final int DEFAULT_DIVIDER_LOCATION = 70;
	private static final Icon CURSOR_LOC_ICON =
		new GIcon("icon.plugin.codebrowser.cursor.location");

	private FormatManager formatManager;
	private ListingModelAdapter layoutModel;

	private FieldPanel fieldPanel;
	private IndexedScrollPane scroller;
	private JSplitPane splitPane;
	private int splitPaneDividerLocation = DEFAULT_DIVIDER_LOCATION;

	private FocusingMouseListener focusingMouseListener = new FocusingMouseListener();
	private ProgramLocationListener programLocationListener;
	private ProgramSelectionListener programSelectionListener;
	private ProgramSelectionListener liveProgramSelectionListener;
	private StringSelectionListener stringSelectionListener;
	private FieldSelectionListener fieldPanelLiveSelectionListener = (selection, trigger) -> {

		if (liveProgramSelectionListener == null) {
			return;
		}

		ProgramSelection ps = layoutModel.getProgramSelection(selection);
		if (ps != null) {
			liveProgramSelectionListener.programSelectionChanged(ps, trigger);
		}
	};

	private ListingModel listingModel;
	private FieldHeader headerPanel;
	private List<ButtonPressedListener> buttonListeners = new ArrayList<>();
	private List<ChangeListener> indexMapChangeListeners = new ArrayList<>();

	private ListingHoverProvider listingHoverHandler;

	private List<ListingMarginProvider> marginProviders = new ArrayList<>();
	private List<ListingOverviewProvider> overviewProviders = new ArrayList<>();

	private String currentTextSelection;
	private boolean useMarkerNameSuffix;
	private UniversalID marginOwnerId = UniversalIdGenerator.nextID();

	private ChangeListener markerChangeListener;
	private MarkerService markerService;
	private Color cursorLineHighlightColor;
	private boolean isHighlightCursorLineEnabled;
	private MarkerSet selectionMarkers;
	private MarkerSet highlightMarkers;
	private MarkerSet cursorMarkers;

	private VerticalPixelAddressMapImpl pixmap;
	private PropertyBasedBackgroundColorModel propertyBasedColorModel;
	private LayeredColorModel layeredColorModel;
	private LayoutModelListener layoutModelListener = new LayoutModelListener() {

		@Override
		public void modelSizeChanged(IndexMapper mapper) {
			updateProviders();
		}

		@Override
		public void dataChanged(BigInteger start, BigInteger end) {
			// don't care
		}
	};
	private List<AddressSetDisplayListener> displayListeners = new ArrayList<>();

	/**
	 * Constructs a new ListingPanel using the given FormatManager
	 *
	 * @param manager the FormatManager to use.
	 */
	public ListingPanel(FormatManager manager) {
		super(new BorderLayout());
		this.formatManager = manager;
		layoutModel = createLayoutModel(null);
		fieldPanel = createFieldPanel(layoutModel);
		fieldPanel.addFieldMouseListener(this);
		fieldPanel.addFieldLocationListener(this);
		fieldPanel.addFieldSelectionListener(this);
		fieldPanel.addLiveFieldSelectionListener(fieldPanelLiveSelectionListener);
		fieldPanel.addLayoutListener(this);
		propertyBasedColorModel = new PropertyBasedBackgroundColorModel();
		fieldPanel.setBackgroundColorModel(propertyBasedColorModel);
		scroller = new IndexedScrollPane(fieldPanel);
		listingHoverHandler = new ListingHoverProvider();
		add(scroller, BorderLayout.CENTER);
		fieldPanel.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				for (ListingMarginProvider provider : marginProviders) {
					provider.getComponent().invalidate();
				}
				validate();
			}
		});

		String viewName = "Assembly Listing View";
		fieldPanel.setName(viewName);
		fieldPanel.getAccessibleContext().setAccessibleName(viewName);

		markerChangeListener = new MarkerChangeListener();
	}

	/**
	 * Constructs a new ListingPanel for the given program.
	 *
	 * @param mgr the FormatManager to use.
	 * @param program the program for which to create a new ListingPanel
	 */
	public ListingPanel(FormatManager mgr, Program program) {
		this(mgr);
		setProgram(program);
	}

	/**
	 * Constructs a new ListingPanel with the given FormatManager and ListingModel
	 *
	 * @param mgr the FormatManager to use
	 * @param model the ListingModel to use.
	 */
	public ListingPanel(FormatManager mgr, ListingModel model) {
		this(mgr);
		setListingModel(model);
		listingHoverHandler.setProgram(model.getProgram());
	}

	@Override
	public Dimension getPreferredSize() {
		Dimension preferredSize = super.getPreferredSize();
		// give new snapshots some decent room
		preferredSize.width = Math.max(preferredSize.width, getNewWindowDefaultWidth());
		return preferredSize;
	}

	/**
	 * A width for new windows that shows a reasonable amount of the Listing
	 * 
	 * @return the width
	 */
	protected int getNewWindowDefaultWidth() {
		return 500;
	}

	// extension point
	protected FieldPanel createFieldPanel(LayoutModel model) {
		FieldPanel fp = new FieldPanel(model, "Listing");
		fp.setFieldDescriptionProvider(new ListingFieldDescriptionProvider());
		return fp;
	}

	// extension point
	protected ListingModel createListingModel(Program program) {
		if (program == null) {
			return null;
		}

		return new ProgramBigListingModel(program, formatManager);
	}

	// extension point
	protected ListingModelAdapter createLayoutModel(ListingModel model) {
		ListingModelAdapter modelAdapter = new ListingModelAdapter(model);
		modelAdapter.addLayoutModelListener(layoutModelListener);
		return modelAdapter;
	}

	/**
	 * Sets the ProgramLocationListener.
	 * <p>
	 * Only one listener is supported
	 *
	 * @param listener the ProgramLocationListener to use.
	 */
	public void setProgramLocationListener(ProgramLocationListener listener) {
		this.programLocationListener = listener;
	}

	/**
	 * Sets the ProgramSelectionListener.
	 * <p>
	 * Only one listener is supported
	 *
	 * @param listener the ProgramSelectionListener to use.
	 */
	public void setProgramSelectionListener(ProgramSelectionListener listener) {
		programSelectionListener = listener;
	}

	/**
	 * Sets the ProgramSelectionListener for selection changes while dragging.
	 * <p>
	 * Only one listener is supported
	 *
	 * @param listener the ProgramSelectionListener to use.
	 */
	public void setLiveProgramSelectionListener(ProgramSelectionListener listener) {
		liveProgramSelectionListener = listener;
	}

	public void setStringSelectionListener(StringSelectionListener listener) {
		stringSelectionListener = listener;
	}

	/**
	 * Sets the ListingModel to use.
	 *
	 * @param newModel the model to use.
	 */
	public void setListingModel(ListingModel newModel) {
		layoutModel.dispose();
		listingModel = newModel;
		layoutModel = createLayoutModel(newModel);
		fieldPanel.setLayoutModel(layoutModel);
		Swing.runLater(() -> updateProviders());
	}

	/**
	 * Returns the current ListingModel used by this panel.
	 * 
	 * @return the model
	 */
	public ListingModel getListingModel() {
		return listingModel;
	}

	/**
	 * Sets whether or not the field header component is visible at the top of the listing panel
	 *
	 * @param show if true, the header component will be show, otherwise it will be hidden.
	 */
	public void showHeader(boolean show) {
		if (show) {
			headerPanel = new FieldHeader(formatManager, scroller, fieldPanel);
			// set the model to that of the field at the cursor location
			Field f = fieldPanel.getCurrentField();
			if (f instanceof ListingField currentField) {
				headerPanel.setSelectedFieldFactory(currentField.getFieldFactory());
			}
		}
		else {
			headerPanel.setViewComponent(null);
			headerPanel = null;
		}
		buildPanels();
	}

	public List<DockingActionIf> getHeaderActions(String ownerName) {
		if (headerPanel != null) {
			return headerPanel.getActions(ownerName);
		}
		return null;
	}

	/**
	 * Returns true if the field header component is showing.
	 * 
	 * @return true if showing
	 */
	public boolean isHeaderShowing() {
		return headerPanel != null;
	}

	private void updateProviders() {
		AddressIndexMap addressIndexMap = layoutModel.getAddressIndexMap();
		for (ListingMarginProvider provider : marginProviders) {
			provider.screenDataChanged(this, addressIndexMap, pixmap);
		}
		for (ListingOverviewProvider provider : overviewProviders) {
			provider.screenDataChanged(getProgram(), addressIndexMap);
		}
		for (ChangeListener indexMapChangeListener : indexMapChangeListeners) {
			indexMapChangeListener.stateChanged(null);
		}
		if (layeredColorModel != null) {
			layeredColorModel.modelDataChanged(this);
		}
		else {
			propertyBasedColorModel.modelDataChanged(this);
		}
	}

	public FieldHeader getFieldHeader() {
		return headerPanel;
	}

	public void updateDisplay(boolean updateImmediately) {
		layoutModel.dataChanged(updateImmediately);
	}

	public void removeMarginService(ListingMarginProviderService service) {
		for (ListingMarginProvider provider : marginProviders) {
			if (service.isOwner(provider)) {
				removeMarginProvider(provider);
				provider.dispose();
				return;
			}
		}
	}

	public void addMarginService(ListingMarginProviderService service, boolean isConnected) {
		if (containsMarginProviver(service)) {
			return;
		}

		ListingMarginProvider provider = service.createMarginProvider();
		provider.setOwnerId(marginOwnerId);
		addMarginProvider(provider);
	}

	private boolean containsMarginProviver(ListingMarginProviderService service) {
		for (ListingMarginProvider provider : marginProviders) {
			if (service.isOwner(provider)) {
				return true;
			}
		}
		return false;
	}

	public void removeOverviewService(ListingOverviewProviderService service) {
		for (ListingOverviewProvider provider : overviewProviders) {
			if (service.isOwner(provider)) {
				removeOverviewProvider(provider);
				provider.dispose();
				return;
			}
		}
	}

	public void addOverviewService(ListingOverviewProviderService service, Navigatable navigatable,
			boolean connected) {
		if (containsOverviewProvider(service)) {
			return;
		}

		ListingOverviewProvider provider = service.createOverviewProvider();
		provider.setNavigatable(navigatable);
		addOverviewProvider(provider);
	}

	private boolean containsOverviewProvider(ListingOverviewProviderService service) {
		for (ListingOverviewProvider provider : overviewProviders) {
			if (service.isOwner(provider)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Removes the given margin provider from this panel
	 *
	 * @param provider the MarginProvider to remove.
	 */
	public void removeMarginProvider(ListingMarginProvider provider) {
		JComponent component = provider.getComponent();
		component.removeMouseListener(focusingMouseListener);

		marginProviders.remove(provider);
		buildPanels();
	}

	/**
	 * Adds the margin provider to this panel.
	 * <p>
	 * This method is for clients that create and manage their own listing panels that are not the
	 * main listing panel.
	 *
	 * @param provider the provider that will  display in this listing panel's left margin area
	 */
	public void addMarginProvider(ListingMarginProvider provider) {

		JComponent component = provider.getComponent();
		component.removeMouseListener(focusingMouseListener);
		component.addMouseListener(focusingMouseListener);

		if (provider.isResizeable()) {
			marginProviders.add(0, provider);
		}
		else {
			marginProviders.add(provider);
		}
		provider.screenDataChanged(this, layoutModel.getAddressIndexMap(), pixmap);
		buildPanels();
	}

	private void buildPanels() {
		boolean fieldPanelHasFocus = fieldPanel.hasFocus();

		removeAll();
		add(buildLeftComponent(), BorderLayout.WEST);
		add(buildCenterComponent(), BorderLayout.CENTER);
		JComponent overviewComponent = buildOverviewComponent();
		if (overviewComponent != null) {
			scroller.setScrollbarSideKickComponent(buildOverviewComponent());
		}
		revalidate();
		repaint();

		if (fieldPanelHasFocus) {
			fieldPanel.requestFocusInWindow();
		}
	}

	private JComponent buildOverviewComponent() {
		if (overviewProviders.isEmpty()) {
			return null;
		}
		JPanel rightPanel = new JPanel(new HorizontalLayout(0));
		for (ListingOverviewProvider overviewProvider : overviewProviders) {
			rightPanel.add(overviewProvider.getComponent());
		}
		return rightPanel;
	}

	private JComponent buildLeftComponent() {
		List<ListingMarginProvider> marginProviderList = getNonResizeableMarginProviders();
		JPanel leftPanel = new JPanel(new ScrollpaneAlignedHorizontalLayout(scroller));
		for (ListingMarginProvider marginProvider : marginProviderList) {
			leftPanel.add(marginProvider.getComponent());
		}
		return leftPanel;
	}

	private List<ListingMarginProvider> getNonResizeableMarginProviders() {
		if (marginProviders.isEmpty()) {
			return marginProviders;
		}
		ListingMarginProvider firstMarginProvider = marginProviders.get(0);
		if (firstMarginProvider.isResizeable()) {
			return marginProviders.subList(1, marginProviders.size());
		}
		return marginProviders;
	}

	private JComponent buildCenterComponent() {
		JComponent centerComponent = scroller;
		ListingMarginProvider resizeableMarginProvider = getResizeableMarginProvider();
		if (resizeableMarginProvider != null) {
			if (splitPane != null) {
				splitPaneDividerLocation = splitPane.getDividerLocation();
			}
			JPanel resizeablePanel = new JPanel(new ScrollpanelResizeablePanelLayout(scroller));
			resizeablePanel.setBackground(Colors.BACKGROUND);
			resizeablePanel.add(resizeableMarginProvider.getComponent());
			splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, resizeablePanel, scroller);
			splitPane.setDividerSize(4);
			splitPane.setDividerLocation(splitPaneDividerLocation);
			splitPane.setContinuousLayout(true);
			splitPane.setBorder(null);
			centerComponent = splitPane;
		}
		if (headerPanel != null) {
			headerPanel.setViewComponent(centerComponent);
			centerComponent = headerPanel;
		}

		return centerComponent;
	}

	private ListingMarginProvider getResizeableMarginProvider() {
		if (marginProviders.isEmpty()) {
			return null;
		}
		ListingMarginProvider marginProvider = marginProviders.get(0);
		return marginProvider.isResizeable() ? marginProvider : null;
	}

	/**
	 * Add a change listener to be notified whenever the indexMap changes.
	 *
	 * @param listener the listener to be added.
	 */
	public void addIndexMapChangeListener(ChangeListener listener) {
		indexMapChangeListeners.add(listener);
	}

	/**
	 * Removes the change listener to be notified when the indexMap changes.
	 *
	 * @param listener the listener to be removed.
	 */
	public void removeIndexMapChangeListener(ChangeListener listener) {
		indexMapChangeListeners.remove(listener);
	}

	/**
	 * Adds the given OverviewProvider with will be displayed in this panels right margin area.
	 * <p>
	 * This method is for clients that create and manage their own listing panels that are not the
	 * main listing panel.
	 *
	 * @param provider the OverviewProvider to display.
	 */
	public void addOverviewProvider(ListingOverviewProvider provider) {

		JComponent component = provider.getComponent();
		component.removeMouseListener(focusingMouseListener);
		component.addMouseListener(focusingMouseListener);

		overviewProviders.add(provider);
		provider.screenDataChanged(getProgram(), layoutModel.getAddressIndexMap());
		buildPanels();
	}

	/**
	 * Removes the given OverviewProvider from this panel
	 *
	 * @param provider the OverviewProvider to remove.
	 */
	public void removeOverviewProvider(ListingOverviewProvider provider) {

		JComponent component = provider.getComponent();
		component.removeMouseListener(focusingMouseListener);

		overviewProviders.remove(provider);
		buildPanels();
	}

	/**
	 * Adds a ButtonPressedListener to be notified when the user presses the mouse button while over
	 * this panel
	 *
	 * @param listener the ButtonPressedListener to add.
	 */
	public void addButtonPressedListener(ButtonPressedListener listener) {
		buttonListeners.add(listener);
	}

	/**
	 * Removes the given ButtonPressedListener.
	 *
	 * @param listener the ButtonPressedListener to remove.
	 */
	public void removeButtonPressedListener(ButtonPressedListener listener) {
		buttonListeners.remove(listener);
	}

	/**
	 * Removes the given {@link ListingHighlightProvider} from this listing.
	 *
	 * @param highlightProvider The provider to remove.
	 * @see #addHighlightProvider(ListingHighlightProvider)
	 */
	public void removeHighlightProvider(ListingHighlightProvider highlightProvider) {
		formatManager.removeHighlightProvider(highlightProvider);
	}

	/**
	 * Adds a {@link ListingHighlightProvider} to this listing.
	 * <p>
	 * This highlight provider will be used with any other registered providers to paint all the
	 * highlights for this listing.
	 *
	 * @param highlightProvider The provider to add
	 */
	public void addHighlightProvider(ListingHighlightProvider highlightProvider) {
		formatManager.addHighlightProvider(highlightProvider);
	}

	/**
	 * Returns the FieldPanel used by this ListingPanel.
	 * 
	 * @return the field panel
	 */
	public FieldPanel getFieldPanel() {
		return fieldPanel;
	}

	@Override
	public void layoutsChanged(List<AnchoredLayout> layouts) {
		AddressIndexMap addrMap = layoutModel.getAddressIndexMap();
		this.pixmap = new VerticalPixelAddressMapImpl(layouts, addrMap);
		for (ListingMarginProvider provider : marginProviders) {
			provider.screenDataChanged(this, addrMap, pixmap);
		}

		for (AddressSetDisplayListener listener : displayListeners) {
			notifyDisplayListener(listener);
		}
	}

	private void notifyDisplayListener(AddressSetDisplayListener listener) {
		AddressSetView displayAddresses = pixmap.getAddressSet();
		try {
			listener.visibleAddressesChanged(displayAddresses);
		}
		catch (Throwable t) {
			Msg.showError(this, fieldPanel, "Error in Display Listener",
				"Exception encountered when notifying listeners of change in display", t);
		}
	}

	/**
	 * Returns the divider location between the left margin areas and the main display.
	 * 
	 * @return the location
	 */
	public int getDividerLocation() {
		if (splitPane != null) {
			return splitPane.getDividerLocation();
		}
		return splitPaneDividerLocation;
	}

	/**
	 * Sets the divider location between the left margin areas and the main display.
	 *
	 * @param dividerLocation the location to set on the divider.
	 */
	public void setDividerLocation(int dividerLocation) {
		splitPaneDividerLocation = dividerLocation;
		if (splitPane != null) {
			splitPane.setDividerLocation(dividerLocation);
		}
	}

	public void setListingHoverHandler(ListingHoverProvider handler) {
		if (handler == null) {
			throw new IllegalArgumentException("Cannot set the hover handler to null!");
		}

		if (listingHoverHandler != null) {
			if (listingHoverHandler.isShowing()) {
				listingHoverHandler.closeHover();
			}
			listingHoverHandler.initializeListingHoverHandler(handler);
			listingHoverHandler.dispose();
		}

		listingHoverHandler = handler;
		fieldPanel.setHoverProvider(listingHoverHandler);
	}

	public void dispose() {
		if (listingModel != null) {
			listingModel.dispose();
			listingModel = null;
		}

		setListingModel(null);

		for (ListingMarginProvider provider : marginProviders) {
			provider.dispose();
		}

		removeAll();
		listingHoverHandler.dispose();
		layoutModel.dispose();
		layoutModel = createLayoutModel(null);
		layoutModel.dispose();
		buttonListeners.clear();

		fieldPanel.dispose();
	}

	/**
	 * Moves the cursor to the given program location and repositions the scrollbar to show that
	 * location in the screen.
	 *
	 * @param loc the location to move to.
	 * @return true if successful
	 */
	public boolean goTo(ProgramLocation loc) {
		return goTo(loc, true);
	}

	/**
	 * Moves the cursor to the given program location.
	 * <p>
	 * Also, repositions the scrollbar to show that location, if the location is not on the screen.
	 *
	 * @param loc the location to move to.
	 * @param centerWhenNotVisible this variable only has an effect if the given location is not on
	 *            the screen. In that case, when this parameter is true, then the given location
	 *            will be placed in the center of the screen; when the parameter is false, then the
	 *            screen will be scrolled only enough to show the cursor.
	 * @return true if successful
	 */
	public boolean goTo(ProgramLocation loc, boolean centerWhenNotVisible) {
		Swing.assertSwingThread("goTo() must be called on the Swing thread");

		final FieldLocation floc = getFieldLocation(loc);
		if (floc == null) {
			return false;
		}

		if (centerWhenNotVisible) {
			fieldPanel.goTo(floc.getIndex(), floc.getFieldNum(), floc.getRow(), floc.getCol(),
				false);
		}
		else {
			fieldPanel.setCursorPosition(floc.getIndex(), floc.getFieldNum(), floc.getRow(),
				floc.getCol());
			fieldPanel.scrollToCursor();
		}
		return true;
	}

	/**
	 * Scroll the view of the listing to the given location.
	 * 
	 * <p>
	 * If the given location is not displayed, this has no effect.
	 * 
	 * @param location the location
	 */
	public void scrollTo(ProgramLocation location) {
		FieldLocation fieldLocation = getFieldLocation(location);
		if (fieldLocation == null) {
			return;
		}
		fieldPanel.scrollTo(fieldLocation);
	}

	/**
	 * Center the view of the listing around the given location.
	 * 
	 * @param location the location
	 */
	public void center(ProgramLocation location) {
		FieldLocation fieldLocation = getFieldLocation(location);
		fieldPanel.center(fieldLocation);
	}

	private FieldLocation getFieldLocation(ProgramLocation loc) {
		Program program = getProgram();
		if (program == null) {
			return null;
		}

		openDataOrFunctionAsNeeded(loc);

		FieldLocation floc = layoutModel.getFieldLocation(loc);
		if (floc != null) {
			return floc;
		}

		Address address = loc.getAddress();
		AddressSpace locAddressSpace = address.getAddressSpace();
		AddressSpace programAddressSpace =
			program.getAddressFactory().getAddressSpace(locAddressSpace.getSpaceID());
		if (programAddressSpace != locAddressSpace) {
			FieldLocation compatibleLocation =
				getFieldLocationForDifferingAddressSpaces(loc, program);
			return compatibleLocation;
		}

		return layoutModel.getFieldLocation(new ProgramLocation(program, address));
	}

	private FieldLocation getFieldLocationForDifferingAddressSpaces(ProgramLocation loc,
			Program program) {
		Address address = DiffUtility.getCompatibleMemoryAddress(loc.getAddress(), program);
		if (address == null) {
			return null;
		}

		CodeUnit cu = program.getListing().getCodeUnitContaining(address);
		if (cu instanceof Data) {
			Data data = (Data) cu;
			if (!cu.getMinAddress().equals(address)) {
				return getFieldLocationForDataAndOpenAsNeeded(data, address);
			}
			else if (!cu.getMinAddress().equals(loc.getByteAddress())) {
				return getFieldLocationForDataAndOpenAsNeeded(data, loc.getByteAddress());
			}
		}
		return layoutModel.getFieldLocation(new ProgramLocation(program, address));
	}

	private void openDataOrFunctionAsNeeded(ProgramLocation location) {
		if (location instanceof CollapsedCodeLocation) {
			return;
		}
		Address address = location.getByteAddress();
		Program program = getProgram();
		CodeUnit cu = program.getListing().getCodeUnitContaining(address);
		if (cu instanceof Data data) {
			openData(data, address);
		}
		else if (cu instanceof Instruction instruction) {
			openFunction(instruction);
		}

	}

	private void openFunction(Instruction instruction) {
		Address address = instruction.getMinAddress();
		Program program = instruction.getProgram();
		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function == null) {
			return;
		}
		Address functionAddress = function.getEntryPoint();
		// don't auto-open entry point addresses
		if (address.equals(functionAddress)) {
			return;
		}
		if (!listingModel.isFunctionOpen(functionAddress)) {
			listingModel.setFunctionOpen(functionAddress, true);
		}
	}

	private void openData(Data data, Address address) {
		if (data.getComponent(0) == null) {
			// not sub data to open
			return;
		}

		Data subData = data.getPrimitiveAt((int) address.subtract(data.getMinAddress()));
		if (subData == null) {
			return;
		}

		if (openAllData(subData)) {
			layoutModel.dataChanged(true);
		}

	}

	private FieldLocation getFieldLocationForDataAndOpenAsNeeded(Data data, Address address) {
		Data subData = data.getPrimitiveAt((int) address.subtract(data.getMinAddress()));
		if (subData != null) {
			boolean didOpen = openAllData(subData);
			if (didOpen) {
				layoutModel.dataChanged(true);
			}
		}

		while (subData != null) {
			Address addr = subData.getMinAddress();
			Program program = subData.getProgram();
			ProgramLocation location = new AddressFieldLocation(program, addr,
				subData.getComponentPath(), addr.toString(), 0);
			FieldLocation floc = layoutModel.getFieldLocation(location);
			if (floc != null) {
				return floc;
			}
			subData = subData.getParent();
		}
		return null;
	}

	private boolean openAllData(Data data) {
		boolean didOpen = false;
		while (data != null) {
			if (!listingModel.isOpen(data)) {
				didOpen |= listingModel.openData(data);
			}
			data = data.getParent();
		}
		return didOpen;
	}

	/**
	 * Positions the ListingPanel to the given address.
	 *
	 * @param addr the address at which to position the listing.
	 * @return true if successful
	 */
	public boolean goTo(Address addr) {
		Program p = getProgram();
		if (p != null) {
			return goTo(new ProgramLocation(p, addr));
		}
		return false;
	}

	/**
	 * Positions the ListingPanel to the given address.
	 *
	 * @param currentAddress used to determine which symbol to goto if the goto address has more
	 *            than one
	 * @param gotoAddress the address at which to position to listing.
	 * @return true if the address exists
	 */
	public boolean goTo(Address currentAddress, Address gotoAddress) {
		Program program = getProgram();
		if (program == null) {
			return false;
		}
		SymbolTable symTable = program.getSymbolTable();
		ReferenceManager refMgr = program.getReferenceManager();
		Reference ref = refMgr.getReference(currentAddress, gotoAddress, 0);
		Symbol symbol = symTable.getSymbol(ref);
		if (symbol != null) {
			ProgramLocation loc = symbol.getProgramLocation();
			if (loc != null) {
				return goTo(loc, true);
			}
		}
		return goTo(gotoAddress);
	}

	@Override
	public void buttonPressed(FieldLocation fieldLocation, Field field, MouseEvent mouseEvent) {
		if (fieldLocation == null || !(field instanceof ListingField listingField)) {
			return;
		}

		ProgramLocation programLocation =
			layoutModel.getProgramLocation(fieldLocation, listingField);
		if (programLocation == null) {
			return;
		}

		for (ButtonPressedListener element : buttonListeners) {
			element.buttonPressed(programLocation, fieldLocation, listingField, mouseEvent);
		}
	}

	/**
	 * Sets the program to be displayed by this listing panel
	 *
	 * @param program the program to display.
	 */
	public void setProgram(Program program) {
		listingHoverHandler.setProgram(program);
		setListingModel(createListingModel(program));
	}

	@Override
	public void fieldLocationChanged(FieldLocation location, Field field, EventTrigger trigger) {
		if (!(field instanceof ListingField lf)) {
			return;
		}

		if (isHeaderShowing()) {
			FieldFactory selectedFieldFactory = headerPanel.getSelectedFieldFactory();
			if (lf.getFieldFactory() != selectedFieldFactory) {
				headerPanel.setSelectedFieldFactory(lf.getFieldFactory());
				headerPanel.repaint();
			}
			headerPanel.setTabLock(false);
		}

		ProgramLocation pLoc = layoutModel.getProgramLocation(location, field);
		if (pLoc == null) {
			return;
		}

		if (programLocationListener != null) {
			programLocationListener.programLocationChanged(pLoc, trigger);
		}

		setCursorMarkerAddress(pLoc.getAddress());

		for (ListingMarginProvider provider : marginProviders) {
			provider.setLocation(pLoc);
		}
	}

	/**
	 * Restricts the program's view to the given address set
	 *
	 * @param view the set of address to include in the view.
	 */
	public void setView(AddressSetView view) {

		view = ImmutableAddressSet.asImmutable(view);

		AddressIndexMap currentMap = layoutModel.getAddressIndexMap();
		AddressSetView originalView = currentMap.getOriginalAddressSet();
		if (view.hasSameAddresses(originalView)) {
			return;
		}

		layoutModel.setAddressSet(view);
		updateProviders();
	}

	/**
	 * Gets the view of this listing panel (meant to be used in conjunction with
	 * {@link #setView(AddressSetView)}.
	 * 
	 * @return the addresses
	 */
	public AddressSetView getView() {
		AddressIndexMap map = layoutModel.getAddressIndexMap();
		return map.getOriginalAddressSet();
	}

	/**
	 * Sets the externally supplied {@link ListingBackgroundColorModel} to be blended with its own
	 * {@link PropertyBasedBackgroundColorModel}.
	 *
	 * @param colorModel the {@link ListingBackgroundColorModel} to use in conjunction with the
	 *            built-in {@link PropertyBasedBackgroundColorModel}
	 */
	public void setBackgroundColorModel(ListingBackgroundColorModel colorModel) {
		if (colorModel == null) {
			fieldPanel.setBackgroundColorModel(propertyBasedColorModel);
			layeredColorModel = null;
		}
		else {
			colorModel.modelDataChanged(this);
			layeredColorModel = new LayeredColorModel(colorModel, propertyBasedColorModel);
			fieldPanel.setBackgroundColorModel(layeredColorModel);
		}
	}

	/**
	 * Sets the background color for the listing panel.
	 * <p>
	 * This will set the background for the main listing display.
	 * 
	 * @param c the color
	 */
	public void setTextBackgroundColor(Color c) {
		if (fieldPanel != null) {
			fieldPanel.setBackgroundColor(c);
		}
	}

	public Color getTextBackgroundColor() {
		if (fieldPanel != null) {
			return fieldPanel.getBackgroundColor();
		}
		return null;
	}

	/**
	 * Returns true if this component has focus.
	 * 
	 * @return true if this component has focus.
	 */
	public boolean isActive() {
		return fieldPanel.isFocused();
	}

	/**
	 * Returns the current program location of the cursor.
	 * 
	 * @return the location
	 */
	public ProgramLocation getProgramLocation() {
		FieldLocation loc = fieldPanel.getCursorLocation();
		if (loc == null) {
			return null;
		}
		Field field = fieldPanel.getCurrentField();
		return layoutModel.getProgramLocation(loc, field);
	}

	/**
	 * Get a program location for the given point.
	 * 
	 * @param point the point
	 * @return program location, or null if point does not correspond to a program location
	 */
	public ProgramLocation getProgramLocation(Point point) {
		FieldLocation dropLoc = new FieldLocation();
		Field field = fieldPanel.getFieldAt(point.x, point.y, dropLoc);
		if (field instanceof ListingField lf) {
			return lf.getFieldFactory().getProgramLocation(dropLoc.getRow(), dropLoc.getCol(), lf);
		}
		return null;
	}

	/**
	 * Get the margin providers in this ListingPanel.
	 * 
	 * @return the providers
	 */
	public List<ListingMarginProvider> getMarginProviders() {
		return marginProviders;
	}

	/**
	 * Get the overview providers in this ListingPanel.
	 * 
	 * @return the providers
	 */
	public List<ListingOverviewProvider> getOverviewProviders() {
		return overviewProviders;
	}

	/**
	 * Returns true if the mouse is at a location that can be dragged.
	 * 
	 * @return true if the mouse is at a location that can be dragged.
	 */
	public boolean isStartDragOk() {
		return fieldPanel.isStartDragOK();
	}

	/**
	 * Sets the cursor to the given program location.
	 *
	 * @param loc the location at which to move the cursor.
	 */
	public void setCursorPosition(ProgramLocation loc) {
		setCursorPosition(loc, EventTrigger.API_CALL);
	}

	/**
	 * Sets the cursor to the given program location with a given trigger
	 * <p>
	 * This method should only be used in automated testing to programmatically simulate a user
	 * navigating within the listing panel.
	 *
	 * @param loc the location at which to move the cursor.
	 * @param trigger the event trigger
	 */
	public void setCursorPosition(ProgramLocation loc, EventTrigger trigger) {
		FieldLocation floc = getFieldLocation(loc);
		if (floc != null) {
			fieldPanel.setCursorPosition(floc.getIndex(), floc.getFieldNum(), floc.getRow(),
				floc.getCol(), trigger);
		}
	}

	public ProgramLocation getCursorLocation() {
		FieldLocation cursorPosition = fieldPanel.getCursorLocation();
		if (cursorPosition == null) {
			return null;
		}
		return layoutModel.getProgramLocation(cursorPosition, fieldPanel.getCurrentField());
	}

	public Point getCursorPoint() {
		return fieldPanel.getCursorPoint();
	}

	public Rectangle getCursorBounds() {
		return fieldPanel.getCursorBounds();
	}

	/**
	 * Returns the AddressIndexMap currently used by this listing panel.
	 * 
	 * @return the map
	 */
	public AddressIndexMap getAddressIndexMap() {
		return layoutModel.getAddressIndexMap();
	}

	/**
	 * Returns the vertical scrollbar used by this panel.
	 * 
	 * @return the scroll bar
	 */
	public JScrollBar getVerticalScrollBar() {
		return scroller.getVerticalScrollBar();
	}

	/**
	 * Returns the FormatManager used by this listing panel.
	 * 
	 * @return the format manager
	 */
	public FormatManager getFormatManager() {
		return formatManager;
	}

	public Layout getLayout(Address addr) {
		return layoutModel.getLayout(addr);
	}

	public void addHoverService(ListingHoverService hoverService) {
		listingHoverHandler.addHoverService(hoverService);
	}

	public void removeHoverService(ListingHoverService hoverService) {
		listingHoverHandler.removeHoverService(hoverService);
	}

	public void setHoverMode(boolean enabled) {
		listingHoverHandler.setHoverEnabled(enabled);
		if (enabled) {
			fieldPanel.setHoverProvider(listingHoverHandler);
		}
		else {
			fieldPanel.setHoverProvider(null);
		}
	}

	public boolean isHoverShowing() {
		return listingHoverHandler.isShowing();
	}

	public Program getProgram() {
		if (listingModel != null) {
			return listingModel.getProgram();
		}
		return null;
	}

	/**
	 * Returns the current program selection.
	 * 
	 * @return the selection
	 */
	public ProgramSelection getProgramSelection() {
		return layoutModel.getProgramSelection(fieldPanel.getSelection());
	}

	public ProgramSelection getProgramSelection(FieldSelection fieldSelection) {
		return layoutModel.getProgramSelection(fieldSelection);
	}

	/**
	 * Sets the selection to the entire listing view.
	 */
	public void selectAll() {
		fieldPanel.requestFocus();
		ProgramSelection sel = layoutModel.getAllProgramSelection();
		setSelection(sel);
	}

	/**
	 * Sets the selection to the complement of the current selection in the listing view.
	 * 
	 * @return the addresses
	 */
	public AddressSet selectComplement() {
		fieldPanel.requestFocus();
		AddressIndexMap addrIndexMap = layoutModel.getAddressIndexMap();
		AddressSetView viewSet = addrIndexMap.getOriginalAddressSet();
		AddressSetView selectionSet = addrIndexMap.getAddressSet(fieldPanel.getSelection());
		AddressSet complementSet = viewSet.subtract(selectionSet);
		fieldPanel.setSelection(addrIndexMap.getFieldSelection(complementSet));
		return complementSet;
	}

	/**
	 * Sets the selection.
	 *
	 * @param sel the new selection
	 */
	public void setSelection(ProgramSelection sel) {
		setSelection(sel, EventTrigger.API_CALL);
	}

	/**
	 * Sets the selection.
	 *
	 * @param sel the new selection
	 * @param trigger the cause of the change
	 */
	public void setSelection(ProgramSelection sel, EventTrigger trigger) {

		Program program = getProgram();
		MarkerSet markers = getSelectionMarkers(program);

		if (sel == null) {
			fieldPanel.setSelection(layoutModel.getFieldSelection(null), trigger);

			if (markers != null) {
				markers.clearAll();
			}
			return;
		}

		InteriorSelection interior = sel.getInteriorSelection();
		if (interior != null) {
			FieldLocation loc1 = layoutModel.getFieldLocation(interior.getFrom());
			FieldLocation loc2 = layoutModel.getFieldLocation(interior.getTo());
			if (loc1 != null && loc2 != null) {
				FieldSelection fieldSel = new FieldSelection();
				int fieldNum1 = -1;
				Layout layout = layoutModel.getLayout(loc1.getIndex());
				if (layout != null) {
					fieldNum1 = layout.getBeginRowFieldNum(loc1.getFieldNum());
				}

				Layout layout2 = layoutModel.getLayout(loc2.getIndex());

				if (fieldNum1 >= 0 && layout2 != null) {
					BigInteger index2 = loc2.getIndex();
					int fieldNum2 = layout.getEndRowFieldNum(loc2.getFieldNum());
					if (fieldNum2 >= layout2.getNumFields()) {
						index2 = loc2.getIndex().add(BigInteger.ONE);
						fieldNum2 = 0;
					}
					fieldSel.addRange(new FieldLocation(loc1.getIndex(), fieldNum1, 0, 0),
						new FieldLocation(index2, fieldNum2, 0, 0));
					fieldPanel.setSelection(fieldSel, trigger);
					return;
				}
			}
		}
		fieldPanel.setSelection(layoutModel.getFieldSelection(sel), trigger);

		if (markers != null) {
			markers.clearAll();
			markers.add(sel);
		}
	}

	/**
	 * Sets the highlight.
	 *
	 * @param highlight the new highlight.
	 */
	public void setHighlight(ProgramSelection highlight) {
		fieldPanel.setHighlight(layoutModel.getFieldSelection(highlight));

		Program program = getProgram();
		MarkerSet markers = getHighlightMarkers(program);
		if (markers == null) {
			return;
		}

		markers.clearAll();

		if (highlight != null && program != null) {
			markers.setAddressSet(highlight);
		}

	}

	public ProgramSelection getProgramHighlight() {
		return layoutModel.getProgramSelection(fieldPanel.getHighlight());
	}

	@Override
	public void selectionChanged(FieldSelection selection, EventTrigger trigger) {
		if (listingModel == null) {
			// Dragging in a popup window that contains a listing while that window
			// closes can trigger this condition
			return;
		}

		String text = FieldSelectionHelper.getFieldSelectionText(selection, fieldPanel);
		if (stringSelectionListener != null) {
			stringSelectionListener.setStringSelection(text);
		}

		currentTextSelection = text;
		if (text != null) {
			return;
		}

		if (listingModel.getProgram() == null || programSelectionListener == null) {
			return;
		}
		ProgramSelection ps = layoutModel.getProgramSelection(selection);
		if (ps != null) {
			programSelectionListener.programSelectionChanged(ps, trigger);
		}
	}

	/**
	 * Returns the currently selected text.
	 * <p>
	 * The value will only be non-null for selections within a single field.
	 * 
	 * @return the selected text or null
	 */
	public String getTextSelection() {
		return currentTextSelection;
	}

	public void enablePropertyBasedColorModel(boolean b) {
		propertyBasedColorModel.setEnabled(b);
	}

	/**
	 * Sets listing panel to never show scroll bars.
	 * <p>
	 * This is useful when you want this listing's parent to always be as big as this listing.
	 */
	public void setNeverSroll() {
		scroller.setNeverScroll(true);
	}

	public void setFormatManager(FormatManager formatManager) {
		List<ListingHighlightProvider> highlightProviders =
			this.formatManager.getHighlightProviders();

		this.formatManager = formatManager;

		for (ListingHighlightProvider provider : highlightProviders) {
			this.formatManager.addHighlightProvider(provider);
		}

		if (headerPanel != null) {
			showHeader(false);
		}
		if (listingModel != null) {
			listingModel.setFormatManager(formatManager);
		}
		layoutModel.dataChanged(true);
	}

	public void addDisplayListener(AddressSetDisplayListener listener) {
		displayListeners.add(listener);
	}

	public void removeDisplayListener(AddressSetDisplayListener listener) {
		displayListeners.remove(listener);
	}

	@Override
	public synchronized void addFocusListener(FocusListener l) {
		// we are not focusable, defer to contained field panel
		fieldPanel.addFocusListener(l);
	}

	@Override
	public synchronized void removeFocusListener(FocusListener l) {
		// we are not focusable, defer to contained field panel
		fieldPanel.removeFocusListener(l);
	}

//==================================================================================================
// Markers
//==================================================================================================

	public void setUseMarkerNameSuffix(boolean b) {
		// Note: this happens just after construction, so no need to recreate the markers
		this.useMarkerNameSuffix = b;
	}

	public void setMarkerService(MarkerService markerService) {

		if (this.markerService != null) {
			this.markerService.removeChangeListener(markerChangeListener);
		}

		if (markerService != null) {
			markerService.addChangeListener(markerChangeListener);
		}
		else {
			doClearMarkers(getProgram());
		}

		this.markerService = markerService;
	}

	public void clearMarkers(Program program) {
		doClearMarkers(program);
	}

	private void doClearMarkers(Program program) {
		if (markerService == null) {
			return;
		}

		if (program == null) {
			return; // can happen during dispose after a programDeactivated()
		}

		if (selectionMarkers != null) {
			markerService.removeMarker(selectionMarkers, program);
			selectionMarkers = null;
		}

		if (highlightMarkers != null) {
			markerService.removeMarker(highlightMarkers, program);
			highlightMarkers = null;
		}

		if (cursorMarkers != null) {
			markerService.removeMarker(cursorMarkers, program);
			cursorMarkers = null;
		}
	}

	public void setSelectionColor(Color color) {

		fieldPanel.setSelectionColor(color);
		if (selectionMarkers != null) {
			selectionMarkers.setMarkerColor(color);
		}
	}

	public void setHighlightColor(Color color) {
		fieldPanel.setHighlightColor(color);
		if (highlightMarkers != null) {
			highlightMarkers.setMarkerColor(color);
		}
	}

	private String getMarkerName(String baseName) {
		if (useMarkerNameSuffix) {
			return baseName + ' ' + marginOwnerId.toString();
		}
		return baseName;
	}

	private MarkerSet getSelectionMarkers(Program program) {
		if (markerService == null || program == null) {
			return null;
		}

		// already created
		if (selectionMarkers != null) {
			return selectionMarkers;
		}

		String markerName = getMarkerName("Selection");
		Color color = fieldPanel.getSelectionColor();
		selectionMarkers = markerService.createAreaMarker(markerName, "Selection Display",
			program, MarkerService.SELECTION_PRIORITY, false, true, false, color);
		selectionMarkers.setOwnerId(marginOwnerId);

		return selectionMarkers;
	}

	private MarkerSet getHighlightMarkers(Program program) {
		if (markerService == null || program == null) {
			return null;
		}

		// already created
		if (highlightMarkers != null) {
			return highlightMarkers;
		}

		String markerName = getMarkerName("Highlight");
		Color color = fieldPanel.getHighlightColor();
		highlightMarkers = markerService.createAreaMarker(markerName, "Highlight Display ",
			program, MarkerService.HIGHLIGHT_PRIORITY, false, true, false, color);
		highlightMarkers.setOwnerId(marginOwnerId);

		return highlightMarkers;
	}

	private MarkerSet getCursorMarkers(Program program) {
		if (markerService == null || program == null) {
			return null;
		}

		// already created
		if (cursorMarkers != null) {
			return cursorMarkers;
		}

		String markerName = getMarkerName("Cursor");
		cursorMarkers = markerService.createPointMarker(markerName, "Cursor Location",
			program, MarkerService.CURSOR_PRIORITY, true, true, isHighlightCursorLineEnabled,
			cursorLineHighlightColor, CURSOR_LOC_ICON);
		cursorMarkers.setOwnerId(marginOwnerId);

		return cursorMarkers;
	}

	public void setCursorHighlightColor(Color cursorHighlightColor) {
		this.cursorLineHighlightColor = cursorHighlightColor;
		if (cursorMarkers != null) {
			cursorMarkers.setMarkerColor(cursorHighlightColor);
		}
	}

	public void setHighlightCursorLineEnabled(boolean b) {
		this.isHighlightCursorLineEnabled = b;
		if (cursorMarkers != null) {
			cursorMarkers.setColoringBackground(b);
		}
	}

	public void setCursorMarkerAddress(Address address) {
		MarkerSet markers = getCursorMarkers(getProgram());
		if (markers != null) {
			markers.clearAll();
			markers.add(address);
		}
	}

	public void updateBackgroundColorModel() {
		if (markerService == null) {
			setBackgroundColorModel(null);
		}
		else {
			AddressIndexMap indexMap = getAddressIndexMap();
			setBackgroundColorModel(
				new MarkerServiceBackgroundColorModel(markerService, indexMap));
		}
	}
//==================================================================================================
// End Markers
//==================================================================================================

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class MarkerChangeListener implements ChangeListener {

		@Override
		public void stateChanged(ChangeEvent e) {
			fieldPanel.repaint();
		}
	}

	private class FocusingMouseListener extends MouseAdapter {
		@Override
		public void mousePressed(MouseEvent e) {
			fieldPanel.requestFocus();
		}
	}
}
