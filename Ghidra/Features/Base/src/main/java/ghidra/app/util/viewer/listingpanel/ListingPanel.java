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
import java.util.Arrays;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ChangeListener;

import docking.action.DockingActionIf;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.*;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.listener.*;
import docking.widgets.fieldpanel.support.*;
import docking.widgets.indexedscrollpane.IndexedScrollPane;
import ghidra.app.plugin.core.codebrowser.LayeredColorModel;
import ghidra.app.plugin.core.codebrowser.hover.ListingHoverService;
import ghidra.app.services.ButtonPressedListener;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.app.util.viewer.field.ListingField;
import ghidra.app.util.viewer.format.FieldHeader;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.util.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.layout.HorizontalLayout;

public class ListingPanel extends JPanel implements FieldMouseListener, FieldLocationListener,
		FieldSelectionListener, LayoutListener {

	public static final int DEFAULT_DIVIDER_LOCATION = 70;

	private FormatManager formatManager;
	private ListingModelAdapter layoutModel;

	private FieldPanel fieldPanel;
	private IndexedScrollPane scroller;
	private JSplitPane splitPane;
	private int splitPaneDividerLocation = DEFAULT_DIVIDER_LOCATION;

	private ProgramLocationListener programLocationListener;
	private ProgramSelectionListener programSelectionListener;
	private StringSelectionListener stringSelectionListener;

	private ListingModel listingModel;
	private FieldHeader headerPanel;
	private ButtonPressedListener[] buttonListeners = new ButtonPressedListener[0];
	private List<ChangeListener> indexMapChangeListeners = new ArrayList<>();

	private ListingHoverProvider listingHoverHandler;

	private List<MarginProvider> marginProviders = new ArrayList<>();
	private List<OverviewProvider> overviewProviders = new ArrayList<>();
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
	private List<ListingDisplayListener> displayListeners = new ArrayList<>();

	private String currentTextSelection;

	/**
	 * Constructs a new ListingPanel using the given FormatManager and ServiceProvider.
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
		fieldPanel.addLayoutListener(this);
		propertyBasedColorModel = new PropertyBasedBackgroundColorModel();
		fieldPanel.setBackgroundColorModel(propertyBasedColorModel);
		scroller = new IndexedScrollPane(fieldPanel);
		listingHoverHandler = new ListingHoverProvider();
		add(scroller, BorderLayout.CENTER);
		fieldPanel.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				for (MarginProvider provider : marginProviders) {
					provider.getComponent().invalidate();
				}
				validate();
			}
		});
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
	 * Constructs a new ListingPanel with the given FormatManager and ListingLayoutModel
	 * 
	 * @param mgr the FormatManager to use
	 * @param model the ListingLayoutModel to use.
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

	/** A width for new windows that shows a reasonable amount of the Listing */
	protected int getNewWindowDefaultWidth() {
		return 500;
	}

	// extension point
	protected FieldPanel createFieldPanel(LayoutModel model) {
		return new FieldPanel(model);
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
	 * Sets the ProgramLocationListener. Only one listener is supported
	 * 
	 * @param listener the ProgramLocationListener to use.
	 */
	public void setProgramLocationListener(ProgramLocationListener listener) {
		this.programLocationListener = listener;
	}

	/**
	 * Sets the ProgramSelectionListener. Only one listener is supported
	 * 
	 * @param listener the ProgramSelectionListener to use.
	 */
	public void setProgramSelectionListener(ProgramSelectionListener listener) {
		programSelectionListener = listener;
	}

	public void setStringSelectionListener(StringSelectionListener listener) {
		stringSelectionListener = listener;
	}

	/**
	 * Sets the ListingLayoutModel to use.
	 * 
	 * @param newModel the model to use.
	 */
	public void setListingModel(ListingModel newModel) {
		layoutModel.dispose();
		listingModel = newModel;
		layoutModel = createLayoutModel(newModel);
		fieldPanel.setLayoutModel(layoutModel);
		SwingUtilities.invokeLater(() -> updateProviders());
	}

	/**
	 * Returns the current ListingModel used by this panel.
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
			ListingField currentField = (ListingField) fieldPanel.getCurrentField();
			if (currentField != null) {
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
	 */
	public boolean isHeaderShowing() {
		return headerPanel != null;
	}

	private void updateProviders() {
		AddressIndexMap addressIndexMap = layoutModel.getAddressIndexMap();
		for (OverviewProvider element : overviewProviders) {
			element.setAddressIndexMap(addressIndexMap);
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

	/**
	 * Adds the MarginProvider to this panel
	 * 
	 * @param provider the MarginProvider that will provide components to display in this panel's
	 *            left margin area.
	 */
	public void addMarginProvider(MarginProvider provider) {
		if (provider.isResizeable()) {
			marginProviders.add(0, provider);
		}
		else {
			marginProviders.add(provider);
		}
		provider.setPixelMap(pixmap);
		buildPanels();
	}

	private void buildPanels() {
		removeAll();
		add(buildLeftComponent(), BorderLayout.WEST);
		add(buildCenterComponent(), BorderLayout.CENTER);
		JComponent overviewComponent = buildOverviewComponent();
		if (overviewComponent != null) {
			scroller.setScrollbarSideKickComponent(buildOverviewComponent());
		}
		repaint();
	}

	private JComponent buildOverviewComponent() {
		if (overviewProviders.isEmpty()) {
			return null;
		}
		JPanel rightPanel = new JPanel(new HorizontalLayout(0));
		for (OverviewProvider overviewProvider : overviewProviders) {
			rightPanel.add(overviewProvider.getComponent());
		}
		return rightPanel;
	}

	private JComponent buildLeftComponent() {
		List<MarginProvider> marginProviderList = getNonResizeableMarginProviders();
		JPanel leftPanel = new JPanel(new ScrollpaneAlignedHorizontalLayout(scroller));
		for (MarginProvider marginProvider : marginProviderList) {
			leftPanel.add(marginProvider.getComponent());
		}
		return leftPanel;
	}

	private List<MarginProvider> getNonResizeableMarginProviders() {
		if (marginProviders.isEmpty()) {
			return marginProviders;
		}
		MarginProvider firstMarginProvider = marginProviders.get(0);
		if (firstMarginProvider.isResizeable()) {
			return marginProviders.subList(1, marginProviders.size());
		}
		return marginProviders;
	}

	private JComponent buildCenterComponent() {
		JComponent centerComponent = scroller;
		MarginProvider resizeableMarginProvider = getResizeableMarginProvider();
		if (resizeableMarginProvider != null) {
			if (splitPane != null) {
				splitPaneDividerLocation = splitPane.getDividerLocation();
			}
			JPanel resizeablePanel = new JPanel(new ScrollpanelResizeablePanelLayout(scroller));
			resizeablePanel.setBackground(Color.WHITE);
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

	private MarginProvider getResizeableMarginProvider() {
		if (marginProviders.isEmpty()) {
			return null;
		}
		MarginProvider marginProvider = marginProviders.get(0);
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
	 * Removes the given margin provider from this panel
	 * 
	 * @param provider the MarginProvider to remove.
	 */
	public void removeMarginProvider(MarginProvider provider) {
		marginProviders.remove(provider);
		buildPanels();
	}

	/**
	 * Adds the given OverviewProvider with will be displayed in this panels right margin area.
	 * 
	 * @param provider the OverviewProvider to display.
	 */
	public void addOverviewProvider(OverviewProvider provider) {
		overviewProviders.add(provider);
		provider.setAddressIndexMap(layoutModel.getAddressIndexMap());
		buildPanels();
	}

	/**
	 * Removes the given OverviewProvider from this panel
	 * 
	 * @param provider the OverviewProvider to remove.
	 */
	public void removeOverviewProvider(OverviewProvider provider) {
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
		List<ButtonPressedListener> list = new ArrayList<>(Arrays.asList(buttonListeners));
		list.add(listener);
		buttonListeners = list.toArray(new ButtonPressedListener[list.size()]);
	}

	/**
	 * Removes the given ButtonPressedListener.
	 * 
	 * @param listener the ButtonPressedListener to remove.
	 */
	public void removeButtonPressedListener(ButtonPressedListener listener) {
		List<ButtonPressedListener> list = new ArrayList<>(Arrays.asList(buttonListeners));
		list.remove(listener);
		buttonListeners = list.toArray(new ButtonPressedListener[list.size()]);
	}

	/**
	 * Removes the given {@link HighlightProvider} from this listing.
	 *
	 * @param highlightProvider The provider to remove.
	 * @see #addHighlightProvider(HighlightProvider)
	 */
	public void removeHighlightProvider(HighlightProvider highlightProvider) {
		formatManager.removeHighlightProvider(highlightProvider);
	}

	/**
	 * Adds a {@link HighlightProvider} to this listing. This highlight provider will be used with
	 * any other registered providers to paint all the highlights for this listing.
	 *
	 * @param highlightProvider The provider to add
	 */
	public void addHighlightProvider(HighlightProvider highlightProvider) {
		formatManager.addHighlightProvider(highlightProvider);
	}

	/**
	 * Returns the FieldPanel used by this ListingPanel.
	 */
	public FieldPanel getFieldPanel() {
		return fieldPanel;
	}

	@Override
	public void layoutsChanged(List<AnchoredLayout> layouts) {
		this.pixmap = new VerticalPixelAddressMapImpl(layouts, layoutModel.getAddressIndexMap());
		for (MarginProvider element : marginProviders) {
			element.setPixelMap(pixmap);
		}

		for (ListingDisplayListener listener : displayListeners) {
			notifyDisplayListener(listener);
		}
	}

	private void notifyDisplayListener(ListingDisplayListener listener) {
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

		removeAll();
		listingHoverHandler.dispose();
		layoutModel.dispose();
		layoutModel = createLayoutModel(null);
		layoutModel.dispose();
		buttonListeners = null;

		fieldPanel.dispose();
	}

	/**
	 * Moves the cursor to the given program location and repositions the scrollbar to show that
	 * location in the screen.
	 * 
	 * @param loc the location to move to.
	 */
	public boolean goTo(ProgramLocation loc) {
		return goTo(loc, true);
	}

	/**
	 * Moves the cursor to the given program location. Also, repositions the scrollbar to show that
	 * location, if the location is not on the screen.
	 *
	 * @param loc the location to move to.
	 * @param centerWhenNotVisible this variable only has an effect if the given location is not on
	 *            the screen. In that case, when this parameter is true, then the given location
	 *            will be placed in the center of the screen; when the parameter is false, then the
	 *            screen will be scrolled only enough to show the cursor.
	 */
	public boolean goTo(ProgramLocation loc, boolean centerWhenNotVisible) {
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

	/** Scroll the view of the listing to the given location. */
	public void scrollTo(ProgramLocation location) {
		FieldLocation fieldLocation = getFieldLocation(location);
		fieldPanel.scrollTo(fieldLocation);
	}

	/** Center the view of the listing around the given location. */
	public void center(ProgramLocation location) {
		FieldLocation fieldLocation = getFieldLocation(location);
		fieldPanel.center(fieldLocation);
	}

	private FieldLocation getFieldLocation(ProgramLocation loc) {
		Program program = getProgram();
		if (program == null) {
			return null;
		}

		openDataAsNeeded(loc);

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
			if (compatibleLocation == null) {
				return null;
			}
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

	private void openDataAsNeeded(ProgramLocation location) {
		Address address = location.getByteAddress();
		Program program = getProgram();
		CodeUnit cu = program.getListing().getCodeUnitContaining(address);
		if (!(cu instanceof Data)) {
			return;
		}

		Data data = (Data) cu;
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
		if (fieldLocation == null || field == null) {
			return;
		}

		ListingField listingField = (ListingField) field;
		ProgramLocation programLocation = layoutModel.getProgramLocation(fieldLocation, field);
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
		ListingField lf = (ListingField) field;
		if (lf == null) {
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

		if (programLocationListener != null) {
			ProgramLocation pLoc = layoutModel.getProgramLocation(location, field);
			if (pLoc != null) {
				programLocationListener.programLocationChanged(pLoc, trigger);
			}
		}
	}

	/**
	 * Restricts the program's view to the given address set
	 * 
	 * @param view the set of address to include in the view.
	 */
	public void setView(AddressSetView view) {
		layoutModel.setAddressSet(view);
		updateProviders();
	}

	/**
	 * Gets the view of this listing panel (meant to be used in conjunction with
	 * {@link #setView(AddressSetView)}.
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
			layeredColorModel = new LayeredColorModel(colorModel, propertyBasedColorModel);
			fieldPanel.setBackgroundColorModel(layeredColorModel);
		}
	}

	/**
	 * Sets the background color for the listing panel. This will set the background for the main
	 * listing display.
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
	 */
	public boolean isActive() {
		return fieldPanel.isFocused();
	}

	/**
	 * Returns the current program location of the cursor.
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
	 * @return program location, or null if point does not correspond to a program location
	 */
	public ProgramLocation getProgramLocation(Point point) {
		FieldLocation dropLoc = new FieldLocation();
		ListingField field = (ListingField) fieldPanel.getFieldAt(point.x, point.y, dropLoc);
		if (field != null) {
			return field.getFieldFactory()
					.getProgramLocation(dropLoc.getRow(), dropLoc.getCol(), field);
		}
		return null;
	}

	/**
	 * Get the margin providers in this ListingPanel.
	 */
	public List<MarginProvider> getMarginProviders() {
		return marginProviders;
	}

	/**
	 * Get the overview providers in this ListingPanel.
	 */
	public List<OverviewProvider> getOverviewProviders() {
		return overviewProviders;
	}

	/**
	 * Returns true if the mouse is at a location that can be dragged.
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
	 * 
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
	 */
	public AddressIndexMap getAddressIndexMap() {
		return layoutModel.getAddressIndexMap();
	}

	/**
	 * Returns the vertical scrollbar used by this panel.
	 */
	public JScrollBar getVerticalScrollBar() {
		return scroller.getVerticalScrollBar();
	}

	/**
	 * Returns the FormatManager used by this listing panel.
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
		if (sel == null) {
			fieldPanel.setSelection(layoutModel.getFieldSelection(null));
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
				BigInteger index2 = null;
				if (layout2 != null) {
					index2 = loc2.getIndex().add(BigInteger.valueOf(layout2.getIndexSize()));
				}
				if (fieldNum1 >= 0 && index2 != null) {
					fieldSel.addRange(new FieldLocation(loc1.getIndex(), fieldNum1, 0, 0),
						new FieldLocation(index2, 0, 0, 0));
					fieldPanel.setSelection(fieldSel);
					return;
				}
			}
		}
		fieldPanel.setSelection(layoutModel.getFieldSelection(sel));
	}

	/**
	 * Sets the highlight.
	 * 
	 * @param highlight the new highlight.
	 */
	public void setHighlight(ProgramSelection highlight) {
		fieldPanel.setHighlight(layoutModel.getFieldSelection(highlight));
	}

	public ProgramSelection getProgramHighlight() {
		return layoutModel.getProgramSelection(fieldPanel.getHighlight());
	}

	@Override
	public void selectionChanged(FieldSelection selection, EventTrigger trigger) {
		if (listingModel == null) {
			// SCR 7092 - Dragging in a popup window that contains a listing while that window
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

		if (trigger != EventTrigger.API_CALL) {
			if (listingModel.getProgram() == null || programSelectionListener == null) {
				return;
			}
			ProgramSelection ps = layoutModel.getProgramSelection(selection);
			if (ps != null) {
				programSelectionListener.programSelectionChanged(ps);
			}
		}
	}

	/**
	 * Returns the currently selected text.   The value will only be non-null for selections within
	 * a single field. 
	 * @return the selected text or null
	 */
	public String getTextSelection() {
		return currentTextSelection;
	}

	public void enablePropertyBasedColorModel(boolean b) {
		propertyBasedColorModel.setEnabled(b);
	}

	/**
	 * Sets listing panel to never show scroll bars. This is useful when you want this listing's
	 * parent to always be as big as this listing.
	 */
	public void setNeverSroll() {
		scroller.setNeverScroll(true);
	}

	public void setFormatManager(FormatManager formatManager) {
		List<HighlightProvider> highlightProviders = this.formatManager.getHighlightProviders();

		this.formatManager = formatManager;

		for (HighlightProvider provider : highlightProviders) {
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

	public void addListingDisplayListener(ListingDisplayListener listener) {
		displayListeners.add(listener);
	}

	public void removeListingDisplayListener(ListingDisplayListener listener) {
		displayListeners.remove(listener);
	}
}
