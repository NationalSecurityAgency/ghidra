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

import java.awt.Component;
import java.awt.Point;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.*;
import java.awt.event.MouseEvent;
import java.util.*;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.*;
import docking.action.*;
import docking.actions.PopupActionProvider;
import docking.dnd.*;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.HoverHandler;
import docking.widgets.fieldpanel.internal.FieldPanelCoordinator;
import docking.widgets.fieldpanel.support.*;
import ghidra.app.nav.*;
import ghidra.app.plugin.core.clipboard.CodeBrowserClipboardProvider;
import ghidra.app.plugin.core.codebrowser.actions.*;
import ghidra.app.plugin.core.codebrowser.hover.ListingHoverService;
import ghidra.app.services.*;
import ghidra.app.util.*;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.app.util.viewer.format.*;
import ghidra.app.util.viewer.listingpanel.*;
import ghidra.app.util.viewer.multilisting.MultiListingLayoutModel;
import ghidra.app.util.viewer.util.FieldNavigator;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.NavigatableComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;
import resources.ResourceManager;

public class CodeViewerProvider extends NavigatableComponentProviderAdapter
		implements ProgramLocationListener, ProgramSelectionListener, Draggable, Droppable,
		ChangeListener, StringSelectionListener, PopupActionProvider {

	private static final String OLD_NAME = "CodeBrowserPlugin";
	private static final String NAME = "Listing";
	private static final String TITLE = NAME + ": ";

	private static final Icon LISTING_FORMAT_EXPAND_ICON =
		ResourceManager.loadImage("images/field.header.down.png");
	private static final Icon LISTING_FORMAT_COLLAPSE_ICON =
		ResourceManager.loadImage("images/field.header.up.png");

	private static final Icon HOVER_ON_ICON = ResourceManager.loadImage("images/hoverOn.gif");
	private static final Icon HOVER_OFF_ICON = ResourceManager.loadImage("images/hoverOff.gif");
	private static final String HOVER_MODE = "Hover Mode";

	private static final String DIVIDER_LOCATION = "DividerLocation";

	private ImageIcon navigatableIcon;
	private Map<Program, HighlightProvider> programHighlighterMap = new HashMap<>();
	private ProgramHighlighterProvider highlighterAdapter;

	private ListingPanel listingPanel;
	private CodeBrowserPluginInterface plugin;
	private Program program;
	private DragSource dragSource;
	private DragGestureAdapter dragGestureAdapter;
	private DragSrcAdapter dragSourceAdapter;
	private int dragAction = DnDConstants.ACTION_MOVE;
	private DropTgtAdapter dropTargetAdapter;
	private DataFlavor[] acceptableFlavors = new DataFlavor[0];
	private ProgramDropProvider[] dropProviders = new ProgramDropProvider[0];
	private ProgramDropProvider curDropProvider;
	private ToggleDockingAction toggleHoverAction;

	private ProgramLocation currentLocation;

	private ListingPanel otherPanel;
	private CoordinatedListingPanelListener coordinatedListingPanelListener;
	private FormatManager formatMgr;
	private FieldPanelCoordinator coordinator;

	private CodeBrowserClipboardProvider codeViewerClipboardProvider;
	private ClipboardService clipboardService;

	private ListingPanelContainer decorationPanel;

	private CloneCodeViewerAction cloneCodeViewerAction;

	private ProgramSelection currentSelection;
	private ProgramSelection currentHighlight;
	private String currentStringSelection;

	private FieldNavigator fieldNavigator;

	private MultiListingLayoutModel multiModel;

	public CodeViewerProvider(CodeBrowserPluginInterface plugin, FormatManager formatMgr,
			boolean isConnected) {
		super(plugin.getTool(), NAME, plugin.getName(), CodeViewerActionContext.class);

		this.plugin = plugin;
		this.formatMgr = formatMgr;

		// note: the owner has not changed, just the name; remove sometime after version 10
		String owner = plugin.getName();
		ComponentProvider.registerProviderNameOwnerChange(OLD_NAME, owner, NAME, owner);

		setConnected(isConnected);
		setIcon(ResourceManager.loadImage("images/Browser.gif"));
		if (!isConnected) {
			setTransient();
		}
		else {
			addToToolbar();
		}
		setHelpLocation(new HelpLocation("CodeBrowserPlugin", "Code_Browser"));
		setDefaultWindowPosition(WindowPosition.RIGHT);

		listingPanel = new ListingPanel(formatMgr);
		listingPanel.enablePropertyBasedColorModel(true);
		decorationPanel = new ListingPanelContainer(listingPanel, isConnected);
		ListingHighlightProvider listingHighlighter =
			createListingHighlighter(listingPanel, tool, decorationPanel);
		highlighterAdapter = new ProgramHighlighterProvider(listingHighlighter);
		listingPanel.addHighlightProvider(highlighterAdapter);

		setWindowMenuGroup("Listing");
		setIntraGroupPosition(WindowPosition.RIGHT);

		setTitle(isConnected ? TITLE : "[" + TITLE + "]");
		fieldNavigator = new FieldNavigator(tool, this);
		listingPanel.addButtonPressedListener(fieldNavigator);
		addToTool();
		createActions();
		listingPanel.setProgramLocationListener(this);
		listingPanel.setProgramSelectionListener(this);
		listingPanel.setStringSelectionListener(this);
		listingPanel.addIndexMapChangeListener(this);

		codeViewerClipboardProvider = new CodeBrowserClipboardProvider(tool, this);
		tool.addPopupActionProvider(this);
	}

	@Override
	public boolean isSnapshot() {
		// we are a snapshot when we are 'disconnected' 
		return !isConnected();
	}

	/**
	 * @return true if this listing is backed by a dynamic data source (e.g., debugger)
	 */
	public boolean isDynamicListing() {
		return false;
	}

	private ListingHighlightProvider createListingHighlighter(ListingPanel panel,
			PluginTool pluginTool, Component repaintComponent) {
		ListingHighlightProvider listingHighlighter =
			new ListingHighlightProvider(pluginTool, repaintComponent);
		panel.addButtonPressedListener(listingHighlighter);
		return listingHighlighter;
	}

	public void setClipboardService(ClipboardService service) {
		clipboardService = service;
		if (clipboardService != null) {
			clipboardService.registerClipboardContentProvider(codeViewerClipboardProvider);
		}
	}

	@Override
	public String getWindowGroup() {
		if (isConnected()) {
			return "Core"; // this lets other components place themselves around us
		}
		return "Core.disconnected";
	}

	@Override
	public WindowPosition getIntraGroupPosition() {
		if (isConnected()) {
			return WindowPosition.TOP;
		}

		// disconnected/snapshot providers should go to the right
		return WindowPosition.RIGHT;
	}

	@Override
	public void closeComponent() {
		if (!isConnected()) {
			plugin.providerClosed(this);
			return;
		}
		boolean closedListing = false;
		// If a second listing panel is showing then this should close it.
		// Otherwise just hide this provider.
		if (otherPanel != null && coordinatedListingPanelListener != null) {
			closedListing = coordinatedListingPanelListener.listingClosed();
		}
		if (!closedListing) {
			tool.showComponentProvider(this, false);
		}
	}

	@Override
	public void dispose() {
		super.dispose();

		tool.removePopupActionProvider(this);

		if (clipboardService != null) {
			clipboardService.deRegisterClipboardContentProvider(codeViewerClipboardProvider);
		}

		listingPanel.dispose();
		program = null;
		currentLocation = null;
		currentSelection = null;
		currentHighlight = null;
	}

	@Override
	public JComponent getComponent() {
		return decorationPanel;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (program == null) {
			return null;
		}

		if (event == null) {
			return new CodeViewerActionContext(this);
		}

		Object source = event.getSource();
		if (source == null || source == listingPanel.getFieldPanel()) {
			Point point = event.getPoint();
			ProgramLocation programLocation = listingPanel.getProgramLocation(point);
			if (programLocation == null) {
				return null;
			}
			return new CodeViewerActionContext(this);
		}

		FieldHeader headerPanel = listingPanel.getFieldHeader();
		if (headerPanel != null && source instanceof FieldHeaderComp) {
			FieldHeaderLocation fhLoc = headerPanel.getFieldHeaderLocation(event.getPoint());
			return createContext(fhLoc);
		}

		if (otherPanel != null && otherPanel.isAncestorOf((Component) source)) {
			Object obj = getContextForMarginPanels(otherPanel, event);
			if (obj != null) {
				return createContext(obj);
			}
			return new OtherPanelContext(this, program);
		}
		return createContext(getContextForMarginPanels(listingPanel, event));
	}

	private Object getContextForMarginPanels(ListingPanel lp, MouseEvent event) {
		Object source = event.getSource();
		List<MarginProvider> marginProviders = lp.getMarginProviders();
		for (MarginProvider marginProvider : marginProviders) {
			JComponent c = marginProvider.getComponent();
			if (c == source) {
				MarkerLocation loc = marginProvider.getMarkerLocation(event.getX(), event.getY());
				if (loc != null) {
					if (lp == listingPanel) {
						return loc;
					}
					return source;
				}
			}
		}
		List<OverviewProvider> overviewProviders = lp.getOverviewProviders();
		for (OverviewProvider overviewProvider : overviewProviders) {
			JComponent c = overviewProvider.getComponent();
			if (c == source) {
				return source;
			}
		}
		return null;
	}

	@Override
	public void dragCanceled(DragSourceDropEvent event) {
		// nothing to do
	}

	@Override
	public int getDragAction() {
		return dragAction;
	}

	@Override
	public DragSourceListener getDragSourceListener() {
		return dragSourceAdapter;
	}

	@Override
	public Transferable getTransferable(Point p) {
		ProgramSelection ps = listingPanel.getProgramSelection();
		return new SelectionTransferable(
			new SelectionTransferData(ps, program.getDomainFile().getPathname()));
	}

	@Override
	public boolean isStartDragOk(DragGestureEvent e) {
		if (program == null) {
			return false;
		}
		return listingPanel.isStartDragOk();
	}

	@Override
	public void move() {
		// nothing to do
	}

	@Override
	public void add(Object obj, DropTargetDropEvent event, DataFlavor f) {
		Point p = event.getLocation();
		ProgramLocation loc = listingPanel.getProgramLocation(p);
		CodeViewerActionContext context = new CodeViewerActionContext(this, loc);
		if (loc != null && curDropProvider != null) {
			curDropProvider.add(context, obj, f);
		}
	}

	@Override
	public void dragUnderFeedback(boolean ok, DropTargetDragEvent e) {
		// nothing to do
	}

	@Override
	public boolean isDropOk(DropTargetDragEvent e) {
		curDropProvider = null;

		Point p = e.getLocation();
		ProgramLocation loc = listingPanel.getProgramLocation(p);
		if (loc == null) {
			return false;
		}

		CodeViewerActionContext context = new CodeViewerActionContext(this, loc);
		for (ProgramDropProvider dropProvider : dropProviders) {
			if (dropProvider.isDropOk(context, e)) {
				curDropProvider = dropProvider;
				return true;
			}
		}
		return false;
	}

	@Override
	public void removeHighlightProvider(HighlightProvider highlightProvider,
			Program highlightProgram) {
		programHighlighterMap.remove(highlightProgram);
		updateHighlightProvider();
	}

	@Override
	public void setHighlightProvider(HighlightProvider highlightProvider,
			Program highlightProgram) {
		programHighlighterMap.put(highlightProgram, highlightProvider);
		updateHighlightProvider();
	}

	public void updateHighlightProvider() {
		listingPanel.getFieldPanel().repaint();
		if (otherPanel != null) {
			otherPanel.getFieldPanel().repaint();
		}
	}

	@Override
	public void undoDragUnderFeedback() {
		// nothing to do
	}

	protected void doSetProgram(Program newProgram) {

		currentLocation = null;
		program = newProgram;

		updateTitle();

		listingPanel.setProgram(program);
		codeViewerClipboardProvider.setProgram(program);
		codeViewerClipboardProvider.setListingLayoutModel(listingPanel.getListingModel());
		if (coordinatedListingPanelListener != null) {
			coordinatedListingPanelListener.activeProgramChanged(newProgram);
		}
		contextChanged();
	}

	protected void updateTitle() {
		String subTitle = program == null ? "" : ' ' + program.getDomainFile().getName();
		String newTitle = TITLE + subTitle;
		if (!isConnected()) {
			newTitle = '[' + newTitle + ']';
		}
		setTitle(newTitle);
	}

	@Override
	public void stateChanged(ChangeEvent e) {
		codeViewerClipboardProvider.setListingLayoutModel(listingPanel.getListingModel());
	}

	private void createActions() {
		tool.addLocalAction(this, new ToggleHeaderAction());

		toggleHoverAction = new ToggleHoverAction();
		tool.addLocalAction(this, toggleHoverAction);

		tool.addLocalAction(this, new ExpandAllDataAction(this));
		tool.addLocalAction(this, new CollapseAllDataAction(this));
		tool.addLocalAction(this, new ToggleExpandCollapseDataAction(this));

		cloneCodeViewerAction = new CloneCodeViewerAction(getName(), this);
		addLocalAction(cloneCodeViewerAction);

		DockingAction action = new GotoPreviousFunctionAction(tool, plugin.getName());
		tool.addAction(action);

		action = new GotoNextFunctionAction(tool, plugin.getName());
		tool.addAction(action);

	}

	void fieldOptionChanged(String fieldName, Object newValue) {
		//TODO		if (name.startsWith(OPERAND_OPTIONS_PREFIX) && (newValue instanceof Boolean)) {
		//			for (int i = 0; i < toggleOperandMarkupActions.length; i++) {
		//				ToggleOperandMarkupAction action = toggleOperandMarkupActions[i];
		//				if (name.equals(action.getOptionName())) {
		//					boolean newState = ((Boolean)newValue).booleanValue();
		//					if (action.isSelected() != newState) {
		//						action.setSelected(newState);
		//					}
		//					break;
		//				}
		//			}
		//		}
	}

	public ListingPanel getListingPanel() {
		return listingPanel;
	}

	protected void addProgramDropProvider(ProgramDropProvider dndProvider) {
		List<ProgramDropProvider> list = new ArrayList<>(Arrays.asList(dropProviders));
		if (list.contains(dndProvider)) {
			return;
		}
		list.add(dndProvider);
		Collections.sort(list, (pdp1, pdp2) -> {
			int p1 = pdp1.getPriority();
			int p2 = pdp2.getPriority();
			return p2 - p1;
		});
		dropProviders = list.toArray(new ProgramDropProvider[list.size()]);
		if (dropTargetAdapter == null) {
			setUpDragDrop();
		}
		else {
			setAcceptableFlavors();
			dropTargetAdapter.setAcceptableDropFlavors(acceptableFlavors);
		}
	}

	@Override
	public void programLocationChanged(ProgramLocation loc, EventTrigger trigger) {
		if (plugin.isDisposed()) {
			return;
		}
		if (!loc.equals(currentLocation)) {
			codeViewerClipboardProvider.setLocation(loc);
			currentLocation = loc;
			plugin.locationChanged(this, loc);
			contextChanged();
		}
	}

	@Override
	public void programSelectionChanged(ProgramSelection selection) {
		doSetSelection(selection);
	}

	@Override
	public void setSelection(ProgramSelection selection) {
		if (selection == null) {
			selection = new ProgramSelection();
		}
		else {
			selection = adjustSelection(selection);
		}

		doSetSelection(selection);
	}

	private void doSetSelection(ProgramSelection selection) {

		currentSelection = selection;
		codeViewerClipboardProvider.setSelection(currentSelection);
		listingPanel.setSelection(currentSelection);
		plugin.selectionChanged(this, currentSelection);
		contextChanged();
		String selectionInfo = null;
		if (!selection.isEmpty()) {
			long n = selection.getNumAddresses();
			String nString = Long.toString(n);
			if (n == 1) {

				selectionInfo = "(1 address selected)";
			}
			else {
				selectionInfo = '(' + nString + " addresses selected)";
			}

		}
		setSubTitle(selectionInfo);
	}

	private ProgramSelection adjustSelection(ProgramSelection selection) {
		if (selection.isEmpty()) {
			return selection;
		}
		if (selection.getInteriorSelection() != null) {
			return selection;
		}
		if (program == null) {
			return selection;
		}

		AddressSet set = new AddressSet();
		AddressRangeIterator it = selection.getAddressRanges();
		while (it.hasNext()) {
			AddressRange range = it.next();
			Address min = getMinCodeUnitAddress(range.getMinAddress());
			Address max = getMaxCodeUnitAddress(range.getMaxAddress());
			if (min != null && max != null && min.compareTo(max) <= 0) {
				set.addRange(min, max);
			}
		}
		return new ProgramSelection(set);
	}

	private Address getMinCodeUnitAddress(Address address) {
		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitContaining(address);
		if (cu != null) {
			return cu.getMinAddress();
		}

		cu = listing.getCodeUnitAfter(address);
		if (cu != null) {
			return cu.getMinAddress();
		}
		return null;
	}

	private Address getMaxCodeUnitAddress(Address address) {
		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitContaining(address);
		if (cu != null) {
			return cu.getMaxAddress();
		}

		cu = listing.getCodeUnitBefore(address);
		if (cu != null) {
			return cu.getMaxAddress();
		}
		return null;
	}

	@Override
	public void setHighlight(ProgramSelection highlight) {
		if (highlight == null) {
			highlight = new ProgramSelection();
		}
		else {
			highlight = adjustSelection(highlight);
		}

		doSetHighlight(highlight);
	}

	@Override
	public boolean supportsHighlight() {
		return true;
	}

	private void doSetHighlight(ProgramSelection highlight) {
		listingPanel.setHighlight(highlight);
		currentHighlight = highlight;
		plugin.highlightChanged(this, highlight);
		contextChanged();
	}

	@Override
	public void setStringSelection(String string) {
		this.currentStringSelection = string;
		codeViewerClipboardProvider.setStringContent(string);
		contextChanged();
	}

	public String getStringSelection() {
		return codeViewerClipboardProvider.getStringContent();
	}

	// set up the drag stuff
	private void setUpDragDrop() {
		setUpDrop();

		// set up drag stuff
		dragSource = DragSource.getDefaultDragSource();
		dragGestureAdapter = new DragGestureAdapter(this);
		dragSourceAdapter = new DragSrcAdapter(this);
		dragSource.createDefaultDragGestureRecognizer(listingPanel.getFieldPanel(), dragAction,
			dragGestureAdapter);
	}

	private void setUpDrop() {

		setAcceptableFlavors();

		// set up drop stuff
		dropTargetAdapter =
			new DropTgtAdapter(this, DnDConstants.ACTION_COPY_OR_MOVE, acceptableFlavors);
		new DropTarget(listingPanel.getFieldPanel(), DnDConstants.ACTION_COPY_OR_MOVE,
			dropTargetAdapter, true);
	}

	private void setAcceptableFlavors() {
		Set<DataFlavor> flavors = new HashSet<>();
		for (ProgramDropProvider dropProvider : dropProviders) {
			DataFlavor[] dfs = dropProvider.getDataFlavors();
			for (DataFlavor df : dfs) {
				flavors.add(df);
			}
		}
		acceptableFlavors = new DataFlavor[flavors.size()];
		flavors.toArray(acceptableFlavors);
	}

	boolean setLocation(ProgramLocation location) {
		if (!listingPanel.goTo(location, true)) {
			ViewManagerService viewManager = plugin.getViewManager(this);
			if (viewManager != null) {
				AddressSetView newView = viewManager.addToView(location);
				listingPanel.setView(newView);
				if (!listingPanel.goTo(location, true)) {
					return false;
				}
				if (otherPanel != null) {
					otherPanel.setView(newView);
					otherPanel.goTo(location, true);
				}
			}
		}
		currentLocation = listingPanel.getProgramLocation();
		codeViewerClipboardProvider.setLocation(location);
		return true;
	}

	public void setPanel(ListingPanel lp) {
		Program myProgram = listingPanel.getListingModel().getProgram();
		Program otherProgram = lp.getListingModel().getProgram();
		String myName = "<EMPTY>";
		String otherName = myName;

		if (myProgram != null) {
			myName = myProgram.getDomainFile().toString();
		}
		if (otherProgram != null) {
			otherName = otherProgram.getDomainFile().toString();
		}
		if (otherPanel != null) {
			removeHoverServices(otherPanel);
		}
		otherPanel = lp;
		AddressSet viewAddrs =
			ProgramMemoryComparator.getCombinedAddresses(myProgram, otherProgram);
		decorationPanel.setOtherPanel(lp, myName, otherName);
		multiModel = new MultiListingLayoutModel(formatMgr,
			new Program[] { myProgram, otherProgram }, viewAddrs);
		ListingModel myAlignedModel = multiModel.getAlignedModel(0);
		ListingModel otherAlignedModel = multiModel.getAlignedModel(1);
		listingPanel.setListingModel(myAlignedModel);
		lp.setListingModel(otherAlignedModel);
		coordinator = new FieldPanelCoordinator(
			new FieldPanel[] { listingPanel.getFieldPanel(), lp.getFieldPanel() });
		addHoverServices(otherPanel);
		HoverHandler hoverHandler = listingPanel.getFieldPanel().getHoverHandler();
		otherPanel.setHoverMode(hoverHandler != null && hoverHandler.isEnabled());
	}

	public ListingPanel getOtherPanel() {
		return otherPanel;
	}

	public void clearPanel() {
		if (otherPanel != null) {
			removeHoverServices(otherPanel);
			programSelectionChanged(new ProgramSelection());
			FieldPanel fp = listingPanel.getFieldPanel();
			FieldLocation loc = fp.getCursorLocation();
			ViewerPosition vp = fp.getViewerPosition();

			listingPanel.setProgram(listingPanel.getProgram());
			coordinator.remove(otherPanel.getFieldPanel());
			coordinator.remove(listingPanel.getFieldPanel());
			coordinator = null;
			otherPanel = null;
			decorationPanel.clearOtherPanel();
			fp.setViewerPosition(vp.getIndex(), vp.getXOffset(), vp.getYOffset());
			fp.setCursorPosition(loc.getIndex(), loc.fieldNum, loc.row, loc.col);
			multiModel = null;
		}
	}

	private void addHoverServices(ListingPanel panel) {
		ListingHoverService[] hoverServices = tool.getServices(ListingHoverService.class);
		for (ListingHoverService hoverService : hoverServices) {
			panel.addHoverService(hoverService);
		}
	}

	private void removeHoverServices(ListingPanel panel) {
		ListingHoverService[] hoverServices = tool.getServices(ListingHoverService.class);
		for (ListingHoverService hoverService : hoverServices) {
			panel.removeHoverService(hoverService);
		}
	}

	public void setNorthComponent(JComponent comp) {
		decorationPanel.setNorthPanel(comp);
	}

	void saveState(SaveState saveState) {
		saveState.putInt(DIVIDER_LOCATION, getListingPanel().getDividerLocation());
		saveState.putBoolean(HOVER_MODE, toggleHoverAction.isSelected());
	}

	void readState(SaveState saveState) {
		getListingPanel().setDividerLocation(
			saveState.getInt(DIVIDER_LOCATION, ListingPanel.DEFAULT_DIVIDER_LOCATION));
		toggleHoverAction.setSelected(saveState.getBoolean(HOVER_MODE, true));
	}

	private void setHoverEnabled(boolean enabled) {
		getListingPanel().setHoverMode(enabled);
		if (otherPanel != null) {
			otherPanel.setHoverMode(enabled);
		}
	}

	public void setCoordinatedListingPanelListener(CoordinatedListingPanelListener listener) {
		this.coordinatedListingPanelListener = listener;
	}

	@Override
	public ProgramLocation getLocation() {
		if (otherPanel != null && otherPanel.getFieldPanel().isFocused()) {
			return otherPanel.getProgramLocation();
		}
		return currentLocation;
	}

	@Override
	public ProgramSelection getSelection() {
		if (otherPanel != null && otherPanel.getFieldPanel().isFocused()) {
			return otherPanel.getProgramSelection();
		}
		return currentSelection;
	}

	@Override
	public ProgramSelection getHighlight() {
		if (otherPanel != null && otherPanel.getFieldPanel().isFocused()) {
			return otherPanel.getProgramHighlight();
		}
		return currentHighlight;
	}

	@Override
	public String getTextSelection() {
		return currentStringSelection;
	}

	@Override
	public Icon getIcon() {
		if (isConnected()) {
			return super.getIcon();
		}

		if (navigatableIcon == null) {
			Icon primaryIcon = super.getIcon();
			navigatableIcon = NavigatableIconFactory.createSnapshotOverlayIcon(primaryIcon);
		}
		return navigatableIcon;
	}

	@Override
	public Icon getNavigatableIcon() {
		return getIcon();
	}

	@Override
	public Program getProgram() {
		return program;
	}

	@Override
	public LocationMemento getMemento() {
		int cursorOffset = listingPanel.getFieldPanel().getCursorOffset();
		return new CodeViewerLocationMemento(program, currentLocation, cursorOffset);
	}

	@Override
	public void setMemento(LocationMemento memento) {
		CodeViewerLocationMemento cvMemento = (CodeViewerLocationMemento) memento;
		int cursorOffset = cvMemento.getCursorOffset();
		listingPanel.getFieldPanel().positionCursor(cursorOffset);

	}

	@Override
	public boolean goTo(Program gotoProgram, ProgramLocation location) {
		if (gotoProgram != program) {
			if (!isConnected()) {
				tool.setStatusInfo("Program location not applicable for this provider!");
				return false;
			}
			ProgramManager programManagerService = tool.getService(ProgramManager.class);
			if (programManagerService != null) {
				programManagerService.setCurrentProgram(gotoProgram);
			}
		}
		setLocation(location);
		return true;
	}

	@Override
	public void requestFocus() {
		listingPanel.getFieldPanel().requestFocus();
	}

	@Override
	public void writeDataState(SaveState saveState) {
		super.writeDataState(saveState);
		writeLocationState(saveState);
	}

	private void writeLocationState(SaveState saveState) {
		if (currentLocation != null) {
			currentLocation.saveState(saveState);
		}
		ViewerPosition vp = listingPanel.getFieldPanel().getViewerPosition();
		saveState.putInt("INDEX", vp.getIndexAsInt());
		saveState.putInt("Y_OFFSET", vp.getYOffset());

	}

	@Override
	public void readDataState(SaveState saveState) {
		super.readDataState(saveState);
		readLocationState(saveState);
	}

	private void readLocationState(SaveState saveState) {
		int index = saveState.getInt("INDEX", 0);
		int yOffset = saveState.getInt("Y_OFFSET", 0);
		ViewerPosition vp = new ViewerPosition(index, 0, yOffset);
		listingPanel.getFieldPanel()
				.setViewerPosition(vp.getIndex(), vp.getXOffset(), vp.getYOffset());
		if (program != null) {
			currentLocation = ProgramLocation.getLocation(program, saveState);
			if (currentLocation != null) {
				setLocation(currentLocation);
			}
		}
	}

	public void cloneWindow() {
		final CodeViewerProvider newProvider = plugin.createNewDisconnectedProvider();
		final ViewerPosition vp = listingPanel.getFieldPanel().getViewerPosition();
		// invoke later to give the window manage a chance to create the new window
		// (its done in an invoke later)
		Swing.runLater(() -> {
			newProvider.doSetProgram(program);
			newProvider.listingPanel.getFieldPanel()
					.setViewerPosition(vp.getIndex(), vp.getXOffset(), vp.getYOffset());
			newProvider.setLocation(currentLocation);
		});
	}

	public void selectAll() {
		listingPanel.getFieldPanel().requestFocus();
		ProgramSelection sel = new ProgramSelection(program.getAddressFactory(),
			listingPanel.getAddressIndexMap().getOriginalAddressSet());
		doSetSelection(sel);
	}

	public void selectComplement() {
		AddressSet complement = listingPanel.selectComplement();
		ProgramSelection sel = new ProgramSelection(program.getAddressFactory(), complement);
		doSetSelection(sel);
	}

	protected FieldNavigator getFieldNavigator() {
		return fieldNavigator;
	}

	public void setView(AddressSetView view) {
		// If we are using a MultiListingLayoutModel then adjust the view address set.
		AddressSetView adjustedView = view;

		if (multiModel != null) {
			if ((program != null) && view.contains(new AddressSet(program.getMemory()))) {
				Program otherProgram = otherPanel.getProgram();
				adjustedView = ProgramMemoryComparator.getCombinedAddresses(program, otherProgram);
			}
			multiModel.setAddressSet(adjustedView);
		}

		listingPanel.setView(adjustedView);
		if (otherPanel != null) {
			// Convert the view addresses to ones compatible with the otherPanel's model.
			AddressSet compatibleAddressSet =
				DiffUtility.getCompatibleAddressSet(adjustedView, otherPanel.getProgram());
			otherPanel.setView(compatibleAddressSet);
		}
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool dt, ActionContext context) {
		if (context.getComponentProvider() == this) {
			return listingPanel.getHeaderActions(getName());
		}
		return null;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	class ToggleHeaderAction extends ToggleDockingAction {
		ToggleHeaderAction() {
			super("Toggle Header", plugin.getName());
			setEnabled(true);

			setToolBarData(new ToolBarData(LISTING_FORMAT_EXPAND_ICON, "zzz"));
			setDescription("Edit the Listing fields");
		}

		@Override
		public void actionPerformed(ActionContext context) {
			boolean show = !listingPanel.isHeaderShowing();
			listingPanel.showHeader(show);
			getToolBarData()
					.setIcon(show ? LISTING_FORMAT_COLLAPSE_ICON : LISTING_FORMAT_EXPAND_ICON);
		}
	}

	private class ToggleHoverAction extends ToggleDockingAction {
		ToggleHoverAction() {
			super("Toggle Mouse Hover Popups", CodeViewerProvider.this.getOwner());
			setEnabled(true);
			setToolBarData(new ToolBarData(HOVER_ON_ICON, "yyyz"));
			setSelected(true);

			setHelpLocation(new HelpLocation(HelpTopics.CODE_BROWSER, "Hover"));
			setHover(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			setHover(isSelected());
		}

		void setHover(boolean enabled) {
			getToolBarData().setIcon(enabled ? HOVER_ON_ICON : HOVER_OFF_ICON);
			setHoverEnabled(enabled);
		}
	}

	/**
	 * A class that allows clients to install transient highlighters while keeping the middle-mouse
	 * highlighting on at the same time.
	 */
	private class ProgramHighlighterProvider implements HighlightProvider {

		private final ListingHighlightProvider listingHighlighter;

		ProgramHighlighterProvider(ListingHighlightProvider listingHighlighter) {
			this.listingHighlighter = listingHighlighter;
		}

		@Override
		public Highlight[] getHighlights(String text, Object obj,
				Class<? extends FieldFactory> fieldFactoryClass, int cursorTextOffset) {

			List<Highlight> list = new ArrayList<>();
			HighlightProvider currentExternalHighligter = programHighlighterMap.get(program);
			if (currentExternalHighligter != null) {
				Highlight[] highlights = currentExternalHighligter.getHighlights(text, obj,
					fieldFactoryClass, cursorTextOffset);
				for (Highlight highlight : highlights) {
					list.add(highlight);
				}
			}

			// always call the listing highlighter last so the middle-mouse highlight will always
			// be on top of other highlights
			Highlight[] highlights =
				listingHighlighter.getHighlights(text, obj, fieldFactoryClass, cursorTextOffset);
			for (Highlight highlight : highlights) {
				list.add(highlight);
			}

			return list.toArray(new Highlight[list.size()]);
		}
	}

	/**
	 * Add the ListingDisplayListener to the listing panel
	 * 
	 * @param listener the listener to add
	 */
	public void addListingDisplayListener(ListingDisplayListener listener) {
		listingPanel.addListingDisplayListener(listener);
	}

	/**
	 * Remove the ListingDisplayListener from the listing panel
	 * 
	 * @param listener the listener to remove
	 */
	public void removeListingDisplayListener(ListingDisplayListener listener) {
		listingPanel.removeListingDisplayListener(listener);
	}
}
