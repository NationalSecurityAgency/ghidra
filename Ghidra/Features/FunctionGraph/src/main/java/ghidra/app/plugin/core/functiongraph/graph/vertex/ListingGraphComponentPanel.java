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
/**
 * 
 */
package ghidra.app.plugin.core.functiongraph.graph.vertex;

import java.awt.*;
import java.awt.event.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.border.BevelBorder;

import docking.ActionContext;
import docking.GenericHeader;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.BackgroundColorModel;
import docking.widgets.label.GDLabel;
import ghidra.app.plugin.core.codebrowser.hover.ListingHoverService;
import ghidra.app.plugin.core.functiongraph.FunctionGraphPlugin;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphOptions;
import ghidra.app.services.HoverService;
import ghidra.app.util.AddEditDialog;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.listingpanel.ListingHoverProvider;
import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.app.util.viewer.util.FieldNavigator;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.ServiceListener;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

public class ListingGraphComponentPanel extends AbstractGraphComponentPanel {

	private GenericHeader genericHeader;
	private FGVertexListingPanel listingPanel;
	private FieldPanel fieldPanel;
	private final PluginTool tool;

	private JComponent toolTipComponent;
	private FGVertexListingPanel previewListingPanel;
	private JLabel tooltipTitleLabel;

	private final Program program;
	private AddressSetView addressSet;
	private List<ListingHoverService> installedHoverServices = new ArrayList<>();

	// kept around for testing
	private DockingAction xrefsAction;
	private DockingAction minimizeViewModeAction;
	private DockingAction maximizeViewModeAction;
	private DockingAction groupAction;
	private DockingAction regroupAction;

	private Color userDefinedColor = null;
	private SetVertexMostRecentColorAction setVertexMostRecentAction;
	private Color defaultBackgroundColor;

	private ServiceListener serviceChangeListener = new ServiceListener() {
		@Override
		public void serviceAdded(Class<?> interfaceClass, Object service) {
			if (interfaceClass == HoverService.class) {
				adjustHoverListeners();
			}
		}

		@Override
		public void serviceRemoved(Class<?> interfaceClass, Object service) {
			if (interfaceClass == HoverService.class) {
				adjustHoverListeners();
			}
		}
	};

	ListingGraphComponentPanel(final FGVertex vertex, final FGController controller,
			PluginTool tool, Program program, AddressSetView addressSet) {
		super(controller, vertex);
		this.tool = tool;
		this.addressSet = addressSet;
		this.program = program;
		this.title = createTitle();

		setLayout(new BorderLayout());
		listingPanel = new FGVertexListingPanel(controller, controller.getMinimalFormatManager(),
			program, addressSet);
		listingPanel.addButtonPressedListener(
			new FieldNavigator(tool, controller.getNavigatable()));
		listingPanel.addButtonPressedListener(
			controller.getSharedHighlighterButtonPressedListener());
		listingPanel.setStringSelectionListener(controller.getSharedStringSelectionListener());

		fieldPanel = listingPanel.getFieldPanel();
		fieldPanel.setCursorOn(false);

		defaultBackgroundColor = listingPanel.getTextBackgroundColor();

		listingPanel.setListingHoverHandler(new ListingHoverAdapter());
		listingPanel.setHoverMode(true);

		tool.addServiceListener(serviceChangeListener);

		adjustHoverListeners();

		add(listingPanel, BorderLayout.CENTER);

		BevelBorder beveledBorder =
			(BevelBorder) BorderFactory.createBevelBorder(BevelBorder.RAISED,
				new Color(225, 225, 225), new Color(155, 155, 155), new Color(96, 96, 96),
				new Color(0, 0, 0));
		setBorder(beveledBorder);

		addKeyListener(new FieldPanelKeyListener());

		genericHeader = new GenericHeader() {
			// overridden to prevent excessive title bar width for long symbol names
			@Override
			public Dimension getPreferredSize() {
				Dimension preferredSize = super.getPreferredSize();
				int maxWidth = listingPanel.getPreferredSize().width;
				if (maxWidth <= 0) {
					return preferredSize;
				}

				int toolBarWidth = getToolBarWidth();
				int minimumGrabArea = 60;
				int minimumWidth = minimumGrabArea + toolBarWidth;

				maxWidth = Math.max(maxWidth, minimumWidth);
				preferredSize.width = Math.max(maxWidth, 170);
				return preferredSize;
			}
		};
		genericHeader.setComponent(fieldPanel);
		genericHeader.setTitle(title);
		genericHeader.setNoWrapToolbar(true);

		createActions();

		// Sets the initial view of the graph to NOT be full-screen, and show 
		// the full function graph.
		setFormat(false);

		add(genericHeader, BorderLayout.NORTH);

		listingPanel.setProgramLocationListener(controller);
		listingPanel.setProgramSelectionListener(controller);
	}

	@Override
	public Component getMaximizedViewComponent() {
		return this;
	}

	private void adjustHoverListeners() {
		// clear old services
		for (ListingHoverService wrapper : installedHoverServices) {
			listingPanel.removeHoverService(wrapper);
		}
		installedHoverServices.clear();

		// add them all back (including the new ones)
		ListingHoverService[] services = tool.getServices(ListingHoverService.class);
		for (ListingHoverService hoverService : services) {
			installedHoverServices.add(hoverService);
			listingPanel.addHoverService(hoverService);
		}
	}

	private void createListingPanelToolTipComponent() {
		JPanel panel = new JPanel(new BorderLayout());

		FunctionGraphOptions options = controller.getFunctionGraphOptions();
		boolean useFullSizeTooltip = options.useFullSizeTooltip();
		previewListingPanel = new FGVertexListingPanel(controller,
			getFormatManager(useFullSizeTooltip), program, addressSet);
		previewListingPanel.setTextBackgroundColor(FGVertex.TOOLTIP_BACKGROUND_COLOR);
		//            previewListingPanel.getFieldPanel().setSelectionMode( FieldPanel.NO_SELECTION );
		previewListingPanel.getFieldPanel().setCursorOn(false);

		// keep the tooltip window from getting too big; use an arbitrary, reasonable max
		Dimension maxSize = new Dimension(700, 400);
		previewListingPanel.setMaximumSize(maxSize);
		Dimension preferredSize = previewListingPanel.getPreferredSize();
		preferredSize.width = Math.min(maxSize.width, preferredSize.width);
		preferredSize.height = Math.min(maxSize.height, preferredSize.height);
		previewListingPanel.setPreferredSize(preferredSize);

		tooltipTitleLabel = new GDLabel();
		tooltipTitleLabel.setHorizontalAlignment(SwingConstants.LEADING);
		tooltipTitleLabel.setBackground(FGVertex.TOOLTIP_BACKGROUND_COLOR);
		tooltipTitleLabel.setOpaque(true);
		Font labelFont = tooltipTitleLabel.getFont();
		tooltipTitleLabel.setFont(labelFont.deriveFont(Font.BOLD));

		JPanel headerPanel = new JPanel(new BorderLayout());
		headerPanel.add(tooltipTitleLabel);
		headerPanel.setBorder(BorderFactory.createLineBorder(Color.BLACK));

		panel.add(headerPanel, BorderLayout.NORTH);
		panel.add(previewListingPanel, BorderLayout.CENTER);

		toolTipComponent = panel;
	}

	/**
	 * Signals to rebuild this component's data model.  This call should not do any real work 
	 * if the model is not 'dirty'.
	 */
	@Override
	void refreshModel() {
		listingPanel.refreshModel();

		if (previewListingPanel != null) {
			previewListingPanel.refreshModel();
		}
	}

	@Override
	void refreshDisplay() {
		// make sure the title stays up-to-date with the symbol at the start address
		title = createTitle();
		genericHeader.setTitle(title);
		previewListingPanel = null;

		updateDefaultBackgroundColor();
	}

	private void updateDefaultBackgroundColor() {
		FunctionGraphOptions options = controller.getFunctionGraphOptions();
		Color newBgColor = options.getDefaultVertexBackgroundColor();
		if (!defaultBackgroundColor.equals(newBgColor)) {
			defaultBackgroundColor = newBgColor;
			if (userDefinedColor == null) {
				listingPanel.setTextBackgroundColor(defaultBackgroundColor);
			}
		}
	}

	@Override
	void refreshDisplayForAddress(Address address) {
		AddressSetView view = listingPanel.getView();
		if (!address.equals(view.getMinAddress())) {
			return;
		}

		refreshDisplay();

	}

	@Override
	Color getDefaultBackgroundColor() {
		return defaultBackgroundColor;
	}

	@Override
	Color getBackgroundColor() {
		return listingPanel.getTextBackgroundColor();
	}

	@Override
	Color getSelectionColor() {
		return fieldPanel.getSelectionColor();
	}

	private void createActions() {
		String firstGroup = "group1";
		String secondGroup = "group2";

		setVertexMostRecentAction = new SetVertexMostRecentColorAction(controller, vertex);
		setVertexMostRecentAction.setHelpLocation(
			new HelpLocation("FunctionGraphPlugin", "Vertex_Action_Color"));
		ToolBarData toolBarData = setVertexMostRecentAction.getToolBarData();
		setVertexMostRecentAction.setToolBarData(
			new ToolBarData(toolBarData.getIcon(), firstGroup));

		xrefsAction = new DockingAction("Jump To XRef", FunctionGraphPlugin.class.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				controller.showXRefsDialog();
			}
		};
		xrefsAction.setDescription("Jump to a XRef");
		ImageIcon imageIcon = ResourceManager.loadImage("images/brick_link.png");
		xrefsAction.setToolBarData(new ToolBarData(imageIcon, firstGroup));
		xrefsAction.setHelpLocation(new HelpLocation("FunctionGraphPlugin", "Vertex_Action_XRefs"));

		maximizeViewModeAction =
			new DockingAction("View Mode", FunctionGraphPlugin.class.getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					setFormat(true);
					vertex.setShowing(true);
					controller.setVertexViewMode(vertex, true);
				}
			};
		maximizeViewModeAction.setDescription("Reverts view from graph to fullscreen");
		imageIcon = ResourceManager.loadImage("images/fullscreen_view.png");
		maximizeViewModeAction.setToolBarData(new ToolBarData(imageIcon, firstGroup));
		maximizeViewModeAction.setHelpLocation(
			new HelpLocation("FunctionGraphPlugin", "Vertex_Action_Full_View"));

		minimizeViewModeAction =
			new DockingAction("View Mode", FunctionGraphPlugin.class.getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					setFormat(false);
					vertex.setShowing(true);
					controller.setVertexViewMode(vertex, false);
				}
			};
		minimizeViewModeAction.setDescription("Reverts view from fullscreen to graph");
		imageIcon = ResourceManager.loadImage("images/graph_view.png");
		minimizeViewModeAction.setToolBarData(new ToolBarData(imageIcon, firstGroup));
		minimizeViewModeAction.setHelpLocation(
			new HelpLocation("FunctionGraphPlugin", "Vertex_Action_Full_View"));

		groupAction = new DockingAction("Group Vertices", FunctionGraphPlugin.class.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				groupVertices();
			}
		};
		groupAction.setDescription("Combine selected vertices into one vertex");
		imageIcon = ResourceManager.loadImage("images/shape_handles.png");
		groupAction.setToolBarData(new ToolBarData(imageIcon, secondGroup));
		groupAction.setHelpLocation(new HelpLocation("FunctionGraphPlugin", "Vertex_Action_Group"));

		regroupAction = new DockingAction("Regroup Vertices", FunctionGraphPlugin.class.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				regroupVertices();
			}
		};
		regroupAction.setDescription("Restore vertex and siblings back to group form");
		imageIcon = ResourceManager.loadImage("images/edit-redo.png");
		regroupAction.setToolBarData(new ToolBarData(imageIcon, secondGroup));

		regroupAction.setHelpLocation(
			new HelpLocation("FunctionGraphPlugin", "Vertex_Action_Regroup"));

		genericHeader.actionAdded(setVertexMostRecentAction);

		if (vertex.getVertexType().isEntry()) {
			// only put the function xrefs on the entry(ies), as they clutter the display and
			// we currently only show xrefs to the function, not to individual blocks
			genericHeader.actionAdded(xrefsAction);
		}
		genericHeader.actionAdded(groupAction);

		genericHeader.update();
	}

	private void removeRedoAction() {
		genericHeader.actionRemoved(regroupAction);
		genericHeader.update();
	}

	private void addRedoAction() {
		GroupHistoryInfo groupInfo = vertex.getGroupInfo();
		regroupAction.setDescription(
			"<html>Restore Group:<br>" + HTMLUtilities.toHTML(groupInfo.getGroupDescription()));

		genericHeader.actionRemoved(regroupAction);
		genericHeader.actionAdded(regroupAction);
		genericHeader.update();
	}

	ProgramSelection getProgramHighlight() {
		return listingPanel.getProgramHighlight();
	}

	@Override
	ProgramSelection getProgramSelection() {
		return listingPanel.getProgramSelection();
	}

	@Override
	String getTextSelection() {
		return listingPanel.getTextSelection();
	}

	@Override
	ProgramLocation getProgramLocation() {
		return listingPanel.getProgramLocation();
	}

	private String createTitle() {
		Address minAddress = addressSet.getMinAddress();
		String newTitle = minAddress.toString();
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol primarySymbol = symbolTable.getPrimarySymbol(minAddress);
		if (primarySymbol != null) {
			newTitle += " - " + primarySymbol.getName(false);
		}
		return newTitle;
	}

	@Override
	public String getTitle() {
		return title;
	}

	@Override
	ListingModel getListingModel(Address address) {
		return listingPanel.getListingModel();
	}

	@Override
	void setCursorPosition(ProgramLocation location) {
		if (location == null) {
			return;
		}
		listingPanel.setCursorPosition(location);
		scrollToCursor();
	}

	@Override
	Rectangle getCursorBounds() {
		Rectangle cursorBounds = listingPanel.getCursorBounds();
		if (cursorBounds == null) {
			return null;
		}
		return SwingUtilities.convertRectangle(listingPanel, cursorBounds, this);
	}

	@Override
	void setProgramSelection(ProgramSelection selection) {
		listingPanel.setSelection(selection);
	}

	@Override
	void setProgramHighlight(ProgramSelection highlight) {
		if (highlight != null) {
			listingPanel.setHighlight(highlight);
		}
	}

	private void scrollToCursor() {
		listingPanel.getFieldPanel().scrollToCursor();
	}

	private void setFormat(boolean isMaximized) {
		listingPanel.setFormatManager(getFormatManager(isMaximized));

		if (isMaximized) {
			genericHeader.actionAdded(minimizeViewModeAction);
			genericHeader.actionRemoved(maximizeViewModeAction);
		}
		else {
			genericHeader.actionRemoved(minimizeViewModeAction);
			genericHeader.actionAdded(maximizeViewModeAction);
		}
	}

	private FormatManager getFormatManager(boolean maximized) {
		if (maximized) {
			return controller.getFullFormatManager();
		}
		return controller.getMinimalFormatManager();
	}

	@Override
	public String getToolTipText(MouseEvent event) {

		Component source = event.getComponent();
		if (SwingUtilities.isDescendingFrom(source, genericHeader)) {
			if (!(source instanceof JComponent)) {
				return null;
			}
			JComponent jComponent = (JComponent) source;
			return jComponent.getToolTipText();
		}
		return null;
	}

	@Override
	JComponent getToolTipComponentForEdge(FGEdge edge) {
		initializeToolTipComponentForEdge(edge);
		return toolTipComponent;
	}

	@Override
	JComponent getToolTipComponentForVertex() {
		Address address = getPreviewAddress(true);
		initializeToolTipComponent(address);
		tooltipTitleLabel.setText(getTitle());
		return toolTipComponent;
	}

	private void initializeToolTipComponentForEdge(FGEdge edge) {
		boolean isDestinationVertex = edge.getEnd() == vertex;
		Address address = getPreviewAddress(isDestinationVertex);
		if (address == null) {
			// This is an unusual case.   For now, do something reasonable.
			String side = isDestinationVertex ? "end" : "start";
			toolTipComponent = new GDLabel("Unable to find address for edge " + side + ": " + edge);
			toolTipComponent.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));
			if (previewListingPanel != null) {
				previewListingPanel = null;
			}
			return;
		}

		initializeToolTipComponent(address);

		if (isDestinationVertex) {
			tooltipTitleLabel.setText("To: " + getTitle());
		}
		else {
			tooltipTitleLabel.setText("From: " + getTitle());
		}

		previewListingPanel.getFieldPanel()
				.setBackgroundColorModel(
					new HighlightingColorModel(address, getColorForEdge(edge)));
	}

	private void initializeToolTipComponent(Address goToAddress) {
		if (previewListingPanel == null) {
			// lazily created
			createListingPanelToolTipComponent();
		}

		previewListingPanel.getFieldPanel().setCursorOn(true);
		previewListingPanel.goTo(goToAddress);
		previewListingPanel.getFieldPanel().setCursorOn(false);
	}

	private Color getColorForEdge(FGEdge edge) {
		FunctionGraphOptions options = controller.getFunctionGraphOptions();
		Color c = options.getColor(edge.getFlowType());
		return new Color(c.getRed(), c.getGreen(), c.getBlue(), 125);
	}

	private Address getPreviewAddress(boolean forward) {
		AddressIterator addresses = addressSet.getAddresses(forward);
		Address address = addresses.next();
		while (getLayoutForAddress(address) == null) {
			address = addresses.next();
		}
		return address;
	}

	private Layout getLayoutForAddress(Address address) {
		return listingPanel.getLayout(address);
	}

	@Override
	public void doSetFocused(boolean focused) {
		fieldPanel.setCursorOn(focused);
		if (focused) {
			requestFocus();
		}
	}

	@Override
	public void requestFocus() {
		listingPanel.requestFocus();
	}

	@Override
	public JComponent getHeader() {
		return genericHeader;
	}

	@Override
	boolean isSelected() {
		return genericHeader.isSelected();
	}

	@Override
	boolean isFullScreenMode() {
		FormatManager fullFormatManager = getFormatManager(true);
		FormatManager currentFormatManager = listingPanel.getFormatManager();
		return currentFormatManager == fullFormatManager;
	}

	@Override
	void setFullScreenMode(boolean fullScreen) {
		setFormat(fullScreen);
		vertex.setShowing(true);
		controller.setVertexViewMode(vertex, fullScreen);
	}

	@Override
	void setSelected(boolean selected) {
		genericHeader.setSelected(selected);
	}

	@Override
	void updateGroupAssociationStatus(boolean groupMember) {
		if (groupMember) {
			addRedoAction();
		}
		else {
			removeRedoAction();
		}
	}

	@Override
	Color getUserDefinedColor() {
		return userDefinedColor;
	}

	@Override
	void restoreColor(Color color) {
		listingPanel.setTextBackgroundColor(color);
	}

	@Override
	void setBackgroundColor(Color color) {
		userDefinedColor = color;
		listingPanel.setTextBackgroundColor(color);
		controller.repaint();
	}

	@Override
	void clearColor() {
		userDefinedColor = null;
		listingPanel.setTextBackgroundColor(defaultBackgroundColor);
		controller.removeColor(vertex);
		controller.repaint();
	}

	@Override
	void editLabel(JComponent parentComponent) {
		AddressSetView view = listingPanel.getView();
		Address minAddress = view.getMinAddress();
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol primarySymbol = symbolTable.getPrimarySymbol(minAddress);

		AddEditDialog dialog = new AddEditDialog("", tool);
		if (primarySymbol == null) {
			dialog.addLabel(minAddress, program, parentComponent);
		}
		else {
			dialog.editLabel(primarySymbol, program, parentComponent);
		}
	}

	@Override
	void dispose() {

		//
		// Let's go a bit overboard and help the garbage collector cleanup by nulling out 
		// references and removing the data from Jung's graph
		//

		removeAll();

		listingPanel.setStringSelectionListener(null);
		listingPanel.removeButtonPressedListener(
			controller.getSharedHighlighterButtonPressedListener());
		listingPanel.dispose();

		if (previewListingPanel != null) {
			previewListingPanel.dispose();
		}

		xrefsAction.dispose();
		setVertexMostRecentAction.dispose();

		tool.removeServiceListener(serviceChangeListener);

		installedHoverServices.clear();

		genericHeader.dispose();

		listingPanel = null;
		fieldPanel = null;
		previewListingPanel = null;
		tooltipTitleLabel = null;
		toolTipComponent = null;
		genericHeader = null;

		super.dispose();
	}

//==================================================================================================
// Inner-inner classes
//==================================================================================================        

	private class ListingHoverAdapter extends ListingHoverProvider {
		public ListingHoverAdapter() {
			super();
		}

		@Override
		protected void showPopup(JComponent comp, Field field, MouseEvent event,
				Rectangle fieldBounds) {
			if (!controller.arePopupsEnabled()) {
				return;
			}

			Rectangle translatedRectangle =
				controller.translateRectangleFromVertexToViewSpace(vertex, fieldBounds);

			MouseEvent translatedEvent =
				controller.translateMouseEventFromVertexToViewSpace(vertex, event);
			super.showPopup(comp, field, translatedEvent, translatedRectangle);
		}
	}

	private class FieldPanelKeyListener implements KeyListener {
		@Override
		public void keyPressed(KeyEvent e) {
			KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
			kfm.redispatchEvent(fieldPanel, e);
		}

		@Override
		public void keyReleased(KeyEvent e) {
			KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
			kfm.redispatchEvent(fieldPanel, e);
		}

		@Override
		public void keyTyped(KeyEvent e) {
			KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
			kfm.redispatchEvent(fieldPanel, e);
		}
	}

	private class HighlightingColorModel implements BackgroundColorModel {
		private Color highlightDefaultBackgroundColor;
		private Color highlightColor;
		private final Address highlightAddress;

		public HighlightingColorModel(Address highlightAddress, Color highlightColor) {
			this.highlightAddress = highlightAddress;
			this.highlightColor = highlightColor;
		}

		@Override
		public Color getBackgroundColor(BigInteger index) {
			BigInteger highlightIndex = getHighlightIndex(highlightAddress);
			if (!highlightIndex.equals(index)) {
				return highlightDefaultBackgroundColor;
			}
			return highlightColor;
		}

		@Override
		public Color getDefaultBackgroundColor() {
			return highlightDefaultBackgroundColor;
		}

		@Override
		public void setDefaultBackgroundColor(Color c) {
			this.highlightDefaultBackgroundColor = c;
		}

		private BigInteger getHighlightIndex(Address address) {
			AddressIndexMap addressIndexMap = listingPanel.getAddressIndexMap();
			return addressIndexMap.getIndex(address);
		}
	}

}
