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
package ghidra.graph.viewer;

import java.awt.*;
import java.awt.event.*;
import java.awt.geom.Point2D;
import java.util.*;

import javax.swing.*;

import com.google.common.base.Function;

import docking.DockingUtils;
import docking.DockingWindowManager;
import docking.actions.KeyBindingUtils;
import docking.help.HelpService;
import docking.widgets.EmptyBorderButton;
import docking.widgets.PopupWindow;
import docking.widgets.label.GIconLabel;
import edu.uci.ics.jung.algorithms.layout.GraphElementAccessor;
import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.visualization.*;
import edu.uci.ics.jung.visualization.VisualizationServer.Paintable;
import edu.uci.ics.jung.visualization.control.AbstractGraphMousePlugin;
import edu.uci.ics.jung.visualization.decorators.PickableVertexPaintTransformer;
import edu.uci.ics.jung.visualization.decorators.ToStringLabeller;
import edu.uci.ics.jung.visualization.picking.PickedState;
import edu.uci.ics.jung.visualization.picking.ShapePickSupport;
import edu.uci.ics.jung.visualization.renderers.Renderer;
import edu.uci.ics.jung.visualization.util.Caching;
import ghidra.graph.VisualGraph;
import ghidra.graph.event.VisualGraphChangeListener;
import ghidra.graph.viewer.edge.*;
import ghidra.graph.viewer.event.mouse.*;
import ghidra.graph.viewer.event.picking.GPickedState;
import ghidra.graph.viewer.event.picking.PickListener;
import ghidra.graph.viewer.layout.LayoutListener;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.graph.viewer.options.ViewRestoreOption;
import ghidra.graph.viewer.options.VisualGraphOptions;
import ghidra.graph.viewer.satellite.CachingSatelliteGraphViewer;
import ghidra.graph.viewer.shape.VisualGraphShapePickSupport;
import ghidra.graph.viewer.vertex.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
import ghidra.util.exception.AssertException;
import resources.Icons;
import resources.ResourceManager;
import util.CollectionUtils;

/**
 * A component that contains primary and satellite graph views.  This viewer provides
 * methods for manipulating the graph using the mouse.
 *
 * <p>To gain the full functionality offered by this class, clients will need to subclass
 * this class and override {@link #createPrimaryGraphViewer(VisualGraphLayout, Dimension)}
 * and {@link #createSatelliteGraphViewer(GraphViewer, Dimension)} as needed.   This allows
 * them to customize renderers and other viewer attributes.  To use the subclass, see the
 * {@link VisualGraphView} and its <code>installGraphViewer()</code> method.
 * 
 * @param <V> the vertex type
 * @param <E> the edge type
 * @param <G> the graph type
 * 
 * @see GraphViewer
 */
public class GraphComponent<V extends VisualVertex, E extends VisualEdge<V>, G extends VisualGraph<V, E>> {

	private static final double PARENT_TO_SATELLITE_RATIO = 4;// 2.5 smaller view seems better
	private static final int MINIMUM_SATELLITE_WIDTH = 150;

	// TODO this is arbitrary right now; perform testing for a generic number value;
	// subclasses can override
	private static final int REALLY_BIG_GRAPH_VERTEX_COUNT = 500;

	private static final Integer PRIMARY_VIEWER_LAYER = Integer.valueOf(100);
	private static final Integer SATELLITE_PROVIDER_BUTTON_LAYER = Integer.valueOf(199);
	private static final Integer SATELLITE_VIEWER_LAYER = Integer.valueOf(200);
	private static final Integer STALE_GRAPH_VIEW_LAYER = Integer.valueOf(300);

	private JPanel staleGraphViewPanel;
	private MessagePaintable messagePaintable = new MessagePaintable();

	protected GPickedState<V> gPickedState;
	private Optional<VertexFocusListener<V>> vertexFocusListener = Optional.empty();
	private Optional<VertexClickListener<V, E>> vertexClickListener = Optional.empty();

	private JPanel mainPanel;
	private JLayeredPane layeredPane;

	protected G graph;
	private GraphChangeListener graphChangeListener = new GraphChangeListener();
	private VertexPickingListener vertexPickingListener;

	protected GraphViewer<V, E> primaryViewer;
	protected SatelliteGraphViewer<V, E> satelliteViewer;
	private Optional<GraphSatelliteListener> satelliteListener = Optional.empty();

	private JPanel undockedSatellitePanel;
	private JButton showUndockedSatelliteButton;

	private LayoutListener<V, E> layoutListener = new PrimaryLayoutListener();

	private boolean isUninitialized = true; // another silly flag to know when we have been painted
	private GraphPerspectiveInfo<V, E> graphPerspectiveInfo;

	private VisualGraphPluggableGraphMouse<V, E> primaryGraphMouse;
	private VisualGraphPluggableGraphMouse<V, E> satelliteGraphMouse;

	// a cache to prevent unnecessary layout calculations
	private Dimension lastSize;

	protected VisualGraphOptions vgOptions = new VisualGraphOptions();

	public GraphComponent(G graph) {

		setGraph(graph);

		build();
	}

	protected GraphComponent() {
		// This allows subclasses to set their required state before building.  However, the
		// subclass is required to call build() inside of the constructor.
	}

	protected void setGraph(G g) {

		this.graph = Objects.requireNonNull(g);
	}

	protected void build() {

		graph.addGraphChangeListener(graphChangeListener);

		VisualGraphLayout<V, E> layout = buildLayout();

		// a big size gives plenty of room to layouts that respect size (the layout uses the
		// initial size of the viewer)
		Dimension mainViewerSize = new Dimension(4000, 4000);
		primaryViewer = buildPrimaryGraphViewer(layout, mainViewerSize);
		decoratePrimaryViewer(primaryViewer, layout);

		// this size forces the satellite to be exactly this size and no bigger
		Dimension satelliteSize = new Dimension(300, 300);
		satelliteViewer = buildSatelliteViewer(primaryViewer, layout, satelliteSize);
		decorateSatelliteViewer(satelliteViewer, layout);

		// install into the view updater
		VisualGraphViewUpdater<V, E> updater = primaryViewer.getViewUpdater();
		updater.setSatelliteViewer(satelliteViewer);

		staleGraphViewPanel = buildStaleLayoutPanel();

		// hover highlight mouse plugin (must be first; does not consume events)
		primaryGraphMouse.prepend(
			new VisualGraphHoverMousePlugin<>(this, primaryViewer, satelliteViewer));
		satelliteGraphMouse.prepend(
			new VisualGraphHoverMousePlugin<>(this, satelliteViewer, primaryViewer));

		primaryGraphMouse.prepend(new VertexClickMousePlugin());

		createGUIComponents(primaryViewer, satelliteViewer);

		ToolTipManager.sharedInstance().registerComponent(primaryViewer);
		ToolTipManager.sharedInstance().registerComponent(satelliteViewer);
	}

	// template method
	protected GraphViewer<V, E> createPrimaryGraphViewer(VisualGraphLayout<V, E> layout,
			Dimension viewerSize) {

		//
		// This method can be overridden by subclasses to perform custom creation and setup.
		// Any setup, like renderers, that this class should not override must be put in this
		// method so that subclasses can override.  Common setup items should be in the
		// method that calls this one.
		//

		GraphViewer<V, E> viewer = new GraphViewer<>(layout, viewerSize);

		Renderer<V, E> renderer = viewer.getRenderer();
		renderer.setVertexRenderer(new VisualVertexRenderer<>());

		RenderContext<V, E> renderContext = viewer.getRenderContext();

		Color normal = Color.GREEN.darker().darker();
		Color selected = Color.GREEN;
		renderContext.setEdgeDrawPaintTransformer(e -> e.isSelected() ? selected : normal);
		renderContext.setArrowDrawPaintTransformer(e -> e.isSelected() ? selected : normal);
		renderContext.setArrowFillPaintTransformer(e -> e.isSelected() ? selected : normal);

		PickedState<V> pickedVertexState = viewer.getPickedVertexState();
		renderContext.setVertexFillPaintTransformer(
			new PickableVertexPaintTransformer<>(pickedVertexState, Color.WHITE, Color.YELLOW));

		viewer.setGraphOptions(vgOptions);

		return viewer;
	}

	private GraphViewer<V, E> buildPrimaryGraphViewer(VisualGraphLayout<V, E> layout,
			Dimension viewerSize) {

		GraphViewer<V, E> viewer = createPrimaryGraphViewer(layout, viewerSize);

		viewer.setViewerInitializedListener(v -> {
			viewerInitialized(v);
		});

		//
		// Listeners
		//
		primaryGraphMouse = viewer.getGraphMouse();

		viewer.setPickSupport(new VisualGraphShapePickSupport<>(viewer));

		// this is a listener that allows us to make edge picking easier as scaling occurs
		RenderContext<V, E> renderContext = viewer.getRenderContext();
		MultiLayerTransformer multiLayerTransformer = renderContext.getMultiLayerTransformer();
		multiLayerTransformer.addChangeListener(
			event -> GraphViewerUtils.adjustEdgePickSizeForZoom(viewer));

		gPickedState = viewer.getGPickedVertexState();
		vertexPickingListener = new VertexPickingListener(graph);
		gPickedState.addPickingListener(vertexPickingListener);

		viewer.addKeyListener(new KeyForwardingKeyAdapter(graph, viewer));

		adjustPickSupport(viewer);

		viewer.addPostRenderPaintable(messagePaintable);

		return viewer;
	}

	/**
	 * This is called to configure the primary viewer's rendering settings.  Subclasses can
	 * override this method to change, as needed.
	 * 
	 * @param viewer the new satellite viewer
	 * @param layout the viewer's layout
	 */
	protected void decoratePrimaryViewer(GraphViewer<V, E> viewer, VisualGraphLayout<V, E> layout) {

		Renderer<V, E> renderer = viewer.getRenderer();
		renderer.setEdgeRenderer(layout.getEdgeRenderer());

		RenderContext<V, E> renderContext = viewer.getRenderContext();

		// this will paint thicker, but with the shape being used...which can look odd
		//renderContext.setEdgeFillPaintTransformer(null);
		PickedState<E> pickedEdgeState = viewer.getPickedEdgeState();
		renderContext.setEdgeStrokeTransformer(
			new VisualGraphEdgeStrokeTransformer<>(pickedEdgeState, 3));
		pickedEdgeState.addItemListener(new EdgePickingListener());

		// the layout defines the shape of the edge (this gives the layout flexibility in how
		// to render its shape)
		Function<E, Shape> edgeTransformer = layout.getEdgeShapeTransformer();
		renderContext.setEdgeShapeTransformer(edgeTransformer);

		renderContext.setArrowPlacementTolerance(5.0f);

		renderContext.setVertexShapeTransformer(new VisualGraphVertexShapeTransformer<>());
	}

	// template method
	protected SatelliteGraphViewer<V, E> createSatelliteGraphViewer(GraphViewer<V, E> masterViewer,
			Dimension viewerSize) {

		SatelliteGraphViewer<V, E> viewer =
			isReallyBigData() ? new CachingSatelliteGraphViewer<>(masterViewer, viewerSize)
					: new SatelliteGraphViewer<>(masterViewer, viewerSize);

		return viewer;
	}

	private SatelliteGraphViewer<V, E> buildSatelliteViewer(GraphViewer<V, E> masterViewer,
			VisualGraphLayout<V, E> layout, Dimension viewerSize) {

		SatelliteGraphViewer<V, E> viewer = createSatelliteGraphViewer(masterViewer, viewerSize);

		viewer.setGraphOptions(vgOptions);

		viewer.setMinimumSize(viewerSize);
		viewer.setMaximumSize(viewerSize);

		satelliteGraphMouse = viewer.getGraphMouse();

		return viewer;
	}

	/**
	 * This is called to configure the satellite viewer's rendering settings.  Subclasses can
	 * override this method to change, as needed.
	 * 
	 * @param viewer the new satellite viewer
	 * @param layout the viewer's layout
	 */
	protected void decorateSatelliteViewer(SatelliteGraphViewer<V, E> viewer,
			VisualGraphLayout<V, E> layout) {

		RenderContext<V, E> renderContext = viewer.getRenderContext();

		Renderer<V, E> renderer = viewer.getRenderer();
		renderer.setVertexRenderer(viewer.getPreferredVertexRenderer());
		renderer.setEdgeRenderer(new VisualGraphEdgeSatelliteRenderer<>(
			(VisualEdgeRenderer<V, E>) layout.getEdgeRenderer()));

		Function<E, Shape> edgeTransformer = layout.getEdgeShapeTransformer();
		renderContext.setEdgeShapeTransformer(edgeTransformer);

		renderContext.setVertexShapeTransformer(new VisualGraphVertexShapeTransformer<>());

		viewer.setVertexToolTipTransformer(new ToStringLabeller());
	}

	private void createGUIComponents(final VisualizationViewer<V, E> viewer,
			SatelliteGraphViewer<V, E> satellite) {

		installCommonListeners(viewer, satellite);

		// add our panels...
		mainPanel = new JPanel(new BorderLayout());

		layeredPane = new JLayeredPane() {

			@Override
			public void setBounds(int x, int y, int width, int height) {
				super.setBounds(x, y, width, height);

				Rectangle bounds = primaryViewer.getBounds();
				Dimension parentSize = mainPanel.getSize();
				if (bounds.width == parentSize.width && bounds.height == parentSize.height) {
					return;
				}

				updateLayeredPaneComponentsForSizeChange();
			}
		};

		layeredPane.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				if (layeredPane.getSize().equals(lastSize)) {
					return;
				}

				updateLayeredPaneComponentsForSizeChange();
			}
		});

		layeredPane.setPreferredSize(new Dimension(400, 400));

		layeredPane.add(viewer, PRIMARY_VIEWER_LAYER);

		layeredPane.add(satellite, SATELLITE_VIEWER_LAYER);
		satellite.setDocked(true);

		mainPanel.add(layeredPane, BorderLayout.CENTER);

		satellite.setBorder(BorderFactory.createLineBorder(Color.BLACK));

		undockedSatellitePanel = new JPanel(new BorderLayout());
		undockedSatellitePanel.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				if (isSatelliteUnDocked()) {
					VisualGraphViewUpdater<V, E> viewUpdater = getViewUpdater();
					viewUpdater.fitGraphToViewerLater(satelliteViewer);
				}
			}
		});

		showUndockedSatelliteButton = buildShowUndockedProviderButton();
		layeredPane.add(showUndockedSatelliteButton, SATELLITE_PROVIDER_BUTTON_LAYER);
	}

	private void installCommonListeners(final VisualizationViewer<V, E> viewer,
			VisualizationViewer<V, E> satellite) {
		MouseListener hidePopupMouseListener = new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				PopupWindow.hideAllWindows();
			}
		};
		viewer.addMouseListener(hidePopupMouseListener);
		satellite.addMouseListener(hidePopupMouseListener);

		KeyListener hidePopupKeyListener = new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
					PopupWindow.hideAllWindows();
					DockingUtils.hideTipWindow();
				}
			}
		};
		viewer.addKeyListener(hidePopupKeyListener);
		satellite.addKeyListener(hidePopupKeyListener);
	}

	private EmptyBorderButton buildShowUndockedProviderButton() {
		String tooltip = "Bring satellite view to the front";

		Icon icon = ResourceManager.loadImage("images/network-wireless.png");
		JLabel iconLabel = new GIconLabel(icon);
		iconLabel.setOpaque(false);
		iconLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		iconLabel.setToolTipText(tooltip);

		EmptyBorderButton button = new VisualGraphLayeredPaneButton(icon);
		button.setName("show.satellite.button");
		button.addActionListener(e -> {
			setSatelliteVisible(true);
		});
		button.setOpaque(false);
		button.setToolTipText(tooltip);

		/*
		 
		 TODO fix when the Generic Visual Graph help module is created
		 
		HelpService helpService = DockingWindowManager.getHelpService();
		helpService.registerHelp(button,
			new HelpLocation("GraphTopic", "Satellite_View_Dock"));
		*/

		return button;
	}

	private JPanel buildStaleLayoutPanel() {
		final JPanel mainStalePanel = new JPanel(new BorderLayout()) {
			@Override
			public boolean isShowing() {
				return true;
			}
		};
		mainStalePanel.setOpaque(false);

		String tooltip = HTMLUtilities.toWrappedHTML("The block model of the function " +
			"for this graph has changed.  Press the relayout button to refresh the layout." +
			"\n\n") + "<b>Note: </b>You can edit the graph " +
			"options to have the graph update automatically.";

		Icon icon = Icons.REFRESH_ICON;
		JLabel iconLabel = new GIconLabel(icon);
		iconLabel.setOpaque(false);
		iconLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		iconLabel.setToolTipText(tooltip);

		EmptyBorderButton refreshButton = new VisualGraphLayeredPaneButton(icon);
		refreshButton.setName("refresh.button");
		refreshButton.addActionListener(e -> refreshCurrentLayout());
		refreshButton.setOpaque(false);
		refreshButton.setToolTipText(tooltip);

		HelpService helpService = DockingWindowManager.getHelpService();
		helpService.registerHelp(refreshButton,
			new HelpLocation("FunctionGraphPlugin", "Stale_Graph"));

		mainStalePanel.add(refreshButton, BorderLayout.WEST);

		return mainStalePanel;
	}

	private VisualGraphLayout<V, E> buildLayout() {

		VisualGraphLayout<V, E> layout = graph.getLayout();
		if (layout == null) {
			// sanity check
			throw new AssertException("Graph should have had a layout applied before rendering." +
				"  Make sure the layout has been created and that it is returned from " +
				"VisualGraph.getLayout()");
		}

		// for knowing when to update the size of the satellite
		layout.addLayoutListener(layoutListener);

		return layout;
	}

	private void adjustPickSupport(VisualizationViewer<V, E> viewer) {
		GraphElementAccessor<V, E> pickSupport = viewer.getPickSupport();
		if (!(pickSupport instanceof ShapePickSupport)) {
			return;
		}

		ShapePickSupport<V, E> shapePickSupport = (ShapePickSupport<V, E>) pickSupport;
		shapePickSupport.setStyle(ShapePickSupport.Style.HIGHEST);
	}

	/**
	 * This method is used to determine caching strategy.  For example, large graph will
	 * trigger the us of a cached satellite view, for performance reasons.
	 * 
	 * @return true if the data is considered 'really big'
	 */
	protected boolean isReallyBigData() {
		return graph.getVertices().size() > REALLY_BIG_GRAPH_VERTEX_COUNT;
	}

	public void setVertexFocusListener(VertexFocusListener<V> l) {
		this.vertexFocusListener = Optional.ofNullable(l);
	}

	public void setVertexClickListener(VertexClickListener<V, E> l) {
		this.vertexClickListener = Optional.ofNullable(l);
	}

	public void setGraphOptions(VisualGraphOptions options) {
		this.vgOptions = options;

		// the viewers may be null if called during initialization
		if (primaryViewer != null) {
			primaryViewer.setGraphOptions(options);
		}

		if (satelliteViewer != null) {
			satelliteViewer.setGraphOptions(options);
		}
	}

	public VisualGraphOptions getGraphOptions() {
		return vgOptions;
	}

	public boolean isUninitialized() {
		return isUninitialized;
	}

	public void setGraphViewStale(boolean isStale) {
		layeredPane.remove(staleGraphViewPanel);
		String message = null;
		if (isStale) {
			layeredPane.add(staleGraphViewPanel, STALE_GRAPH_VIEW_LAYER);
			message = "Graph is stale";
		}
		setStatusMessage(message);
		layeredPane.repaint();
	}

	public boolean isGraphViewStale() {
		Component[] comps = layeredPane.getComponentsInLayer(STALE_GRAPH_VIEW_LAYER);
		return comps.length != 0;
	}

	/**
	 * Sets a message to be painted on the viewer.  This is useful to show a text message to the
	 * user.  Passing null will clear the message.
	 * 
	 * @param message the message
	 */
	public void setStatusMessage(String message) {
		messagePaintable.setMessage(message);
		primaryViewer.repaint();
	}

	public JComponent getComponent() {
		return mainPanel;
	}

	public void optionsChanged() {
		primaryViewer.optionsChanged();
		satelliteViewer.optionsChanged();
	}

	public void repaint() {
		mainPanel.repaint();
	}

	public GraphViewer<V, E> getPrimaryViewer() {
		return primaryViewer;
	}

	public SatelliteGraphViewer<V, E> getSatelliteViewer() {
		return satelliteViewer;
	}

	protected VisualGraphViewUpdater<V, E> getViewUpdater() {
		return primaryViewer.getViewUpdater();
	}

	/**
	 * Returns an empty rectangle if the satellite is not visible
	 * @return the bounds
	 */
	public Rectangle getSatelliteBounds() {
		if (!isSatelliteShowing()) {
			return new Rectangle(0, 0, 0, 0);
		}
		return satelliteViewer.getBounds();
	}

	private void viewerInitialized(VisualizationViewer<V, E> viewer) {
		isUninitialized = false;

		if (graphPerspectiveInfo != null) {
			// always prefer the previous state
			applyGraphPerspective(graphPerspectiveInfo);
		}
		else {
			//
			// Default Zoom - Zoomed-out or Zoomed-in?
			//
			ViewRestoreOption viewOption = vgOptions.getViewRestoreOption();
			if (viewOption == ViewRestoreOption.START_FULLY_ZOOMED_IN) {
				zoomInCompletely(getInitialVertex());
			}
			else {
				// default to zoomed out, even in the other view option modes
				VisualGraphViewUpdater<V, E> viewUpdater = getViewUpdater();
				viewUpdater.fitAllGraphsToViewsNow();
			}
		}

		// this does nothing if not scaled past the interaction threshold
		twinkleVertex(graph.getFocusedVertex());

		graphPerspectiveInfo = null;
	}

	/*
	 * Returns the vertex that should be shown when the graph is first made visible
	 */
	protected V getInitialVertex() {
		return graph.getFocusedVertex();
	}

	protected void zoomInCompletely(V v) {
		VisualGraphViewUpdater<V, E> viewUpdater = getViewUpdater();
		viewUpdater.zoomInCompletely(v);
	}

	// note: called only when we have valid saved data, otherwise the default null value is used
	//       when the viewer is initialized
	public void setGraphPerspective(GraphPerspectiveInfo<V, E> info) {
		if (isUninitialized) {
			this.graphPerspectiveInfo = info;
		}
		else {
			applyGraphPerspective(info);
		}
	}

	private void applyGraphPerspective(GraphPerspectiveInfo<V, E> graphInfo) {
		VisualGraphViewUpdater<V, E> viewUpdater = getViewUpdater();
		viewUpdater.setGraphPerspective(graphInfo);
	}

	/**
	 * Sets the given vertex to be the focused vertex.  This will be the only focused vertex.
	 * 
	 * @param vertex the vertex
	 */
	public void setVertexFocused(V vertex) {

		if (!vertex.isFocused()) {
			// reset the world's notion of the focused vertex
			gPickedState.pickToActivate(vertex);
		}
		else {
			// the vertex is already focused, make sure everyone is in sync
			gPickedState.pickToSync(vertex);
		}
	}

	public void setVerticesSelected(Collection<V> vertices) {
		gPickedState.clear();
		for (V v : vertices) {
			gPickedState.pick(v, true);
		}
	}

	public void twinkleVertex(V twinkleVertex) {
		if (twinkleVertex == null) {
			return;
		}

		VisualGraphViewUpdater<V, E> viewUpdater = getViewUpdater();
		viewUpdater.twinkeVertex(twinkleVertex);
	}

	public boolean isSatelliteComponent(Component c) {
		return c == satelliteViewer;
	}

	protected JComponent getSatelliteContentComponent() {
		return undockedSatellitePanel;
	}

	private void updateSatellite(boolean docked, boolean visible) {

		layeredPane.remove(satelliteViewer);
		undockedSatellitePanel.remove(satelliteViewer);

		if (visible) {
			if (docked) {
				layeredPane.add(satelliteViewer, SATELLITE_VIEWER_LAYER);
			}
			else {
				undockedSatellitePanel.add(satelliteViewer);
			}
		}

		satelliteViewer.setDocked(docked);

		updateLayeredPaneComponentsSizes(true);
		layeredPane.repaint();
		undockedSatellitePanel.repaint();

		satelliteListener.ifPresent(l -> l.satelliteVisibilityChanged(docked, visible));
	}

	void setSatelliteLisetener(GraphSatelliteListener l) {
		satelliteListener = Optional.ofNullable(l);
	}

	void setInitialSatelliteState(boolean visible, boolean docked) {
		updateSatellite(docked, visible);
	}

	public void setSatelliteDocked(boolean docked) {

		if (isSatelliteDocked() == docked) {
			return; // nothing to do
		}

		satelliteViewer.setDocked(docked);

		// when transitioning from docked to undocked, we show the satellite
		updateSatellite(docked, true);
	}

	public void setSatelliteVisible(boolean visible) {

		if (isSatelliteShowing() == visible) {

			if (visible && !isSatelliteDocked()) {
				Window w = SwingUtilities.windowForComponent(satelliteViewer);
				w.toFront();
			}

			return;
		}

		updateSatellite(isSatelliteDocked(), visible);
	}

	public boolean isSatelliteShowing() {
		Component[] comps = layeredPane.getComponentsInLayer(SATELLITE_VIEWER_LAYER);
		if (comps.length != 0) {
			return true; // satellite is in this component
		}

		// it may be in another window--see if it is showing
		return satelliteViewer.isShowing();
	}

	private void updateLayeredPaneComponentsForSizeChange() {
		updateLayeredPaneComponentsSizes(false);
	}

	private void updateLayeredPaneComponentsSizes(boolean force) {
		Dimension parentSize = mainPanel.getSize();
		primaryViewer.setBounds(0, 0, parentSize.width, parentSize.height);

		updateSatelliteBounds(parentSize, force);

		Dimension stalePanelSize = staleGraphViewPanel.getPreferredSize();
		int x = 0;
		int y = parentSize.height - stalePanelSize.height;
		staleGraphViewPanel.setBounds(x, y, stalePanelSize.width, stalePanelSize.height);

		Dimension buttonSize = showUndockedSatelliteButton.getPreferredSize();
		x = parentSize.width - buttonSize.width;
		y = parentSize.height - buttonSize.height;
		showUndockedSatelliteButton.setBounds(x, y, buttonSize.width, buttonSize.height);

		lastSize = new Dimension(parentSize.width, parentSize.height);
	}

	private void updateSatelliteBounds(Dimension parentSize, boolean forceUpdate) {

		if (!isSatelliteShowing() && !forceUpdate) {
			return;
		}

		if (!isSatelliteUnDocked()) {

			// put satellite in lower corner
			Dimension satelliteSize = satelliteViewer.getSize();
			int newWidth = getNewBoundsSize(parentSize, satelliteSize);
			satelliteSize.width = newWidth;
			satelliteSize.height = newWidth;
			int x = parentSize.width - satelliteSize.width;
			int y = parentSize.height - satelliteSize.height;
			satelliteViewer.setBounds(x, y, satelliteSize.width, satelliteSize.height);
		}

		VisualGraphViewUpdater<V, E> viewUpdater = getViewUpdater();
		viewUpdater.fitGraphToViewerNow(satelliteViewer);
	}

	private int getNewBoundsSize(Dimension parentBounds, Dimension satelliteBounds) {
		double newSatelliteHeight = parentBounds.height / PARENT_TO_SATELLITE_RATIO;
		double newSatelliteWidth = parentBounds.width / PARENT_TO_SATELLITE_RATIO;

		int newValue = (int) Math.round(newSatelliteWidth);
		if (newSatelliteHeight < newSatelliteWidth) {
			newValue = (int) Math.round(newSatelliteHeight);
		}

		return Math.max(MINIMUM_SATELLITE_WIDTH, newValue);
	}

	public boolean isSatelliteDocked() {
		return satelliteViewer.isDocked();
	}

	public boolean isSatelliteUnDocked() {
		return !satelliteViewer.isDocked();
	}

	public void setPopupsVisible(boolean visible) {
		primaryViewer.setPopupsVisible(visible);
	}

	public PathHighlightMode getVertexHoverPathHighlightMode() {
		return primaryViewer.getVertexHoverPathHighlightMode();
	}

	public void setVertexHoverPathHighlightMode(PathHighlightMode mode) {
		primaryViewer.setVertexHoverPathHighlightMode(mode);
		primaryViewer.repaint();
		satelliteViewer.repaint();
	}

	public PathHighlightMode getVertexFocusPathHighlightMode() {
		return primaryViewer.getVertexFocusPathHighlightMode();
	}

	public void setVertexFocusPathHighlightMode(PathHighlightMode mode) {
		primaryViewer.setVertexFocusPathHighlightMode(mode);
		primaryViewer.repaint();
		satelliteViewer.repaint();
	}

	public RenderContext<V, E> getRenderContext() {
		RenderContext<V, E> context = primaryViewer.getRenderContext();
		return context;
	}

	public G getGraph() {
		return graph;
	}

	public VisualGraphPathHighlighter<V, E> getPathHighlighter() {
		return primaryViewer.getPathHighlighter();
	}

	protected void refreshCurrentLayout() {
		setGraphViewStale(false);
	}

	public void dispose() {

		if (graph != null) {
			graph.removeGraphChangeListener(graphChangeListener);
			VisualGraphLayout<V, E> layout = graph.getLayout();
			layout.removeLayoutListener(layoutListener);
		}

		//
		// Let's go a bit overboard and help the garbage collector cleanup by nulling out
		// references and removing the data from Jung's graph
		//

		Layout<V, E> layout = primaryViewer.getGraphLayout();
		if (layout instanceof Caching) {
			((Caching) layout).clear();
		}

		layout = satelliteViewer.getGraphLayout();
		if (layout instanceof Caching) {
			((Caching) layout).clear();
		}

		gPickedState.removePickingListener(vertexPickingListener);

		PickedState<V> vertexState = primaryViewer.getPickedVertexState();
		vertexState.clear();
		vertexState = satelliteViewer.getPickedVertexState();
		vertexState.clear();

		PickedState<E> edgeState = primaryViewer.getPickedEdgeState();
		edgeState.clear();
		edgeState = primaryViewer.getPickedEdgeState();
		edgeState.clear();

		primaryViewer.dispose();

		undockedSatellitePanel.removeAll();
		undockedSatellitePanel.repaint();
		satelliteViewer.removeAll();

		primaryGraphMouse.dispose();
		satelliteGraphMouse.dispose();

		layeredPane.removeAll();
		layeredPane = null;

		mainPanel.removeAll();
		mainPanel = null;

		primaryViewer = null;
		satelliteViewer = null;
		graphPerspectiveInfo = null;
		satelliteListener = null;
		graph = null;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================
	private class PrimaryLayoutListener implements LayoutListener<V, E> {

		@Override
		public void vertexLocationChanged(final V v, final Point2D newLocation,
				ChangeType changeType) {
			if (isUninitialized) {
				return; // can happen during setup
			}

			v.setLocation(newLocation);

			if (changeType == ChangeType.RESTORE) {
				// ignore these events, as they are a bulk operation and will be handled later
				return;
			}

			if (isSatelliteShowing()) {
				VisualGraphViewUpdater<V, E> viewUpdater = getViewUpdater();
				viewUpdater.fitGraphToViewerLater(satelliteViewer);
			}

			graph.vertexLocationChanged(v,
				new Point((int) newLocation.getX(), (int) newLocation.getY()), changeType);
		}
	}

	private class MessagePaintable implements Paintable {

		private final Color backgroundColor = new Color(134, 180, 238);
		private String message = null;

		@Override
		public void paint(Graphics g) {
			if (message == null) {
				return;
			}

			Graphics2D g2 = (Graphics2D) g;
			Composite originalComposite = g2.getComposite();

			// this composite softens the text and color of the message
			g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SrcOver.getRule(), .60f));

			Font font = new Font("Sanf Serif", Font.BOLD | Font.ITALIC, 18);
			g.setFont(font);

			Rectangle stringBounds =
				font.getStringBounds(message, g2.getFontRenderContext()).getBounds();

			Rectangle viewerBounds = primaryViewer.getBounds();
			Point viewPosition = viewerBounds.getLocation();
			int bottomY = (int) (viewPosition.y + viewerBounds.getHeight());

			int startX = 0;
			int startY = bottomY - 5; // add some padding

			Color[] colors = new Color[] { backgroundColor, primaryViewer.getBackground() };

			int backgroundHeight = (stringBounds.height * 3);
			int backgroundWidth = viewerBounds.width;
			int backgroundX = startX;
			int backgroundY = bottomY - backgroundHeight;

			float[] fractions = new float[] { 0.0f, .95f };
			int upperY = backgroundY;
			LinearGradientPaint bottomToTopGradiant = new LinearGradientPaint(
				new Point(startX, startY), new Point(startX, upperY), fractions, colors);

			g2.setPaint(bottomToTopGradiant);
			g2.fillRect(backgroundX, upperY, backgroundWidth, backgroundHeight);

			g2.setPaint(Color.BLACK);
			int textX =
				startX + (isGraphViewStale() ? staleGraphViewPanel.getBounds().width + 5 : 0);
			g2.drawString(message, textX, startY);

//			ImageIcon icon = ResourceManager.loadImage("images/dragon_head.png");
//			g2.drawImage(icon.getImage(), backgroundX, upperY, null);

			g2.setComposite(originalComposite);
		}

		@Override
		public boolean useTransform() {
			return false;
		}

		void setMessage(String message) {
			this.message = message;
		}
	}

	private class KeyForwardingKeyAdapter extends KeyAdapter {

		private final VisualizationViewer<V, E> viewer;
		private final VisualGraph<V, E> innerClassGraph;

		public KeyForwardingKeyAdapter(VisualGraph<V, E> g, VisualizationViewer<V, E> viewer) {
			this.innerClassGraph = g;
			this.viewer = viewer;
		}

		@Override
		public void keyPressed(KeyEvent e) {
			V focusedVertex = innerClassGraph.getFocusedVertex();
			if (focusedVertex == null) {
				return;
			}

			KeyBindingUtils.retargetEvent(focusedVertex.getComponent(), e);
			viewer.repaint();
		}

		@Override
		public void keyReleased(KeyEvent e) {
			V focusedVertex = innerClassGraph.getFocusedVertex();
			if (focusedVertex == null) {
				return;
			}

			KeyBindingUtils.retargetEvent(focusedVertex.getComponent(), e);
			viewer.repaint();
		}

		@Override
		public void keyTyped(KeyEvent e) {
			V focusedVertex = innerClassGraph.getFocusedVertex();
			if (focusedVertex == null) {
				return;
			}

			KeyBindingUtils.retargetEvent(focusedVertex.getComponent(), e);
			viewer.repaint();
		}
	}

	private class VertexPickingListener implements PickListener<V> {
		private final VisualGraph<V, E> innerClassGraph;

		public VertexPickingListener(VisualGraph<V, E> g) {
			this.innerClassGraph = g;
		}

		@Override
		public void verticesPicked(Set<V> vertices, EventSource source) {

			if (vertices.size() == 0) {
				innerClassGraph.clearSelectedVertices();
			}
			else if (vertices.size() == 1) {
				focusVertex(CollectionUtils.any(vertices), source);
			}
			else {
				innerClassGraph.setSelectedVertices(vertices);
			}

			getPathHighlighter().setFocusedVertex(graph.getFocusedVertex());
		}

		private void focusVertex(V vertex, EventSource source) {
			innerClassGraph.setVertexFocused(vertex, true);
			if (source == EventSource.INTERNAL) {
				// send the event out, as this vertex was focused by the API and not the user
				vertexFocusListener.ifPresent(l -> l.vertexFocused(vertex));
			}
		}
	}

	private class EdgePickingListener implements ItemListener {

		@Override
		public void itemStateChanged(ItemEvent e) {

			@SuppressWarnings("unchecked")
			E edge = (E) e.getItem();
			edge.setSelected(e.getStateChange() == ItemEvent.SELECTED);
		}

	}

	private class GraphChangeListener implements VisualGraphChangeListener<V, E> {

		@Override
		public void verticesRemoved(Iterable<V> vertices) {
			getPathHighlighter().clearEdgeCache();
		}

		@Override
		public void verticesAdded(Iterable<V> vertices) {
			getPathHighlighter().clearEdgeCache();
		}

		@Override
		public void edgesAdded(Iterable<E> edges) {
			getPathHighlighter().clearEdgeCache();
		}

		@Override
		public void edgesRemoved(Iterable<E> edges) {
			getPathHighlighter().clearEdgeCache();
		}
	}

	private class VertexClickMousePlugin extends AbstractGraphMousePlugin
			implements MouseListener, VisualGraphMousePlugin<V, E> {

		private V selectedVertex;

		public VertexClickMousePlugin() {
			super(InputEvent.BUTTON1_DOWN_MASK);
		}

		@Override
		public boolean checkModifiers(MouseEvent e) {
			return e.getModifiersEx() == modifiers;
		}

		@Override
		public void mousePressed(MouseEvent e) {

			if (!checkModifiers(e)) {
				return;
			}

			if (e.getClickCount() != 2) {
				return;
			}

			if (!onVertex(e)) {
				return; // no vertex clicked, nothing to do
			}

			GraphViewer<V, E> viewer = getGraphViewer(e);
			VertexMouseInfo<V, E> info =
				GraphViewerUtils.convertMouseEventToVertexMouseEvent(viewer, e);
			vertexClickListener.ifPresent(l -> {

				if (l.vertexDoubleClicked(selectedVertex, info)) {
					e.consume();
				}
			});
		}

		// overridden to not consume the event
		private boolean onVertex(MouseEvent e) {

			if (!checkModifiers(e)) {
				selectedVertex = null;
				return false;
			}

			VisualizationViewer<V, E> vv = getViewer(e);
			GraphElementAccessor<V, E> pickSupport = vv.getPickSupport();
			Layout<V, E> layout = vv.getGraphLayout();
			if (pickSupport == null) {
				return false;
			}

			// p is the screen point for the mouse event
			Point2D p = e.getPoint();
			selectedVertex = pickSupport.getVertex(layout, p.getX(), p.getY());
			if (selectedVertex == null) {
				return false;
			}

			return true;
		}

		@Override
		public void mouseClicked(MouseEvent e) {
			// stub
		}

		@Override
		public void mouseReleased(MouseEvent e) {
			// stub
		}

		@Override
		public void mouseEntered(MouseEvent e) {
			// stub
		}

		@Override
		public void mouseExited(MouseEvent e) {
			// stub
		}
	}
}
