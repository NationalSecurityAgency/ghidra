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
import java.awt.event.MouseEvent;
import java.awt.event.MouseMotionListener;
import java.awt.geom.Point2D;
import java.util.function.Consumer;

import javax.swing.*;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.visualization.VisualizationViewer;
import edu.uci.ics.jung.visualization.picking.MultiPickedState;
import edu.uci.ics.jung.visualization.picking.PickedState;
import generic.util.WindowUtilities;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.edge.PathHighlightListener;
import ghidra.graph.viewer.edge.VisualGraphPathHighlighter;
import ghidra.graph.viewer.event.mouse.*;
import ghidra.graph.viewer.event.picking.GPickedState;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.graph.viewer.options.VisualGraphOptions;
import ghidra.graph.viewer.popup.*;
import ghidra.graph.viewer.renderer.VisualGraphRenderer;
import ghidra.util.layout.PairLayout;

/**
 * The base viewer for the Graph module.   This viewer provides methods for manipulating
 * the graph using the mouse.
 * 
 * <P>The viewer is currently an extension of the {@link VisualizationViewer} and as such it 
 * is accessed by much of the event handling subsystem, such as the mouse plugins, as well as 
 * the rendering system.
 * 
 * <P>Also, tooltips/popups for edges and vertices are handled by this class.
 * 
 * <P>This class creates a {@link VisualGraphViewUpdater} that perform graph transformations, 
 * such as panning the graph, with and without animation, as requested.
 * 
 * @param <V> the vertex type
 * @param <E> the edge type
 * 
 */
public class GraphViewer<V extends VisualVertex, E extends VisualEdge<V>>
		extends VisualizationViewer<V, E> {

	private GPickedState<V> gPickedState;

	private Consumer<GraphViewer<V, E>> initializedListener;

	private PopupRegulator<V, E> popupRegulator;
	private VertexTooltipProvider<V, E> vertexTooltipProvider = new DummyTooltipProvider();

	protected VisualGraphOptions vgOptions;

	private VisualGraphViewUpdater<V, E> viewUpdater;
	private VisualGraphPathHighlighter<V, E> pathHighlighter;

	public GraphViewer(VisualGraphLayout<V, E> layout, Dimension size) {
		super(layout, size);

		buildUpdater();

		// TODO how slow does this make painting?
		//Map<Key, Object> hints = getRenderingHints();
		//hints.put(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);

		setRenderer(new VisualGraphRenderer<>(layout.getEdgeLabelRenderer()));

		setGraphMouse(new VisualGraphPluggableGraphMouse<>());

		PickedState<V> pickedState = getPickedVertexState();
		gPickedState = new GPickedState<>((MultiPickedState<V>) pickedState);
		setPickedVertexState(gPickedState);

		popupRegulator = new PopupRegulator<>(new GraphViewerPopupSource());
	}

	private void buildUpdater() {
		viewUpdater = createViewUpdater();
		PathHighlightListener listener = hoverChange -> {
			if (hoverChange) {
				viewUpdater.animateEdgeHover();
			}
			else {
				repaint();
			}
		};
		pathHighlighter = createPathHighlighter(listener);

		//
		// The path highlighter is subordinate to the view updater in that the path highlighter
		// should not be running while the view updater is running jobs that can mutate the
		// graph.  To facilitate this, we are using these callbacks below.  We can create a more
		// uniformed interface if needed, but this setup is very simple and easy to follow.
		//
		// signal to the path updater to stop work while jobs may be mutating the graph
		viewUpdater.addJobScheduledListener(() -> pathHighlighter.stop());
		pathHighlighter.setWorkPauser(() -> viewUpdater.isMutatingGraph());
	}

	protected VisualGraphPathHighlighter<V, E> createPathHighlighter(
			PathHighlightListener listener) {
		return new VisualGraphPathHighlighter<>(getVisualGraph(), listener);
	}

	protected VisualGraphViewUpdater<V, E> createViewUpdater() {
		return new VisualGraphViewUpdater<>(this, getVisualGraph());
	}

	public VisualGraphLayout<V, E> getVisualGraphLayout() {
		return GraphViewerUtils.getVisualGraphLayout(getGraphLayout());
	}

	@Override
	public void setGraphLayout(Layout<V, E> layout) {
		if (!(layout instanceof VisualGraphLayout)) {
			throw new IllegalArgumentException(getClass().getSimpleName() + " only supports " +
				"layouts of type " + VisualGraphLayout.class.getSimpleName());
		}
		super.setGraphLayout(layout);
	}

	public VisualGraph<V, E> getVisualGraph() {
		VisualGraphLayout<V, E> l = getVisualGraphLayout();
		return l.getVisualGraph();
	}

	@SuppressWarnings("unchecked")
	@Override
	public VisualGraphPluggableGraphMouse<V, E> getGraphMouse() {
		return (VisualGraphPluggableGraphMouse<V, E>) super.getGraphMouse();
	}

	@Override
	public void setGraphMouse(GraphMouse graphMouse) {
		if (!(graphMouse instanceof VisualGraphPluggableGraphMouse)) {
			throw new IllegalArgumentException(
				"GraphViewer must use a VisualGraphPluggableGraphMouse");
		}
		super.setGraphMouse(graphMouse);
	}

	public void setGraphOptions(VisualGraphOptions options) {
		this.vgOptions = options;
		optionsChanged();
	}

	public void optionsChanged() {
		setBackground(vgOptions.getGraphBackgroundColor());
	}

	public VisualGraphOptions getOptions() {
		return vgOptions;
	}

	public void setVertexHoverPathHighlightMode(PathHighlightMode hoverMode) {
		pathHighlighter.setVertexHoverMode(hoverMode);
	}

	public void setVertexFocusPathHighlightMode(PathHighlightMode focusMode) {
		pathHighlighter.setVertexFocusMode(focusMode);
	}

	public PathHighlightMode getVertexHoverPathHighlightMode() {
		return pathHighlighter.getVertexHoverPathHighlightMode();
	}

	public PathHighlightMode getVertexFocusPathHighlightMode() {
		return pathHighlighter.getVertexFocusPathHighlightMode();
	}

	public void setViewerInitializedListener(Consumer<GraphViewer<V, E>> listener) {
		this.initializedListener = listener;
	}

	public VisualGraphPathHighlighter<V, E> getPathHighlighter() {
		return pathHighlighter;
	}

	public VisualGraphViewUpdater<V, E> getViewUpdater() {
		return viewUpdater;
	}

	public GPickedState<V> getGPickedVertexState() {
		PickedState<V> ps = super.getPickedVertexState();
		if (!(ps instanceof GPickedState)) {
			throw new IllegalArgumentException(
				"GPickedState was not installed or was overrwritten");
		}

		return (GPickedState<V>) ps;
	}

	public void setVertexTooltipProvider(VertexTooltipProvider<V, E> vertexTooltipProvider) {
		if (vertexTooltipProvider == null) {
			vertexTooltipProvider = new DummyTooltipProvider();
		}
		this.vertexTooltipProvider = vertexTooltipProvider;
	}

	/**
	 * When true (the default), the zoom will center wherever the mouse is positioned.  False 
	 * will zoom at the center of the view.
	 * 
	 * @return true if using mouse-relative zoom
	 */
	public boolean useMouseRelativeZoom() {
		return vgOptions.useMouseRelativeZoom();
	}

	/**
	 *                       !!Super Hacky Override!!
	 * The code we are overriding blindly calls add(), without first checking to see if it has
	 * already been added.  Java 6 added a method, removeNotify(), that is called when components
	 * are removed.  When add is called in the overridden method, it triggers a call to remove, 
	 * which triggers removeNotify().  This call is made during the painting process.  The problem
	 * therein is that out buttons borders get reset (see AbstractButton.removeNotify()) when
	 * we repaint, which means that mouse hovers do not work correctly (SCR 6819).
	 */
	@Override
	public Component add(Component comp) {
		if (SwingUtilities.isDescendingFrom(comp, this)) {
			return comp;
		}
		return super.add(comp);
	}

	/**
	 *                       !!Super Hacky Override!!
	 * This is done to make sure that we center the view when we are fully laid-out.  If
	 * you know of a better way to do this, then, get rid of this overridden method and do
	 * the good thing.
	 */
	@Override
	protected void paintComponent(Graphics g) {

		if (initializedListener != null) {
			initializedListener.accept(this);
			initializedListener = null;
		}
		super.paintComponent(g);
	}

	@Override
	public Point2D getCenter() {
		Dimension d = getSize();
		Container myParent = getParent();
		if (myParent != null) {
			// this fixes the issue of size not being correct before we've been laid out
			d = myParent.getSize();
		}

		return new Point2D.Float(d.width / 2, d.height / 2);
	}

	private boolean isScaledPastInteractionThreshold() {
		return GraphViewerUtils.isScaledPastVertexInteractionThreshold(this);
	}

//==================================================================================================
// Popups and Tooltips
//==================================================================================================	

	/*package*/ void setPopupDelay(int delayMs) {
		popupRegulator.setPopupDelay(delayMs);
	}

	public void setPopupsVisible(boolean visible) {
		popupRegulator.setPopupsVisible(visible);
	}

	/*package*/ boolean isPopupShowing() {
		return popupRegulator.isPopupShowing();
	}

	@Override
	public String getToolTipText(MouseEvent event) {
		return null; // no standard Java tooltips...we will handle later
	}

	private ToolTipInfo<?> getToolTipInfo(MouseEvent event) {
		Layout<V, E> viewerLayout = getGraphLayout();
		Point p = event.getPoint();

		// check for a vertex hit first, otherwise, we get edge hits when we are hovering 
		// over a vertex, due to how edges are interpreted as existing all the way to the 
		// center point of a vertex
		V vertex = getPickSupport().getVertex(viewerLayout, p.getX(), p.getY());
		if (vertex != null) {
			return new VertexToolTipInfo(vertex, event);
		}

		E edge = getPickSupport().getEdge(viewerLayout, p.getX(), p.getY());
		if (edge != null) {
			return new EdgeToolTipInfo(edge, event);
		}

		// no vertex or edge hit; just create a basic info that is essentially a null-object
		// placeholder to prevent NPEs
		return new VertexToolTipInfo(vertex, event);
	}

	public VertexMouseInfo<V, E> createVertexMouseInfo(MouseEvent e, V v,
			Point2D vertexBasedClickPoint) {
		return new VertexMouseInfo<>(e, v, vertexBasedClickPoint, this);
	}

	public void dispose() {

		viewUpdater.dispose();

		pathHighlighter.dispose();

		removeAll();
	}

	private GraphViewer<V, E> viewer() {
		return GraphViewer.this;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================     

	private class GraphViewerPopupSource implements PopupSource<V, E> {

		@Override
		public ToolTipInfo<?> getToolTipInfo(MouseEvent event) {
			return viewer().getToolTipInfo(event);
		}

		@Override
		public V getVertex(MouseEvent event) {
			Layout<V, E> viewerLayout = getGraphLayout();
			Point p = event.getPoint();
			return getPickSupport().getVertex(viewerLayout, p.getX(), p.getY());
		}

		@Override
		public E getEdge(MouseEvent event) {
			Layout<V, E> viewerLayout = getGraphLayout();
			Point p = event.getPoint();
			return getPickSupport().getEdge(viewerLayout, p.getX(), p.getY());
		}

		@Override
		public void addMouseMotionListener(MouseMotionListener l) {
			viewer().addMouseMotionListener(l);
		}

		@Override
		public void repaint() {
			viewer().repaint();
		}

		@Override
		public Window getPopupParent() {
			return WindowUtilities.windowForComponent(viewer());
		}

	}

	private class VertexToolTipInfo extends ToolTipInfo<V> {

		VertexToolTipInfo(V vertex, MouseEvent event) {
			super(event, vertex);
		}

		@Override
		public JComponent createToolTipComponent() {
			if (graphObject == null) {
				return null;
			}

			if (isScaledPastInteractionThreshold()) {
				return vertexTooltipProvider.getTooltip(graphObject);
			}

			VertexMouseInfo<V, E> mouseInfo =
				GraphViewerUtils.convertMouseEventToVertexMouseEvent(GraphViewer.this, event);
			MouseEvent translatedMouseEvent = mouseInfo.getTranslatedMouseEvent();
			String toolTip =
				vertexTooltipProvider.getTooltipText(graphObject, translatedMouseEvent);
			if (toolTip == null) {
				return null;
			}
			JToolTip jToolTip = new JToolTip();
			jToolTip.setTipText(toolTip);
			return jToolTip;
		}

		@Override
		protected void emphasize() {
			if (graphObject == null) {
				return;
			}

			// only add a tooltip emphasis when we are scaled to a small size (this prevents
			// odd vertex sizing behavior while the user is attempting to interact with the 
			// vertex)
			if (GraphViewerUtils.isScaledPastVertexInteractionThreshold(GraphViewer.this)) {
				graphObject.setEmphasis(.25);
			}
		}

		@Override
		public void deEmphasize() {
			if (graphObject == null) {
				return;
			}
			graphObject.setEmphasis(0);
		}
	}

	private class EdgeToolTipInfo extends ToolTipInfo<E> {

		EdgeToolTipInfo(E edge, MouseEvent event) {
			super(event, edge);
		}

		@Override
		public JComponent createToolTipComponent() {
			if (graphObject == null) {
				return null;
			}

			V start = graphObject.getStart();
			V end = graphObject.getEnd();

			JComponent startComponent = vertexTooltipProvider.getTooltip(start, graphObject);
			if (startComponent == null) {
				return null;
			}

			if (start == end) {
				// self-loop
				JComponent component = new JPanel(new BorderLayout());
				component.add(startComponent, BorderLayout.CENTER);
				return component;
			}

			JComponent endComponent = vertexTooltipProvider.getTooltip(end, graphObject);
			if (endComponent == null) {
				return null;
			}

			JComponent component = new JPanel(new PairLayout());
			component.add(startComponent);
			component.add(endComponent);
			return component;
		}

		@Override
		protected void emphasize() {
			if (graphObject == null) {
				return;
			}
			graphObject.setEmphasis(1);
		}

		@Override
		public void deEmphasize() {
			if (graphObject == null) {
				return;
			}
			graphObject.setEmphasis(0);
		}
	}

	private class DummyTooltipProvider implements VertexTooltipProvider<V, E> {
		@Override
		public JComponent getTooltip(V v) {
			return null;
		}

		@Override
		public String getTooltipText(V v, MouseEvent e) {
			return null;
		}

		@Override
		public JComponent getTooltip(V v, E e) {
			return null;
		}
	}
}
