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
import java.util.function.Consumer;

import javax.swing.*;

import docking.widgets.PopupWindow;
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

	private PopupRegulator popupRegulator = new PopupRegulator();
	private PopupWindow popupWindow;
	private boolean showPopups = true;
	private VertexTooltipProvider<V, E> vertexTooltipProvider = new DummyTooltipProvider();

	protected VisualGraphOptions options;

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
		this.options = options;
	}

	public VisualGraphOptions getOptions() {
		return options;
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
		return options.useMouseRelativeZoom();
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

	public void setPopupsVisible(boolean visible) {
		this.showPopups = visible;
		if (!showPopups) {
			hidePopupTooltips();
		}
	}

	/*package*/ boolean isPopupShowing() {
		return popupWindow != null && popupWindow.isShowing();
	}

	private void hidePopupTooltips() {
		if (popupWindow != null && popupWindow.isShowing()) {
			popupWindow.hide();
			// don't call dispose, or we don't get our componentHidden() callback 
			// popupWindow.dispose();
		}
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

	private void showTooltip(ToolTipInfo<?> info) {
		JComponent tipComponent = info.getToolTipComponent();
		if (tipComponent == null) {
			return;
		}

		MouseEvent event = info.getMouseEvent();
		showPopupWindow(event, tipComponent);
	}

	private void showPopupWindow(MouseEvent event, JComponent component) {
		MenuSelectionManager menuManager = MenuSelectionManager.defaultManager();
		if (menuManager.getSelectedPath().length != 0) {
			return;
		}

		Window parentWindow = WindowUtilities.windowForComponent(this);
		popupWindow = new PopupWindow(parentWindow, component);

		popupWindow.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentShown(ComponentEvent e) {
				popupRegulator.popupShown();
			}

			@Override
			public void componentHidden(ComponentEvent e) {
				popupRegulator.popupHidden();
			}
		});

		popupWindow.showPopup(event);
	}

	public VertexMouseInfo<V, E> createVertexMouseInfo(MouseEvent e, V v,
			Point2D vertexBasedClickPoint) {
		return new VertexMouseInfo<>(e, v, vertexBasedClickPoint, this);
	}

	/*package*/ void setPopupDelay(int delayMs) {
		popupRegulator.setPopupDelay(delayMs);
	}

	public void dispose() {

		viewUpdater.dispose();

		pathHighlighter.dispose();

		removeAll();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================     

	private class PopupRegulator {
		private int popupDelay = 1000;

		/**
		 * We need this timer because the default mechanism for triggering popups doesn't 
		 * always work.  We use this timer in conjunction with a mouse motion listener to 
		 * get the results we want.
		 */
		private Timer popupTimer;
		private MouseEvent popupMouseEvent;

		/** the current target (vertex or edge) of a popup window */
		private Object nextPopupTarget;

		/** 
		 * This value is not null when the user moves the cursor over a target for which a 
		 * popup is already showing.  We use this value to prevent showing a popup multiple times
		 * while over a single node.
		 */
		private Object lastShownPopupTarget;

		/** The tooltip info used when showing the popup */
		private ToolTipInfo<?> currentToolTipInfo;

		PopupRegulator() {
			popupTimer = new Timer(popupDelay, e -> {
				if (isPopupShowing()) {
					return; // don't show any new popups while the user is perusing
				}
				showPopupForMouseEvent(popupMouseEvent);
			});

			popupTimer.setRepeats(false);

			addMouseMotionListener(new MouseMotionListener() {
				@Override
				public void mouseDragged(MouseEvent e) {
					hidePopupTooltips();
					popupTimer.stop();
					popupMouseEvent = null; // clear any queued popups
				}

				@Override
				public void mouseMoved(MouseEvent e) {
					popupMouseEvent = e;

					// this clears out the current last popup shown so that the user can 
					// move off and on a node to re-show the popup
					savePopupTarget(e);

					// make sure the popup gets triggered eventually
					popupTimer.restart();
				}
			});
		}

		void setPopupDelay(int delayMs) {
			popupTimer.stop();
			popupTimer.setDelay(delayMs);
			popupTimer.setInitialDelay(delayMs);
			popupDelay = delayMs;
		}

		private void showPopupForMouseEvent(MouseEvent event) {
			if (!showPopups) {
				return;
			}

			if (event == null) {
				return;
			}

			ToolTipInfo<?> toolTipInfo = getToolTipInfo(event);
			JComponent toolTipComponent = toolTipInfo.getToolTipComponent();
			boolean isCustomJavaTooltip = !(toolTipComponent instanceof JToolTip);
			if (lastShownPopupTarget == nextPopupTarget && isCustomJavaTooltip) {
				// 
				// Kinda Hacky:
				// We don't show repeated popups for the same item (the user has to move away
				// and then come back to re-show the popup).  However, one caveat to this is that
				// we do want to allow the user to see popups for the toolbar actions always.  So,
				// only return here if we have already shown a popup for the item *and* we are 
				// using a custom tooltip (which is used to show a vertex tooltip or an edge 
				// tooltip)
				return;
			}

			currentToolTipInfo = toolTipInfo;
			showTooltip(currentToolTipInfo);
		}

		void popupShown() {
			lastShownPopupTarget = nextPopupTarget;
			currentToolTipInfo.emphasize();
			repaint();
		}

		void popupHidden() {
			currentToolTipInfo.deEmphasize();
			repaint();
		}

		private void savePopupTarget(MouseEvent event) {
			nextPopupTarget = null;
			V vertex = getVertexForEvent(event);
			if (vertex != null) {
				nextPopupTarget = vertex;
			}
			else {
				E edge = getEdgeForEvent(event);
				nextPopupTarget = edge;
			}

			if (nextPopupTarget == null) {
				// We've moved off of a target. We will clear that last target so the user can
				// mouse off of a vertex and back on in order to trigger a new popup
				lastShownPopupTarget = null;
			}
		}

		private V getVertexForEvent(MouseEvent event) {
			Layout<V, E> viewerLayout = getGraphLayout();
			Point p = event.getPoint();
			return getPickSupport().getVertex(viewerLayout, p.getX(), p.getY());
		}

		private E getEdgeForEvent(MouseEvent event) {
			Layout<V, E> viewerLayout = getGraphLayout();
			Point p = event.getPoint();
			return getPickSupport().getEdge(viewerLayout, p.getX(), p.getY());
		}
	}

	/** Basic container object that knows how to generate tooltips */
	private abstract class ToolTipInfo<T> {
		protected final MouseEvent event;
		protected final T graphObject;
		private JComponent tooltipComponent;

		ToolTipInfo(MouseEvent event, T t) {
			this.event = event;
			this.graphObject = t;
			tooltipComponent = createToolTipComponent(t);
		}

		protected abstract JComponent createToolTipComponent(T t);

		protected abstract void emphasize();

		protected abstract void deEmphasize();

		MouseEvent getMouseEvent() {
			return event;
		}

		JComponent getToolTipComponent() {
			return tooltipComponent;
		}
	}

	private class VertexToolTipInfo extends ToolTipInfo<V> {

		VertexToolTipInfo(V vertex, MouseEvent event) {
			super(event, vertex);
		}

		@Override
		public JComponent createToolTipComponent(V vertex) {
			if (vertex == null) {
				return null;
			}

			if (isScaledPastInteractionThreshold()) {
				return vertexTooltipProvider.getTooltip(vertex);
			}

			VertexMouseInfo<V, E> mouseInfo =
				GraphViewerUtils.convertMouseEventToVertexMouseEvent(GraphViewer.this, event);
			MouseEvent translatedMouseEvent = mouseInfo.getTranslatedMouseEvent();
			String toolTip = vertexTooltipProvider.getTooltipText(vertex, translatedMouseEvent);
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
		public JComponent createToolTipComponent(E edge) {
			if (edge == null) {
				return null;
			}

			V start = edge.getStart();
			V end = edge.getEnd();

			JComponent startComponent = vertexTooltipProvider.getTooltip(start, edge);
			if (startComponent == null) {
				return null;
			}

			if (start == end) {
				// self-loop
				JComponent component = new JPanel(new BorderLayout());
				component.add(startComponent, BorderLayout.CENTER);
				return component;
			}

			JComponent endComponent = vertexTooltipProvider.getTooltip(end, edge);
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
