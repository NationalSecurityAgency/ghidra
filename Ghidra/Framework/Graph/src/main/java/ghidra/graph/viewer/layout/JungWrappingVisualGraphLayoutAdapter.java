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
package ghidra.graph.viewer.layout;

import java.awt.Dimension;
import java.awt.Shape;
import java.awt.geom.Point2D;
import java.lang.ref.WeakReference;
import java.lang.reflect.Constructor;
import java.util.*;

import com.google.common.base.Function;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.visualization.renderers.BasicEdgeRenderer;
import edu.uci.ics.jung.visualization.renderers.Renderer.EdgeLabel;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;
import ghidra.graph.viewer.layout.LayoutListener.ChangeType;
import ghidra.graph.viewer.renderer.ArticulatedEdgeRenderer;
import ghidra.graph.viewer.shape.ArticulatedEdgeTransformer;
import ghidra.util.exception.AssertException;
import ghidra.util.task.TaskMonitor;

/**
 * A wrapper that allows for existing Jung layouts to be used inside of the Visual Graph system. 
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
//@formatter:off
public class JungWrappingVisualGraphLayoutAdapter<V extends VisualVertex, 
                                                  E extends VisualEdge<V>>

	implements VisualGraphLayout<V, E> {
//@formatter:on

	private ArticulatedEdgeTransformer<V, E> edgeShapeTransformer =
		new ArticulatedEdgeTransformer<>();
	private ArticulatedEdgeRenderer<V, E> edgeRenderer = new ArticulatedEdgeRenderer<>();

	private List<WeakReference<LayoutListener<V, E>>> listeners = new ArrayList<>();

	protected Layout<V, E> delegate;

	public JungWrappingVisualGraphLayoutAdapter(Layout<V, E> jungLayout) {
		this.delegate = jungLayout;
	}

	@Override
	public void initialize() {
		delegate.initialize();
	}

	@Override
	public void reset() {
		delegate.reset();
	}

	@Override
	public LayoutPositions<V, E> calculateLocations(VisualGraph<V, E> graph, TaskMonitor monitor) {

		Map<V, Point2D> vertexLocations = new HashMap<>();
		Collection<V> vertices = graph.getVertices();
		for (V v : vertices) {
			Point2D location = delegate.apply(v);
			vertexLocations.put(v, location);
		}

		Map<E, List<Point2D>> edgeErticulations = new HashMap<>();
		Collection<E> edges = graph.getEdges();
		for (E edge : edges) {
			List<Point2D> newArticulations = new ArrayList<>();
			edgeErticulations.put(edge, newArticulations);
		}

		return LayoutPositions.createNewPositions(vertexLocations, edgeErticulations);
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public JungWrappingVisualGraphLayoutAdapter cloneLayout(VisualGraph<V, E> newGraph) {

		Layout<V, E> newJungLayout = cloneJungLayout(newGraph);
		return new JungWrappingVisualGraphLayoutAdapter(newJungLayout);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	protected Layout<V, E> cloneJungLayout(VisualGraph<V, E> newGraph) {

		Class<? extends Layout> delegateClass = delegate.getClass();
		try {
			Constructor<? extends Layout> constructor = delegateClass.getConstructor(Graph.class);
			Layout layout = constructor.newInstance(newGraph);
			return layout;
		}
		catch (Exception e) {
			throw new RuntimeException("Unable to clone jung graph: " + delegate.getClass(), e);
		}
	}

	@Override
	public boolean usesEdgeArticulations() {
		return false;
	}

	@Override
	public void dispose() {
		listeners.clear();
	}

	@Override
	public Graph<V, E> getGraph() {
		return delegate.getGraph();
	}

	@Override
	public Dimension getSize() {
		return delegate.getSize();
	}

	@Override
	public boolean isLocked(V v) {
		return delegate.isLocked(v);
	}

	@Override
	public void lock(V v, boolean lock) {
		delegate.lock(v, lock);
	}

	@Override
	public void setGraph(Graph<V, E> graph) {
		delegate.setGraph(graph);
	}

	@Override
	public void setInitializer(Function<V, Point2D> t) {
		delegate.setInitializer(t);
	}

	@Override
	public void setSize(Dimension d) {
		delegate.setSize(d);
		syncVertexLocationsToLayout();
	}

	private void syncVertexLocationsToLayout() {
		Graph<V, E> g = getGraph();
		Collection<V> vertices = g.getVertices();
		for (V v : vertices) {
			v.setLocation(apply(v));
		}
	}

	@Override
	public Point2D apply(V v) {
		return delegate.apply(v);
	}

//==================================================================================================
// Default Edge Stuff
//==================================================================================================	
	@Override
	public BasicEdgeRenderer<V, E> getEdgeRenderer() {
		return edgeRenderer;
	}

	@Override
	public Function<E, Shape> getEdgeShapeTransformer() {
		return edgeShapeTransformer;
	}

	@Override
	public EdgeLabel<V, E> getEdgeLabelRenderer() {
		return null;
	}

//==================================================================================================
// Listener Stuff
//==================================================================================================

	@Override
	@SuppressWarnings("unchecked")
	public void addLayoutListener(LayoutListener<V, E> listener) {
		Class<? extends LayoutListener<V, E>> listenerClass =
			(Class<? extends LayoutListener<V, E>>) listener.getClass();
		if (listenerClass.isAnonymousClass()) {
			throw new AssertException("Cannot add anonymous listeners to a weak collection!");
		}
		listeners.add(new WeakReference<>(listener));
	}

	@Override
	public void removeLayoutListener(LayoutListener<V, E> listener) {
		Iterator<WeakReference<LayoutListener<V, E>>> iterator = listeners.iterator();
		for (; iterator.hasNext();) {
			WeakReference<LayoutListener<V, E>> reference = iterator.next();
			LayoutListener<V, E> layoutListener = reference.get();
			if (layoutListener == null) {
				iterator.remove();
			}

			if (layoutListener == listener) {
				iterator.remove();
			}
		}
	}

	private void fireVertexLocationChanged(V vertex, Point2D point, ChangeType type) {
		Iterator<WeakReference<LayoutListener<V, E>>> iterator = listeners.iterator();
		for (; iterator.hasNext();) {
			WeakReference<LayoutListener<V, E>> reference = iterator.next();
			LayoutListener<V, E> layoutListener = reference.get();
			if (layoutListener == null) {
				iterator.remove();
				continue;
			}

			layoutListener.vertexLocationChanged(vertex, point, type);
		}
	}

	@Override
	public void setLocation(V v, Point2D location) {
		delegate.setLocation(v, location);
		fireVertexLocationChanged(v, location, ChangeType.USER);
	}

	@Override
	public void setLocation(V v, Point2D location, ChangeType changeType) {
		delegate.setLocation(v, location);
		fireVertexLocationChanged(v, location, changeType);
	}

	@SuppressWarnings("unchecked")
	@Override
	public VisualGraph<V, E> getVisualGraph() {
		return (VisualGraph<V, E>) getGraph();
	}
}
