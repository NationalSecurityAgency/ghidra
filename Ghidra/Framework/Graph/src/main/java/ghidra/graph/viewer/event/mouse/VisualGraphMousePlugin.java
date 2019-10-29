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
package ghidra.graph.viewer.event.mouse;

import java.awt.event.MouseEvent;

import edu.uci.ics.jung.visualization.VisualizationViewer;
import edu.uci.ics.jung.visualization.control.PickingGraphMousePlugin;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.*;

/**
 * An interface to provide a common set of methods for classes that could not otherwise 
 * extend an abstract class.  This interface signals that the implementer is a {@link VisualGraph}
 * mouse plugin.
 * 
 * <P>Note: The implementors of this interface still use the deprecated 
 * {@link MouseEvent#getModifiers()} method, since many of those classes extends from 
 * 3rd-party classes that still use them, such as {@link PickingGraphMousePlugin}.   We will need
 * to update the library (if/when possible), or rewrite our code so that it does not use the 
 * old 3rd-party algorithms. 
 *
 * @param <V> the vertex
 * @param <E> the edge
 */
public interface VisualGraphMousePlugin<V extends VisualVertex, E extends VisualEdge<V>> {

	public default VisualizationViewer<V, E> getViewer(MouseEvent e) {
		GraphViewer<V, E> viewer = getGraphViewer(e);
		return viewer;
	}

	/**
	 * Returns the <b>primary/master</b> graph viewer.
	 * 
	 * @param e the mouse event from which to get the viewer
	 * @return the viewer
	 */
	@SuppressWarnings("unchecked")
	public default GraphViewer<V, E> getGraphViewer(MouseEvent e) {
		VisualizationViewer<V, E> viewer = (VisualizationViewer<V, E>) e.getSource();

		// is this the satellite viewer? 
		if (viewer instanceof SatelliteGraphViewer) {
			return (GraphViewer<V, E>) ((SatelliteGraphViewer<V, E>) viewer).getMaster();
		}

		if (viewer instanceof GraphViewer) {
			GraphViewer<V, E> graphViewer = (GraphViewer<V, E>) viewer;
			return graphViewer;
		}

		throw new IllegalStateException("Do not have a master or satellite GraphViewer");
	}

	/**
	 * Returns the satellite graph viewer.  This assumes that the mouse event originated from 
	 * the satellite viewer.
	 * 
	 * @param e the mouse event from which to get the viewer
	 * @return the viewer
	 */
	@SuppressWarnings("unchecked")
	public default SatelliteGraphViewer<V, E> getSatelliteGraphViewer(MouseEvent e) {

		VisualizationViewer<V, E> viewer = (VisualizationViewer<V, E>) e.getSource();

		// is this the satellite viewer? 
		if (viewer instanceof SatelliteGraphViewer) {
			return (SatelliteGraphViewer<V, E>) viewer;
		}

		throw new IllegalStateException("Do not have a satellite GraphViewer");
	}

	/**
	 * Returns the updater that is used to modify the primary graph viewer.
	 * 
	 * @param e the mouse event from which to get the viewer
	 * @return the updater
	 */
	public default VisualGraphViewUpdater<V, E> getViewUpdater(MouseEvent e) {
		GraphViewer<V, E> viewer = getGraphViewer(e);
		VisualGraphViewUpdater<V, E> updater = viewer.getViewUpdater();
		return updater;
	}

	/**
	 * Returns the updater that is used to modify the primary graph viewer.
	 * 
	 * @param viewer the viewer
	 * @return the updater
	 */
	public default VisualGraphViewUpdater<V, E> getViewUpdater(GraphViewer<V, E> viewer) {
		VisualGraphViewUpdater<V, E> updater = viewer.getViewUpdater();
		return updater;
	}

	/**
	 * Signals to perform any cleanup when this plugin is going away
	 */
	public default void dispose() {
		// stub
	}
}
