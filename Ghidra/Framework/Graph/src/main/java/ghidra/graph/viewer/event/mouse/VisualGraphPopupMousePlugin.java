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

import javax.swing.JPopupMenu;

import edu.uci.ics.jung.visualization.VisualizationViewer;
import edu.uci.ics.jung.visualization.control.AbstractPopupGraphMousePlugin;

public class VisualGraphPopupMousePlugin<V, E> extends AbstractPopupGraphMousePlugin {

// TODO: don't need this class if the context works for the main graph/provider (may need this
	// for the satellite view if we want popups there
	@Override
	protected void handlePopup(MouseEvent e) {
		VisualizationViewer<V, E> viewer = getViewer(e);
//        GraphElementAccessor<V, E> pickSupport = viewer.getPickSupport();
//        PickedState<V> pickedVertexState = viewer.getPickedVertexState();
//        PickedState<E> pickedEdgeState = viewer.getPickedEdgeState();
//        
		JPopupMenu popup = new JPopupMenu();
		popup.show(viewer, e.getX(), e.getY());
	}

	@SuppressWarnings("unchecked")
	protected VisualizationViewer<V, E> getViewer(MouseEvent e) {
		VisualizationViewer<V, E> viewer = (VisualizationViewer<V, E>) e.getSource();
		return viewer;
	}
}
