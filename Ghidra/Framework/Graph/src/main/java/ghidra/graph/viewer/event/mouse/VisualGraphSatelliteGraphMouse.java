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

import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;

public class VisualGraphSatelliteGraphMouse<V extends VisualVertex, E extends VisualEdge<V>>
		extends VisualGraphPluggableGraphMouse<V, E> {

	@Override
	protected void addPlugins() {

		// This would allow for picking vertices/edges from the satellite.  Currently, this
		// seems like it would be confusing to allow this from the satellite, as that view is
		// more about fast panning.  This is still here as a reminder of how we could make that
		// work.
		//add(new VisualGraphAnimatedPickingGraphMousePlugin<V, E>()); // animate on double-click
		//add(new VisualGraphPickingGraphMousePlugin<V, E>());
		//add(new VisualGraphEdgeSelectionGraphMousePlugin<V, E>());

		add(new VisualGraphSatelliteTranslatingGraphMousePlugin<V, E>());

		// moving the view
		add(new VisualGraphSatelliteNavigationGraphMousePlugin<V, E>());

		// zooming and alternate mouse wheel operation--panning
		add(new VisualGraphSatelliteScalingGraphMousePlugin<V, E>());
		add(new VisualGraphScrollWheelPanningPlugin<V, E>());

		// cursor cleanup
		add(new VisualGraphCursorRestoringGraphMousePlugin<V, E>());
	}
}
