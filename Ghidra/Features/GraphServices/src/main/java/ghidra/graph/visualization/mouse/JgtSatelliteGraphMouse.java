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
package ghidra.graph.visualization.mouse;

import org.jungrapht.visualization.control.*;

import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedVertex;

// Note: if the jungrapht API changes to fix '// JUNGRAPHT CHANGE 1' and '2', then this class
//       can be removed
public class JgtSatelliteGraphMouse
		extends DefaultSatelliteGraphMouse<AttributedVertex, AttributedEdge> {

	@Override
	public void loadPlugins() {
		scalingPlugin =
			new SatelliteScalingGraphMousePlugin(
				new CrossoverScalingControl(),
				scalingMask,
				xAxisScalingMask,
				yAxisScalingMask,
				in,
				out);

		//
		// JUNGRAPHT CHANGE 3
		//
		// disable single selection in satellite view by setting masks to 0
		SelectingGraphMousePlugin<AttributedVertex, AttributedEdge> mySelectingPlugin =
			new JgtSelectingGraphMousePlugin(0, 0);
		mySelectingPlugin.setLocked(true);
		selectingPlugin = mySelectingPlugin;

		regionSelectingPlugin =
			RegionSelectingGraphMousePlugin.builder()
					.regionSelectionMask(regionSelectionMask)
					.toggleRegionSelectionMask(toggleRegionSelectionMask)
					.regionSelectionCompleteMask(regionSelectionCompleteMask)
					.toggleRegionSelectionCompleteMask(toggleRegionSelectionCompleteMask)
					.build();
		translatingPlugin = SatelliteTranslatingGraphMousePlugin.builder()
				.translatingMask(translatingMask).build();
		add(selectingPlugin);
		add(regionSelectingPlugin);
		add(translatingPlugin);
		add(scalingPlugin);
	}
}
