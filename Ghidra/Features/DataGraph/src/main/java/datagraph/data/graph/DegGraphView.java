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
package datagraph.data.graph;

import java.awt.event.MouseEvent;

import javax.swing.JComponent;

import ghidra.graph.viewer.GraphViewer;
import ghidra.graph.viewer.VisualGraphView;
import ghidra.graph.viewer.event.mouse.VertexTooltipProvider;

/**
 * Extends the VisualGraphView mainly to provide appropriate tool tips.
 */
public class DegGraphView extends VisualGraphView<DegVertex, DegEdge, DataExplorationGraph> {
	DegGraphView() {
		super();
		setSatelliteVisible(false);
	}

	@Override
	protected void installGraphViewer() {
		super.installGraphViewer();
		GraphViewer<DegVertex, DegEdge> viewer = graphComponent.getPrimaryViewer();
		viewer.setVertexTooltipProvider(new DataGraphVertexTipProvider());
	}

	private class DataGraphVertexTipProvider implements VertexTooltipProvider<DegVertex, DegEdge> {

		@Override
		public JComponent getTooltip(DegVertex v) {
			return null;
		}

		@Override
		public JComponent getTooltip(DegVertex v, DegEdge e) {
			return null;
		}

		@Override
		public String getTooltipText(DegVertex v, MouseEvent e) {
			return v.getTooltip(e);
		}

	}
}
