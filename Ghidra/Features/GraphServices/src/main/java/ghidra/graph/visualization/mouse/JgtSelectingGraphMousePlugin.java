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

import java.awt.Graphics;
import java.awt.event.MouseEvent;
import java.awt.geom.Point2D;

import org.jungrapht.visualization.VisualizationServer;
import org.jungrapht.visualization.VisualizationServer.Paintable;
import org.jungrapht.visualization.control.GraphElementAccessor;
import org.jungrapht.visualization.control.SelectingGraphMousePlugin;
import org.jungrapht.visualization.layout.model.LayoutModel;
import org.jungrapht.visualization.selection.MutableSelectedState;
import org.jungrapht.visualization.selection.ShapePickSupport;

import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedVertex;

public class JgtSelectingGraphMousePlugin
		extends SelectingGraphMousePlugin<AttributedVertex, AttributedEdge> {

	private Paintable dummyPickFootprintPaintable = new Paintable() {
		@Override
		public void paint(Graphics g) {
			// stub
		}

		@Override
		public boolean useTransform() {
			return false;
		}
	};

	JgtSelectingGraphMousePlugin() {
		super();

		//
		// JUNGRAPHT CHANGE 1
		// turn off painting of the picking square
		this.pickFootprintPaintable = dummyPickFootprintPaintable;
	}

	public JgtSelectingGraphMousePlugin(int singleSelectionMask, int toggleSingleSelectionMask) {
		super(SelectingGraphMousePlugin.<AttributedVertex, AttributedEdge>builder()
						.singleSelectionMask(singleSelectionMask)
						.toggleSingleSelectionMask(toggleSingleSelectionMask));

		//
		// JUNGRAPHT CHANGE 1
		// turn off painting of the picking square
		this.pickFootprintPaintable = dummyPickFootprintPaintable;
	}

	// JUNGRAPHT CHANGE 2
	@Override
	protected boolean singleVertexSelection(
			MouseEvent e, Point2D layoutPoint, boolean addToSelection) {
		VisualizationServer<AttributedVertex, AttributedEdge> vv =
			(VisualizationServer<AttributedVertex, AttributedEdge>) e.getSource();
		GraphElementAccessor<AttributedVertex, AttributedEdge> pickSupport =
			vv.getPickSupport();
		MutableSelectedState<AttributedVertex> selectedVertexState =
			vv.getSelectedVertexState();
		LayoutModel<AttributedVertex> layoutModel = vv.getVisualizationModel().getLayoutModel();
		if (pickSupport instanceof ShapePickSupport) {
			ShapePickSupport<AttributedVertex, AttributedEdge> shapePickSupport =
				(ShapePickSupport<AttributedVertex, AttributedEdge>) pickSupport;
			vertex = shapePickSupport.getVertex(layoutModel, footprintRectangle);
		}
		else {
			vertex = pickSupport.getVertex(layoutModel, layoutPoint.getX(), layoutPoint.getY());
		}

		if (vertex != null) {
			if (!selectedVertexState.isSelected(vertex)) {
				if (!addToSelection) {
					selectedVertexState.clear();
				}
				selectedVertexState.select(vertex);
			}
			else {
				// If this vertex is still around in mouseReleased, it will be deselected
				// If this vertex was pressed again in order to drag it, it will be set
				// to null in the mouseDragged method

				//
				// JUNGRAPHT CHANGE 2 HERE
				//					
			}
			e.consume();
			return true;
		}
		return false;
	}
}
