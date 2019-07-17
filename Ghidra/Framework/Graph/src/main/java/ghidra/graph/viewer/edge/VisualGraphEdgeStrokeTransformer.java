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
package ghidra.graph.viewer.edge;

import java.awt.BasicStroke;
import java.awt.Stroke;

import com.google.common.base.Function;

import edu.uci.ics.jung.visualization.picking.PickedInfo;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;

public class VisualGraphEdgeStrokeTransformer<V extends VisualVertex, E extends VisualEdge<V>>
		implements Function<E, Stroke> {

	private static final Stroke BASIC_STROKE = new BasicStroke(1);
	private final Stroke HEAVY_STROKE;

	private final PickedInfo<E> pickedInfo;

	public VisualGraphEdgeStrokeTransformer(PickedInfo<E> pickedInfo, int pickedStrokeSize) {
		HEAVY_STROKE = new BasicStroke(pickedStrokeSize);
		this.pickedInfo = pickedInfo;
	}

	@Override
	public Stroke apply(E e) {
		if (pickedInfo.isPicked(e)) {
			return HEAVY_STROKE;
		}
		return BASIC_STROKE;
	}

}
