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
package ghidra.app.plugin.core.functiongraph.graph.jung.transformer;

import java.awt.Color;
import java.awt.Paint;

import com.google.common.base.Function;

import edu.uci.ics.jung.visualization.picking.PickedInfo;
import ghidra.app.plugin.core.functiongraph.graph.FGVertexType;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.program.util.ProgramSelection;

public class FGVertexPickableBackgroundPaintTransformer implements Function<FGVertex, Paint> {

	private final PickedInfo<FGVertex> info;
	private final Color pickedColor;
	private final Color entryColor;
	private final Color exitColor;
	private final Color pickedStartColor;
	private final Color pickedEndColor;

	private static Color mix(Color c1, Color c2) {
		return new Color((c1.getRed() + c2.getRed()) / 2, (c1.getGreen() + c2.getGreen()) / 2,
			(c1.getBlue() + c2.getBlue()) / 2);
	}

	public FGVertexPickableBackgroundPaintTransformer(PickedInfo<FGVertex> info, Color pickedColor,
			Color startColor, Color endColor) {

		if (info == null) {
			throw new IllegalArgumentException("PickedInfo instance must be non-null");
		}
		this.info = info;
		this.pickedColor = pickedColor;
		this.entryColor = startColor;
		this.exitColor = endColor;
		this.pickedStartColor = mix(pickedColor, startColor);
		this.pickedEndColor = mix(pickedColor, endColor);
	}

	@Override
	public Paint apply(FGVertex v) {
		Color backgroundColor = v.getBackgroundColor();

		ProgramSelection selection = v.getProgramSelection();
		if (!selection.isEmpty()) {
			// mix the colors so the user can see both the selection and the background color
			Color selectionColor = v.getSelectionColor();
			Color mixed = mix(selectionColor, backgroundColor);
			backgroundColor = mixed;
		}

		FGVertexType vertexType = v.getVertexType();
		if (info.isPicked(v)) {
			if (v.isDefaultBackgroundColor()) {
				if (vertexType.isEntry()) {
					return pickedStartColor;
				}
				if (vertexType.isExit()) {
					return pickedEndColor;
				}
				return pickedColor;
			}
			if (vertexType.isEntry()) {
				return pickedStartColor.darker();
			}
			if (vertexType.isExit()) {
				return pickedEndColor.darker();
			}
			return pickedColor.darker();
		}

		if (vertexType.isEntry()) {
			return entryColor;
		}
		if (vertexType.isExit()) {
			return exitColor;
		}
		return backgroundColor;
	}
}
