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
import java.util.Objects;

import com.google.common.base.Function;

import edu.uci.ics.jung.visualization.picking.PickedInfo;
import generic.theme.Gui;
import ghidra.app.plugin.core.functiongraph.graph.FGVertexType;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.program.util.ProgramSelection;
import ghidra.util.ColorUtils;

public class FGVertexPickableBackgroundPaintTransformer implements Function<FGVertex, Paint> {

	private final PickedInfo<FGVertex> info;
	private final Color pickedColor;
	private final Color entryColor;
	private final Color exitColor;
	private final Color pickedEntryColor;
	private final Color pickedExitColor;

	private static Color mix(Color c1, Color c2) {
		return ColorUtils.blend(c1, c2, .5f);
	}

	public FGVertexPickableBackgroundPaintTransformer(PickedInfo<FGVertex> info, Color pickedColor,
			Color startColor, Color endColor) {

		this.info = Objects.requireNonNull(info);
		this.pickedColor = pickedColor;
		this.entryColor = startColor;
		this.exitColor = endColor;
		this.pickedEntryColor = mix(pickedColor, startColor);
		this.pickedExitColor = mix(pickedColor, endColor);
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
					return pickedEntryColor;
				}
				if (vertexType.isExit()) {
					return pickedExitColor;
				}
				return pickedColor;
			}
			if (vertexType.isEntry()) {
				// this is a vertex that has a non-default, user-defined color; making the value
				// darker() is meant to signal that the 'picked entry color' is on top of a vertex
				// that has another color underneath
				return Gui.darker(pickedEntryColor);
			}
			if (vertexType.isExit()) {
				// this is a vertex that has a non-default, user-defined color; making the value
				// darker() is meant to signal that the 'picked exit color' is on top of a vertex
				// that has another color underneath
				return Gui.darker(pickedExitColor);
			}

			// this is a vertex that has a non-default, user-defined color; making the value
			// darker() is meant to signal that the 'picked color' is on top of a vertex that has 
			// another color underneath
			Color mixed = mix(pickedColor, backgroundColor);
			return Gui.darker(mixed);
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
