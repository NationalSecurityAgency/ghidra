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
package ghidra.graph.viewer.renderer;

import java.awt.*;

import javax.swing.JComponent;

import edu.uci.ics.jung.visualization.renderers.DefaultEdgeLabelRenderer;

/**
 * Overrides the {@link DefaultEdgeLabelRenderer} so that the client can set the non-picked
 * foreground color.  See {@link #setNonPickedForegroundColor(Color)}.
 */
public class VisualGraphEdgeLabelRenderer extends DefaultEdgeLabelRenderer {

	private Color nonPickedForegroundColor;

	public VisualGraphEdgeLabelRenderer(Color pickedColor) {
		super(pickedColor);
	}

	@Override
	public <E> Component getEdgeLabelRendererComponent(JComponent vv, Object value, Font font,
			boolean isSelected, E edge) {

		super.getEdgeLabelRendererComponent(vv, value, font, isSelected, edge);

		// fixup the parent call to use this label's foreground
		if (!isSelected) {
			setForeground(nonPickedForegroundColor);
		}

		return this;
	}

	/**
	 * Sets the foreground color for this renderer when the edge is not picked/selected
	 * 
	 * @param color the color
	 */
	public void setNonPickedForegroundColor(Color color) {
		this.nonPickedForegroundColor = color;
	}
}
