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
package ghidra.graph.visualization;

import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import ghidra.util.layout.VerticalLayout;

/**
 * Extends DialogComponentProvider to make a dialog with buttons to activate/deactivate
 * filters on graph vertices and edges
 */
public class FilterDialog extends DialogComponentProvider {

	/**
	 * A title for the vertex filter section of the dialog
	 */
	private static final String VERTEX_TITLE = "Vertex Filters";

	/**
	 * A title for the edge filter section of the dialog
	 */
	private static final String EDGE_TITLE = "Edge Filters";

	/**
	 * A {@code List} (possibly empty) of filter buttons for vertices
	 */
	private final List<? extends AbstractButton> vertexButtons;

	/**
	 * A {@code List} (possibly empty) of filter buttons for edges
	 */
	List<? extends AbstractButton> edgeButtons;

	/**
	 * @param vertexButtons a {@code List} of {@code AbstractButton}s to filter vertices
	 * @param edgeButtons a {@code List} of {@code AbstractButton}s to filter edges
	 */
	public FilterDialog(List<? extends AbstractButton> vertexButtons,
			List<? extends AbstractButton> edgeButtons) {
		super("Filters", false);
		this.vertexButtons = vertexButtons;
		this.edgeButtons = edgeButtons;
		super.addWorkPanel(createPanel());
		setRememberSize(false);
		addDismissButton();
		setDefaultButton(dismissButton);
	}

	/**
	 * Create a layout-formatted JComponent holding 2 vertical lists
	 * of buttons, one list for vertex filter buttons and one list for
	 * edge filter buttons. Each list has a border and title.
	 * @return a formatted JComponent (container)
	 */
	JComponent createPanel() {
		JPanel panel = new JPanel(new VerticalLayout(10));

		if (!vertexButtons.isEmpty()) {
			JPanel vertexPanel = new JPanel(new VerticalLayout(5));
			vertexPanel.setBorder(BorderFactory.createTitledBorder(VERTEX_TITLE));
			vertexButtons.forEach(vertexPanel::add);
			panel.add(vertexPanel);
		}
		if (!edgeButtons.isEmpty()) {
			JPanel edgePanel = new JPanel(new VerticalLayout(5));
			edgePanel.setBorder(BorderFactory.createTitledBorder(EDGE_TITLE));
			edgeButtons.forEach(edgePanel::add);
			panel.add(edgePanel);
		}

		if (vertexButtons.isEmpty() && edgeButtons.isEmpty()) {

			JLabel label = new JLabel("No Filters available for this graph!");
			label.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
			panel.add(label);
		}
		return panel;
	}
}
