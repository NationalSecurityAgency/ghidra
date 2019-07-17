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
package ghidra.feature.vt.gui.provider.matchtable;

import java.awt.Component;

import javax.swing.*;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.docking.settings.Settings;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.HTMLUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.table.column.AbstractGhidraColumnRenderer;
import resources.ResourceManager;

/**
 * This class provides a field renderer for version tracking tables. It is used for indicating 
 * if the source or destination address for a match has multiple labels. An icon gives a visual
 * clue that there is more than one label, since the source and destination label fields only 
 * indicate the primary label name for the match. The field also indicates the number of labels
 * at the match address. If there is one label or none then this field remains blank.
 */
public class MultipleLabelsRenderer extends AbstractGhidraColumnRenderer<Symbol[]> {

	public enum MultipleLabelsRendererType {
		SOURCE("source"), DESTINATION("destination");

		public final String displayString;

		/**
		 * Constructor for an enumerated type of a Multiple Labels Indicator renderer.
		 * @param displayString a displayable string that identifies which type of 
		 * MultipleLabelsRenderer.
		 */
		MultipleLabelsRendererType(String displayString) {
			this.displayString = displayString;
		}

		/**
		 * Gets the display string for this type.
		 * @return the type as a displayable string.
		 */
		String getDisplayString() {
			return displayString;
		}
	}

	private static final Icon MULTIPLE_LABELS_ICON =
		ResourceManager.loadImage("images/application_view_detail.png");
	private static final String SINGLE_NAME_TOOLTIP = "Doesn't have multiple labels.";
	// Uncomment the following if it is needed for the configure... method below.
//	private static final String MULTI_NAME_TOOLTIP =
//		"Has multiple labels. The number indicates how many."
//			+ " Labels can be viewed using the dual listing of Markup Items.";

	private MultipleLabelsRendererType type;

	/**
	 * Constructs the field renderer for indicating when there are multiple labels.
	 * @param type indicates whether this is a source or destination renderer
	 */
	public MultipleLabelsRenderer(MultipleLabelsRendererType type) {
		super();
		this.type = type;
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);

		Object value = data.getValue();
		JTable table = data.getTable();
		int row = data.getRowViewIndex();

		if (!(value instanceof Symbol[])) {
			throw new AssertException(
				"Incorrect column value for the match's multiple labels indicator column");
		}

		configureRendererForMultipleLabelsIndicator(table, row, renderer, (Symbol[]) value);

		return renderer;
	}

	private JLabel configureRendererForMultipleLabelsIndicator(JTable table, int row,
			JLabel renderer, Symbol[] symbols) {
		renderer.setText("");
		renderer.setHorizontalAlignment(CENTER);
		int labelCount = symbols.length;
		if (labelCount > 1) {
			renderer.setIcon(MULTIPLE_LABELS_ICON);
			renderer.setText("" + labelCount);

			// Set up the tooltip information.
			String displayString = type.getDisplayString();
			StringBuffer buffer = new StringBuffer();
			buffer.append("Has " + labelCount + " " + displayString +
				" labels. Labels can also be viewed using the dual listing of Markup Items.");
			buffer.append("\n");
			int displayCount = 0;
			for (Symbol symbol : symbols) {
				if (displayCount++ == 20) {
					// Only show first 20 names.
					buffer.append("\n...");
					break;
				}
				buffer.append("\n" + symbol.getName());
			}
			String text = buffer.toString();
			String htmlString = HTMLUtilities.toWrappedHTML(text);
			renderer.setToolTipText(htmlString);
			// If the following uses too much memory, then comment out the tooltip code above
			// and just use the MULTI_NAME_TOOLTIP instead of the htmlString.
//			renderer.setToolTipText(MULTI_NAME_TOOLTIP);
		}
		else {
			renderer.setIcon(null);
			renderer.setText("");
			renderer.setToolTipText(SINGLE_NAME_TOOLTIP);
		}

		return renderer;
	}

	private String asString(Symbol[] symbols) {

		int labelCount = symbols.length;
		if (labelCount > 1) {
			// Set up the tooltip information.
			String displayString = type.getDisplayString();
			StringBuffer buffer = new StringBuffer();
			buffer.append("Has " + labelCount + " " + displayString +
				" labels. Labels can also be viewed using the dual listing of Markup Items.");
			buffer.append("\n");
			int displayCount = 0;
			for (Symbol symbol : symbols) {
				if (displayCount++ == 20) {
					// Only show first 20 names.
					buffer.append("\n...");
					break;
				}
				buffer.append("\n" + symbol.getName());
			}
			String text = buffer.toString();
			return labelCount + " " + text;

		}
		return SINGLE_NAME_TOOLTIP;
	}

	@Override
	public String getFilterString(Symbol[] t, Settings settings) {
		return asString(t);
	}
}
