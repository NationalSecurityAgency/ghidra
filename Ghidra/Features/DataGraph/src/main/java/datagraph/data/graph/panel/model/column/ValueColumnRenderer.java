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
package datagraph.data.graph.panel.model.column;

import java.awt.Color;
import java.awt.Component;

import docking.widgets.trable.DefaultGTrableCellRenderer;
import docking.widgets.trable.GTrable;
import generic.theme.GColor;

/**
 * Column renderer for the values column. Used to change the foreground color for values.
 */
public class ValueColumnRenderer extends DefaultGTrableCellRenderer<String> {
	private Color valueColor = new GColor("color.fg.datagraph.value");

	@Override
	public Component getCellRenderer(GTrable<?> trable, String value, boolean isSelected,
			boolean hasFocus, int row, int column) {

		super.getCellRenderer(trable, value, isSelected, hasFocus, row, column);
		if (value.startsWith(" =") && !isSelected) {
			setForeground(valueColor);
		}
		return this;
	}
}
