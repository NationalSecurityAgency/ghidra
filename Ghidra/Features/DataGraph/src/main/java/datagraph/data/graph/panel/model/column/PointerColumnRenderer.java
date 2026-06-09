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

import java.awt.Component;

import javax.swing.Icon;

import docking.widgets.trable.DefaultGTrableCellRenderer;
import docking.widgets.trable.GTrable;
import resources.Icons;

/**
 * Renderer for the pointer icon column where the use can click to add vertices to the graph.
 */
public class PointerColumnRenderer extends DefaultGTrableCellRenderer<Boolean> {

	private static final Icon ICON = Icons.RIGHT_ICON;

	@Override
	public Component getCellRenderer(GTrable<?> trable, Boolean value, boolean isSelected,
			boolean hasFocus, int row, int column) {

		super.getCellRenderer(trable, null, isSelected, hasFocus, row, column);

		boolean isPointer = value;
		Icon icon = isPointer ? ICON : null;
		setIcon(icon);
		return this;
	}
}
