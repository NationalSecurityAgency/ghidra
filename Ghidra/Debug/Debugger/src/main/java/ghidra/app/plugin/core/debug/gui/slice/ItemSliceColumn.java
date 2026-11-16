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
package ghidra.app.plugin.core.debug.gui.slice;

import java.awt.Font;

import docking.widgets.gtreetable.GTreeTableCellRenderer;
import docking.widgets.gtreetable.GTreeTableModel.AbstractTreeColumn;
import docking.widgets.gtreetable.GTreeTableNode;

public class ItemSliceColumn extends AbstractTreeColumn<AbstractSliceNode> {
	protected class ItemTreeCellRenderer extends GTreeTableCellRenderer<GTreeTableNode> {
		public ItemTreeCellRenderer() {
			setHTMLRenderingEnabled(true);
		}

		@Override
		protected Font getDefaultFont() {
			return fixedWidthFont;
		}
	}

	private final GTreeTableCellRenderer<GTreeTableNode> renderer =
		new ItemTreeCellRenderer();

	@Override
	public String getColumnName() {
		return "Item";
	}

	@Override
	public GTreeTableCellRenderer<GTreeTableNode> getColumnRenderer() {
		return renderer;
	}
}
