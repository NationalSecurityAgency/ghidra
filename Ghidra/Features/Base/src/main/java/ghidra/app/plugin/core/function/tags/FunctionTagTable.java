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
package ghidra.app.plugin.core.function.tags;

import java.awt.Component;
import java.awt.Font;
import java.awt.event.MouseEvent;
import java.util.Set;

import javax.swing.JTable;
import javax.swing.table.TableCellRenderer;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import ghidra.util.HTMLUtilities;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableCellRenderer;

/**
 * Table that displays function tags and a count of the number of times
 * each tag has been used
 */
public class FunctionTagTable extends GhidraTable {

	/** 
	 * If true, disable any rows that have already been assigned 
	 * to a function (and thus cannot be added again)
	 */
	private boolean disable = false;

	/** The selected function */
	private Function function = null;

	private TagRenderer renderer = new TagRenderer();

	/**
	 * Constructor
	 * 
	 * @param model the table model
	 */
	public FunctionTagTable(FunctionTagTableModel model) {
		super(model);
	}

	protected void setDisabled(boolean disable) {
		this.disable = disable;
	}

	public void setFunction(Function function) {
		this.function = function;
	}

	@Override
	public String getToolTipText(MouseEvent evt) {
		FunctionTagTable table = (FunctionTagTable) evt.getSource();
		int row = this.rowAtPoint(evt.getPoint());
		FunctionTagTableModel model = (FunctionTagTableModel) table.getModel();
		FunctionTagRowObject rowObject = model.getRowObject(row);
		String comment = rowObject.getComment();
		if (comment.isEmpty()) {
			return "no tooltip set";
		}

		return "<html>" + HTMLUtilities.escapeHTML(comment);
	}

	/**
	 * We need to override the renderer for the following cases:
	 * <li>italicize tags that cannot be edited</li>
	 * <li>disable rows in the source table that have already been added to the selected function </li>
	 */
	@Override
	public TableCellRenderer getCellRenderer(int row, int col) {
		return renderer;
	}

	private class TagRenderer extends GhidraTableCellRenderer {

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			Component c = super.getTableCellRendererComponent(data);

			JTable table = data.getTable();
			int nameColumn = table.getColumnModel().getColumnIndex("Name");

			int row = data.getRowViewIndex();
			FunctionTagTableModel model = (FunctionTagTableModel) table.getModel();
			FunctionTagRowObject rowObject = model.getRowObject(row);

			boolean enableRow = true;
			if (disable && function != null) {
				String tagName = rowObject.getName();
				Set<FunctionTag> tags = function.getTags();
				enableRow = !tags.stream().anyMatch(t -> t.getName().equals(tagName));
			}
			c.setEnabled(enableRow);

			c.setFont(getFont().deriveFont(Font.PLAIN));

			int column = data.getColumnViewIndex();
			if (column == nameColumn) {
				if (rowObject.isImmutable()) {
					c.setFont(getFont().deriveFont(Font.ITALIC));
				}
			}

			return c;
		}
	}
}
