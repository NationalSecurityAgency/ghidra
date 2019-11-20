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
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import ghidra.util.HTMLUtilities;
import ghidra.util.table.GhidraTable;

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
		int nameCol = table.getColumnModel().getColumnIndex("Name");
		String tagName = (String)table.getValueAt(row, nameCol);
		FunctionTagTableModel model = (FunctionTagTableModel) table.getModel();
		FunctionTag tag = model.getTag(tagName);

		if (tag.getComment().isEmpty()) {
			return "no tooltip set";
		}

		return "<html>" + HTMLUtilities.escapeHTML(tag.getComment());		
	}
	
	/**
	 * We need to override the renderer for the following cases:
	 * <li>italicize tags that cannot be edited</li>
	 * <li>disable rows in the source table that have already been added to the selected function </li>
	 */
	@Override
	public TableCellRenderer getCellRenderer(int row, int col) {
	
		return new TableCellRenderer() {
			
			@Override
			public Component getTableCellRendererComponent(JTable table, Object value,
					boolean isSelected, boolean hasFocus, int row, int column) {
				
				DefaultTableCellRenderer renderer = new DefaultTableCellRenderer();
				Component c = renderer.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
						
				boolean enableRow = true;
				if (disable && function != null) {
					int nameCol = table.getColumnModel().getColumnIndex("Name");
					String nameVal = (String)table.getValueAt(row, nameCol);
					Set<FunctionTag> tags = function.getTags();
					enableRow = !tags.stream().anyMatch(t -> t.getName().equals(nameVal));
				}
				c.setEnabled(enableRow);
				
				switch (table.getColumnName(column)) {
					case "Count":
						break;
					case "Name":
						FunctionTagTableModel model = (FunctionTagTableModel) table.getModel();
						FunctionTag tag = model.getTag((String)value);
						if (tag instanceof FunctionTagTemp) {
							c.setFont(getFont().deriveFont(Font.ITALIC));
						}
						else {
							c.setFont(getFont().deriveFont(Font.PLAIN));
						}									
						break;
				}
				
				return c;
			}
		};
	}
}
