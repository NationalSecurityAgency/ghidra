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
package docking.widgets.table;

import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.util.function.Consumer;

import javax.swing.*;
import javax.swing.table.TableColumn;

public enum CellEditorUtils {
	;
	public static void onOneFocus(JComponent editorComponent, Runnable action) {
		FocusAdapter l = new FocusAdapter() {
			@Override
			public void focusGained(FocusEvent e) {
				action.run();
				editorComponent.removeFocusListener(this);
			}
		};
		editorComponent.addFocusListener(l);
	}

	public static <R> void installButton(JTable table, GTableFilterPanel<R> filterPanel,
			TableColumn column, Icon icon, int size, Consumer<R> action) {
		table.setRowHeight(size);
		column.setMaxWidth(size);
		column.setMinWidth(size);
		column.setCellRenderer(new IconButtonTableCellRenderer(icon, size));
		column.setCellEditor(new IconButtonTableCellEditor<>(filterPanel, icon, action));
	}
}
