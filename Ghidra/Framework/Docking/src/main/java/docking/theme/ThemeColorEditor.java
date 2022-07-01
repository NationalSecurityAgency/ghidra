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
package docking.theme;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.util.EventObject;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.table.TableCellEditor;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.options.editor.GhidraColorChooser;
import docking.widgets.label.GDLabel;

public class ThemeColorEditor extends AbstractCellEditor implements TableCellEditor {
	private GhidraColorChooser colorChooser;
	private Color lastUserSelectedColor;
	private Color color;

	private ColorDialogProvider dialog;
	private JTable table;
	private ColorValue colorValue;

	private GThemeValueMap values;
	private ThemeColorTableModel model;

	public ThemeColorEditor(GThemeValueMap values, ThemeColorTableModel model) {
		this.values = values;
		this.model = model;
	}

	@Override
	public Component getTableCellEditorComponent(JTable theTable, Object value, boolean isSelected,
			int row, int column) {

		this.table = theTable;
		colorValue = (ColorValue) value;

		JLabel label = new GDLabel();
		label.setBorder(BorderFactory.createBevelBorder(BevelBorder.LOWERED));
		label.setText(colorValue.getId());

		dialog = new ColorDialogProvider();
		dialog.setRememberSize(false);
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				DockingWindowManager.showDialog(dialog);
				stopCellEditing();
			}
		});

		return label;
	}

	@Override
	public void cancelCellEditing() {
		dialog.close();
	}

	@Override
	public Object getCellEditorValue() {
		return null;
	}

	@Override
	public boolean stopCellEditing() {
		ListSelectionModel columnSelectionModel = table.getColumnModel().getSelectionModel();
		columnSelectionModel.setValueIsAdjusting(true);
		int columnAnchor = columnSelectionModel.getAnchorSelectionIndex();
		int columnLead = columnSelectionModel.getLeadSelectionIndex();

		if (color != null) {
			Gui.setColor(colorValue.getId(), color);
			model.refresh();
		}
		dialog.close();
		fireEditingStopped();

		columnSelectionModel.setAnchorSelectionIndex(columnAnchor);
		columnSelectionModel.setLeadSelectionIndex(columnLead);
		columnSelectionModel.setValueIsAdjusting(false);

		return true;
	}

	// only double-click edits
	@Override
	public boolean isCellEditable(EventObject anEvent) {
		if (anEvent instanceof MouseEvent) {
			return ((MouseEvent) anEvent).getClickCount() >= 2;
		}
		return true;
	}

//==================================================================================================
// Inner Classes    
//==================================================================================================

	class ColorDialogProvider extends DialogComponentProvider {
		ColorDialogProvider() {
			super("Color Editor", true);

			addWorkPanel(new ColorEditorPanel());
			addOKButton();
			addCancelButton();
		}

		@Override
		protected void okCallback() {
			color = lastUserSelectedColor;
			close();
		}

		@Override
		protected void cancelCallback() {
			color = null;
			close();
		}
	}

	class ColorEditorPanel extends JPanel {

		ColorEditorPanel() {

			setLayout(new BorderLayout());

			if (colorChooser == null) {
				colorChooser = new GhidraColorChooser();
			}

			add(colorChooser, BorderLayout.CENTER);
			colorChooser.getSelectionModel().addChangeListener(new ChangeListener() {

				@Override
				public void stateChanged(ChangeEvent e) {
					lastUserSelectedColor = colorChooser.getColor();
					// This could be a ColorUIResource, but Options only support storing Color.
					lastUserSelectedColor =
						new Color(lastUserSelectedColor.getRed(), lastUserSelectedColor.getGreen(),
							lastUserSelectedColor.getBlue(), lastUserSelectedColor.getAlpha());
				}
			});
			colorChooser.setColor(colorValue.get(values));
		}
	}
}
