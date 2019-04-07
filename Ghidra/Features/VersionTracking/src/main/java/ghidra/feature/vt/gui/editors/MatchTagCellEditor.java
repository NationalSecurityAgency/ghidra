/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.feature.vt.gui.editors;

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.util.SystemUtilities;

import java.awt.Component;
import java.awt.event.*;
import java.util.*;

import javax.swing.*;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableModel;

import docking.widgets.table.RowObjectTableModel;

public class MatchTagCellEditor extends AbstractCellEditor implements TableCellEditor {

	private MatchTagComboBox matchTagChoices;
	private JTable table;
	private final VTController controller;
	private VTMatchTag tag;

	public MatchTagCellEditor(VTController controller) {
		this.controller = controller;
	}

	@Override
	@SuppressWarnings("unchecked")
	public Component getTableCellEditorComponent(JTable theTable, Object value, boolean isSelected,
			int row, int column) {

		this.table = theTable;
		TableModel model = table.getModel();
		RowObjectTableModel<VTMatch> matchModel = (RowObjectTableModel<VTMatch>) model;
		VTMatch match = matchModel.getRowObject(row);
		List<VTMatch> matches = new ArrayList<VTMatch>();
		matches.add(match);
		VTSession session = controller.getSession();
		tag = match.getTag();
		matchTagChoices = new MatchTagComboBox(session, matches, theTable, tag);
		matchTagChoices.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				stopCellEditing();
			}
		});

		matchTagChoices.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				stopCellEditing();
			}
		});

		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				matchTagChoices.showPopup();
				matchTagChoices.requestFocus();
			}
		});

		return matchTagChoices;
	}

	@Override
	public void cancelCellEditing() {
		// nothing to do
	}

	@Override
	public Object getCellEditorValue() {
		return matchTagChoices.getText();
	}

	@Override
	public boolean stopCellEditing() {
		ListSelectionModel columnSelectionModel = table.getColumnModel().getSelectionModel();
		columnSelectionModel.setValueIsAdjusting(true);
		int columnAnchor = columnSelectionModel.getAnchorSelectionIndex();
		int columnLead = columnSelectionModel.getLeadSelectionIndex();

		VTMatchTag editedTag = (VTMatchTag) matchTagChoices.getSelectedItem();

		if (SystemUtilities.isEqual(editedTag, tag)) {
			fireEditingCanceled();
			return true;
		}

		tag = editedTag;

		matchTagChoices.apply();
		fireEditingStopped();

		columnSelectionModel.setAnchorSelectionIndex(columnAnchor);
		columnSelectionModel.setLeadSelectionIndex(columnLead);
		columnSelectionModel.setValueIsAdjusting(false);

		return true;
	}

	// only double-click edits
	@Override
	public boolean isCellEditable(EventObject anEvent) {
		if (controller.getSession() == null) {
			return false;
		}
		if (anEvent instanceof MouseEvent) {
			return ((MouseEvent) anEvent).getClickCount() >= 2;
		}
		return true;
	}
}
