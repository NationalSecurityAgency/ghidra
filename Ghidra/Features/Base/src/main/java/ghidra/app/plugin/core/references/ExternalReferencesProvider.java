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
package ghidra.app.plugin.core.references;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.ActionContext;
import docking.widgets.table.DefaultSortedTableModel;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.table.GhidraTable;

public class ExternalReferencesProvider extends ComponentProviderAdapter {
	private JPanel mainPanel;
	private ExternalNamesTableModel tableModel;
	private DefaultSortedTableModel sortedModel;
	private GhidraTable table;
	private Program program;

	private DomainObjectListener domainObjectListener = ev -> {
		if (isVisible()) {
			tableModel.updateTableData();
		}
	};

	private AddExternalReferenceNameAction addExternalAction;
	private DeleteExternalReferenceNameAction deleteExternalAction;
	private SetExternalNameAssociationAction setAssocationAction;
	private ClearExternalNameAssociationAction clearAssociationAction;

	public ExternalReferencesProvider(ReferencesPlugin plugin) {
		super(plugin.getTool(), "External Programs", plugin.getName());
		mainPanel = buildMainPanel();
		setHelpLocation(new HelpLocation("ReferencesPlugin", "ExternalNamesDialog"));
		addToTool();
		addExternalAction = new AddExternalReferenceNameAction(this);
		deleteExternalAction = new DeleteExternalReferenceNameAction(this);
		setAssocationAction = new SetExternalNameAssociationAction(this);
		clearAssociationAction = new ClearExternalNameAssociationAction(this);

		addLocalAction(addExternalAction);
		addLocalAction(setAssocationAction);
		addLocalAction(clearAssociationAction);
		addLocalAction(deleteExternalAction);
		updateActionEnablement();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	void setProgram(Program program) {
		if (this.program != null) {
			this.program.removeListener(domainObjectListener);
		}
		this.program = program;
		if (this.program != null) {
			this.program.addListener(domainObjectListener);
		}

		if (isVisible()) {
			tableModel.setProgram(program);
		}
		updateActionEnablement();
	}

	@Override
	public void componentHidden() {
		tableModel.setProgram(null);
	}

	@Override
	public void componentShown() {
		tableModel.setProgram(program);
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		return new ActionContext(this, table);
	}

	private JPanel buildMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		tableModel = new ExternalNamesTableModel(tool);

		sortedModel = new DefaultSortedTableModel(tableModel);
		sortedModel.sortByColumn(ExternalNamesTableModel.NAME_COL);
		table = new GhidraTable(sortedModel);

		InputMap inputMap = table.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
		KeyStroke enter = KeyStroke.getKeyStroke("ENTER");
		while (inputMap != null) {
			inputMap.remove(enter);
			inputMap = inputMap.getParent();
		}

		table.addKeyListener(new KeyAdapter() {
			@Override
			public void keyReleased(KeyEvent e) {
				int selectedRowCount = table.getSelectedRowCount();
				if (selectedRowCount != 1) {
					return;
				}

				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					int row = table.getSelectedRow();
					table.editCellAt(row, 0);
					Component editorComponent = table.getEditorComponent();
					if (editorComponent != null) {
						editorComponent.requestFocus();
					}
				}
			}
		});

		table.getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			updateActionEnablement();
		});

		JScrollPane sp = new JScrollPane(table);
		table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
		docking.ToolTipManager.sharedInstance().registerComponent(table);

		panel.add(sp, BorderLayout.CENTER);

//        addButton = new JButton("Add");
//        addButton.setMnemonic('A');
//        addButton.addActionListener(new ActionListener() {
//			public void actionPerformed(ActionEvent e) {
//				clearStatusText();
//				tableModel.addDefaultRow();
//			}
//        });
//        ToolTipManager.setToolTipText(addButton,
//        	"Link new External Program name to blank Ghidra Pathname");
//
//        clearButton = new JButton("Clear");
//		clearButton.setMnemonic('C');
//        clearButton.addActionListener(new ActionListener() {
//			public void actionPerformed(ActionEvent e) {
//				clear();
//			}
//        });
//        ToolTipManager.setToolTipText(clearButton, "Remove External Program Link");

//        editButton = new JButton("Edit");
//		editButton.setMnemonic('E');
//        editButton.addActionListener(new ActionListener() {
//			public void actionPerformed(ActionEvent e) {
//				editPathName();
//			}
//        });
//        ToolTipManager.setToolTipText(editButton, "Edit Ghidra Pathname");
//
//        addButton(addButton);
//        addButton(editButton);
//        addButton(clearButton);
//        enableButtons();

		return panel;
	}

	private void updateActionEnablement() {
		deleteExternalAction.setEnabled(table.getSelectedRowCount() > 0);
		clearAssociationAction.setEnabled(table.getSelectedRowCount() > 0);
		setAssocationAction.setEnabled(table.getSelectedRowCount() == 1);
		addExternalAction.setEnabled(program != null);
	}

	public Program getProgram() {
		return program;
	}

	public List<String> getSelectedExternalNames() {
		List<String> externalNames = new ArrayList<>();
		int[] selectedRows = table.getSelectedRows();
		for (int selectedRow : selectedRows) {
			int index = sortedModel.getSortedIndex(selectedRow);
			String externalName = (String) tableModel.getValueAt(index, 0);
			externalNames.add(externalName);
		}
		return externalNames;
	}

	@Override
	public PluginTool getTool() {
		return tool;
	}

	void dispose() {
		table.dispose();
	}
}
