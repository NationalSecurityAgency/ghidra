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
package ghidra.app.plugin.core.equate;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.*;
import java.util.List;

import javax.swing.*;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableCellEditor;

import docking.ActionContext;
import docking.action.*;
import docking.action.builder.ActionBuilder;
import docking.widgets.label.GLabel;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.services.GoToService;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Equate;
import ghidra.util.HelpLocation;
import ghidra.util.UniversalID;
import ghidra.util.table.*;
import resources.Icons;

public class EquateTableProvider extends ComponentProviderAdapter {

	private EquateTablePlugin plugin;
	private GhidraTable equatesTable;
	private EquateTableModel equatesModel;
	private GhidraTable referencesTable;
	private EquateReferenceTableModel referencesModel;
	private DockingAction deleteAction;
	private JPanel mainPanel;

	private GhidraTableFilterPanel<Equate> equatesFilterPanel;

	EquateTableProvider(EquateTablePlugin plugin) {
		super(plugin.getTool(), "Equates Table", plugin.getName(), ProgramActionContext.class);

		setHelpLocation(new HelpLocation("EquatePlugin", "Equate Table"));
		this.plugin = plugin;
		mainPanel = createWorkPanel();
		addToTool();
		createActions();
	}

	@Override
	public void closeComponent() {
		super.closeComponent();
		plugin.componentClosed();
	}

	@Override
	public void componentShown() {
		plugin.componentShown();
		updateEquates();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		Program program = plugin.getProgram();
		if (program == null) {
			return null;
		}
		if (event != null) {
			if (event.getSource() == referencesTable) {
				return new ProgramActionContext(this, program, referencesTable);
			}
		}
		return new ProgramActionContext(this, program, equatesTable);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	void programOpened(Program program) {
		equatesModel.update();
		referencesModel.setEquate(null);
	}

	void programClosed() {
		equatesModel.update();
		referencesModel.setEquate(null);
	}

	void updateEquates() {
		// restore selection after update
		List<Equate> selectedItems = equatesFilterPanel.getSelectedItems();

		equatesModel.update();

		equatesFilterPanel.setSelectedItems(selectedItems);

		handleEquateTableSelection();
	}

	void showEquates() {
		tool.showComponentProvider(this, true);
	}

	void dispose() {
		removeFromTool();
		equatesFilterPanel.dispose();
		referencesTable.dispose();
	}

	GhidraTable getReferencesTable() {
		return referencesTable;
	}

	GhidraTable getEquatesTable() {
		return equatesTable;
	}

	private JPanel createWorkPanel() {

		equatesModel = new EquateTableModel(plugin);

		equatesTable = new GhidraTable(equatesModel);

		equatesTable.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					handleEquateTableSelection();
					e.consume();
				}
			}

			@Override
			public void keyReleased(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_UP || e.getKeyCode() == KeyEvent.VK_DOWN ||
					e.getKeyCode() == KeyEvent.VK_PAGE_UP ||
					e.getKeyCode() == KeyEvent.VK_PAGE_DOWN) {
					handleEquateTableSelection();
				}
			}
		});

		equatesTable.getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			handleEquateTableSelection();
		});

		equatesTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
		equatesTable.setPreferredScrollableViewportSize(new Dimension(350, 150));
		equatesTable.setRowSelectionAllowed(true);
		equatesTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

		equatesFilterPanel = new GhidraTableFilterPanel<>(equatesTable, equatesModel);

		JScrollPane equatesTablePane = new JScrollPane(equatesTable);

		JPanel equatesPanel = new JPanel(new BorderLayout());
		equatesPanel.add(new GLabel("Equates", SwingConstants.CENTER), BorderLayout.NORTH);
		equatesPanel.add(equatesTablePane, BorderLayout.CENTER);
		equatesPanel.add(equatesFilterPanel, BorderLayout.SOUTH);

		referencesModel = new EquateReferenceTableModel(plugin);

		referencesTable = new GhidraTable(referencesModel);

		referencesTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
		referencesTable.setPreferredScrollableViewportSize(new Dimension(250, 150));
		referencesTable.setRowSelectionAllowed(true);
		referencesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		GoToService goToService = tool.getService(GoToService.class);
		if (goToService != null) {
			referencesTable.installNavigation(goToService, goToService.getDefaultNavigatable());
		}

		JScrollPane referencesTablePane = new JScrollPane(referencesTable);

		JTableHeader referencesHeader = referencesTable.getTableHeader();
		referencesHeader.setUpdateTableInRealTime(true);

		JPanel referencesPanel = new JPanel(new BorderLayout());
		referencesPanel.add(new GLabel("References", SwingConstants.CENTER), "North");
		referencesPanel.add(referencesTablePane, "Center");

		JPanel workPanel = new JPanel(new BorderLayout());
		JSplitPane splitPane =
			new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, equatesPanel, referencesPanel);
		splitPane.setResizeWeight(0.5);
		workPanel.add(splitPane, BorderLayout.CENTER);

		return workPanel;
	}

	private void handleEquateTableSelection() {

		int[] rows = equatesTable.getSelectedRows();
		if (rows.length > 1) {
			referencesTable.clearSelection();
			referencesModel.setEquate(null);
			return;
		}

		Equate equate = equatesFilterPanel.getSelectedItem();
		referencesTable.clearSelection();
		referencesModel.setEquate(equate);
	}

	private void createActions() {

		//@formatter:off
		String group = "Popup Group";
		new ActionBuilder("Show Enum", plugin.getName())
			.popupMenuGroup(group)
			.popupMenuPath("Show Enum")
			.popupWhen(c -> true)
			.enabledWhen(c -> getEnum(getSelectedEquate()) != null)
			.onAction(c -> {
				DataTypeManagerService dtms = tool.getService(DataTypeManagerService.class);
				if (dtms != null) {
					dtms.setDataTypeSelected(getEnum(getSelectedEquate()));
				}
			})
			.helpLocation(new HelpLocation("EquatePlugin", "Show_Enum"))
			.buildAndInstallLocal(this);

		new ActionBuilder("Edit Enum", plugin.getName())
			.popupMenuGroup(group)
			.popupMenuPath("Edit Enum")
			.popupWhen(c -> true)
			.enabledWhen(c -> getEnum(getSelectedEquate()) != null)
			.onAction(c -> edit(getEnum(getSelectedEquate())))
			.helpLocation(new HelpLocation("EquatePlugin", "Edit_Enum"))
			.buildAndInstallLocal(this);

		//@formatter:on

		Icon deleteImage = Icons.DELETE_ICON;
		deleteAction = new DockingAction("Delete Equate", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				delete();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (context.getContextObject() == equatesTable) {
					return super.isEnabledForContext(context);
				}
				return false;
			}
		};

		deleteAction.setPopupMenuData(new MenuData(new String[] { "Delete" }, deleteImage));
		deleteAction.setToolBarData(new ToolBarData(deleteImage));
		deleteAction.setDescription("Delete an Equate");
		deleteAction.setHelpLocation(new HelpLocation("EquatePlugin", "Delete Equate"));

		SelectionNavigationAction selectionNavigationAction =
			new SelectionNavigationAction(plugin, referencesTable);
		selectionNavigationAction
				.setHelpLocation(new HelpLocation(HelpTopics.SEARCH, "Selection_Navigation"));

		tool.addLocalAction(this, deleteAction);
		tool.addLocalAction(this, selectionNavigationAction);
	}

	private Equate getSelectedEquate() {
		if (equatesTable.getSelectedRowCount() != 1) {
			return null;
		}

		return equatesFilterPanel.getSelectedItem();
	}

	private Enum getEnum(Equate equate) {
		if (equate == null) {
			return null;
		}

		if (!equate.isEnumBased()) {
			return null;
		}

		DataTypeManagerService dtms = tool.getService(DataTypeManagerService.class);
		if (dtms == null) {
			return null;
		}

		DataTypeManager dtm = plugin.getProgram().getDataTypeManager();
		UniversalID id = equate.getEnumUUID();
		Enum enoom = (Enum) dtm.findDataTypeForID(id);
		return enoom;
	}

	private void edit(Enum enoom) {
		DataTypeManagerService dtms = tool.getService(DataTypeManagerService.class);
		if (dtms != null) {
			dtms.edit(enoom);
		}
	}

	private void delete() {

		TableCellEditor cellEditor = equatesTable.getCellEditor();
		if (cellEditor != null) {
			cellEditor.stopCellEditing();
		}

		List<Equate> equates = equatesFilterPanel.getSelectedItems();
		plugin.deleteEquates(equates);
	}

	void setGoToService(GoToService service) {
		if (service != null) {
			referencesTable.installNavigation(service, service.getDefaultNavigatable());
		}
		else {
			referencesTable.removeNavigation();
		}
	}

	EquateTableModel getEquatesModel() {
		return equatesModel;
	}

	Program getProgram() {
		return plugin.getProgram();
	}
}
