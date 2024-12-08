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
package sarif.view;

import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.ComponentProvider;
import docking.action.DockingAction;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Program;
import ghidra.util.table.GhidraFilterTable;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import sarif.SarifController;
import sarif.handlers.SarifResultHandler;
import sarif.model.SarifColumnKey;
import sarif.model.SarifDataFrame;
import sarif.model.SarifResultsTableModelFactory;
import sarif.model.SarifResultsTableModelFactory.SarifResultsTableModel;

/**
 * Show the SARIF result as a table and build possible actions on the table
 *
 */
public class SarifResultsTableProvider extends ComponentProvider  {

	private JComponent component;
	public SarifResultsTableModel model;
	public GhidraFilterTable<Map<String, Object>> filterTable;
	public Program program;
	private Plugin plugin;
	private SarifController controller;

	public SarifResultsTableProvider(String description, Plugin plugin, SarifController controller, SarifDataFrame df) {
		super(plugin.getTool(), controller.getProgram().getName(), plugin.getName());
		this.plugin = plugin;
		this.controller = controller;
		this.program = controller.getProgram();
		SarifResultsTableModelFactory factory = new SarifResultsTableModelFactory(df.getColumns());
		this.model = factory.createModel(description, plugin.getTool(), program, df);
		this.component = buildPanel();
		filterTable.getTable().getSelectionModel().addListSelectionListener(e -> plugin.getTool().contextChanged(this));
		this.createActions();
		this.setTransient();
	}

	private JComponent buildPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		filterTable = new GhidraFilterTable<>(this.model);
		GhidraTable table = (GhidraTable) filterTable.getTable();

		GoToService goToService = this.getTool().getService(GoToService.class);
		table.installNavigation(plugin.getTool(), goToService.getDefaultNavigatable());
		table.setNavigateOnSelectionEnabled(true);
		panel.add(filterTable);
		return panel;
	}
	
	public void dispose() {
		filterTable.dispose();
		closeComponent();
	}

	public void closeComponent() {
		super.closeComponent();
		getController().removeProvider(this);
	}
	
	@Override
	public JComponent getComponent() {
		return component;
	}

	/**
	 * Columns are added to the table based on if they are required by the SARIF
	 * format or are a taxonomy that the SARIF file defines We "support" certain
	 * taxonomies here by if the names match adding additional context actions that
	 * can be performed
	 */
	public void createActions() {
		DockingAction selectionAction = new MakeProgramSelectionAction(this.plugin,
				(GhidraTable) filterTable.getTable());
		this.addLocalAction(selectionAction);
		Set<SarifResultHandler> resultHandlers = controller.getSarifResultHandlers();
		List<SarifColumnKey> columns = model.getDataFrame().getColumns();
		List<String> keyNames = new ArrayList<>();
		for (SarifColumnKey key : columns) {
			keyNames.add(key.getName());
		}
		for (SarifResultHandler handler : resultHandlers) {
			if (keyNames.contains(handler.getKey())) {
				if (handler.getActionName() != null) {
					this.addLocalAction(handler.createAction(this));
				}
			}		
		}
	}
	
	
	public int getIndex(String key) {
		List<SarifColumnKey> columns = model.getDataFrame().getColumns();
		for (SarifColumnKey c : columns) {
			if (c.getName().equals(key)) {
				columns.indexOf(c);
			}
		}
		return -1;
	}

	public Object getValue(int x, int y) {
		return model.getColumnValueForRow(model.getRowObject(x), y);
	}

	public Map<String, Object> getRow(int x) {
		return model.getRowObject(x);
	}
	
	public SarifController getController() {
		return controller;
	}

}
