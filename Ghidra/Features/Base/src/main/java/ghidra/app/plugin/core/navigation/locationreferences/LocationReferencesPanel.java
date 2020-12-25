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
package ghidra.app.plugin.core.navigation.locationreferences;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.MouseEvent;
import java.util.Collection;

import javax.swing.JPanel;
import javax.swing.ListSelectionModel;
import javax.swing.event.TableModelListener;

import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramSelection;
import ghidra.util.table.*;

/**
 * A panel that contains a table for displaying results of performing a search for references 
 * to a given location.
 */
public class LocationReferencesPanel extends JPanel {

	private LocationReferencesProvider locationReferencesProvider;
	private GhidraThreadedTablePanel<LocationReference> tablePanel;
	private LocationReferencesTableModel tableModel;
	private GhidraTable table;

	LocationReferencesPanel(LocationReferencesProvider locationReferencesProvider) {
		this.locationReferencesProvider = locationReferencesProvider;

		buildPanel();
	}

	private void buildPanel() {
		tableModel = new LocationReferencesTableModel(locationReferencesProvider);
		tablePanel = new GhidraThreadedTablePanel<>(tableModel, 250);
		table = tablePanel.getTable();
		table.setHTMLRenderingEnabled(true);
		table.setPreferredScrollableViewportSize(new Dimension(300, 120));
		table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

		setLayout(new BorderLayout(10, 10));

		PluginTool tool = locationReferencesProvider.getTool();
		GoToService goToService = tool.getService(GoToService.class);
		table.installNavigation(goToService, goToService.getDefaultNavigatable());

		GhidraTableFilterPanel<LocationReference> tableFilterPanel =
			new GhidraTableFilterPanel<>(table, tableModel);
		add(tablePanel, BorderLayout.CENTER);
		add(tableFilterPanel, BorderLayout.SOUTH);
	}

	Collection<Address> getReferenceAddresses() {
		return tableModel.getReferenceAddresses();
	}

	GhidraTable getTable() {
		return table;
	}

	ProgramSelection getSelection() {
		return table.getProgramSelection();
	}

	/**
	 * Causes the model to update the table.  This differs from {@link #reloadModel()} in that if
	 * there is data cached, then this call will use that cached data.
	 */
	void updateModel() {
		tableModel.reload();
	}

	/**
	 * Reloads the model of the table in this panel.  This differs from {@link #updateModel()} in
	 * that it forces any existing data to be thrown out.
	 */
	void reloadModel() {
		tableModel.fullReload();
	}

	void addTableModelListener(TableModelListener listener) {
		tableModel.addTableModelListener(listener);
	}

	boolean isInitialized() {
		return tableModel.isInitialized();
	}

	boolean selectRow(MouseEvent event) {
		return table.selectRow(event);
	}

	void dispose() {
		table.dispose();
	}
}
