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
package ghidra.app.plugin.core.symtable;

import java.awt.BorderLayout;
import java.awt.Dimension;

import javax.swing.JPanel;
import javax.swing.ListSelectionModel;
import javax.swing.event.TableModelListener;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;

import ghidra.app.services.GoToService;
import ghidra.program.model.symbol.Reference;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraThreadedTablePanel;

/**
 * 
 * 
 */
class ReferencePanel extends JPanel {

	private ReferenceProvider referenceProvider;
	private GhidraTable refTable;
	private TableModelListener listener;
	private GhidraThreadedTablePanel<Reference> threadedTablePanel;

	ReferencePanel(ReferenceProvider provider, SymbolReferenceModel model, SymbolRenderer renderer,
			GoToService gotoService) {

		super(new BorderLayout());

		referenceProvider = provider;

		threadedTablePanel = new GhidraThreadedTablePanel<>(model);

		refTable = threadedTablePanel.getTable();
		refTable.setAutoLookupColumn(SymbolReferenceModel.LABEL_COL);
		refTable.setName("ReferenceTable");//used by JUnit...
		refTable.setPreferredScrollableViewportSize(new Dimension(250, 200));
		refTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		refTable.installNavigation(gotoService, gotoService.getDefaultNavigatable());

		this.listener = e -> referenceProvider.updateTitle();
		refTable.getModel().addTableModelListener(listener);

		for (int i = 0; i < refTable.getColumnCount(); i++) {
			TableColumn column = refTable.getColumnModel().getColumn(i);
			if (column.getModelIndex() == SymbolReferenceModel.LABEL_COL) {
				column.setCellRenderer(renderer);
			}
		}

		add(threadedTablePanel, BorderLayout.CENTER);
	}

	GhidraTable getTable() {
		return refTable;
	}

	void dispose() {
		TableModel model = refTable.getModel();
		model.removeTableModelListener(listener);
		threadedTablePanel.dispose();
		refTable.dispose();
		referenceProvider = null;
	}
}
