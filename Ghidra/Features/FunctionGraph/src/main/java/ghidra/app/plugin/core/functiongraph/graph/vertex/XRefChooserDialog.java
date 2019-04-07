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
package ghidra.app.plugin.core.functiongraph.graph.vertex;

import java.awt.BorderLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.util.table.*;
import ghidra.util.table.field.ReferenceEndpoint;

public class XRefChooserDialog extends DialogComponentProvider {

	private GhidraTable table;
	private GhidraTableFilterPanel<ReferenceEndpoint> filterPanel;

	private final Program program;
	private ServiceProvider serviceProvider;
	private List<Reference> references;

	public XRefChooserDialog(List<Reference> references, Program program,
			ServiceProvider serviceProvider) {
		super("Jump to XRef");
		this.references = references;
		this.program = program;
		this.serviceProvider = serviceProvider;

		setPreferredSize(400, 400);

		addOKButton();
		addCancelButton();
		addWorkPanel(createWorkPanel());

		setOkEnabled(false);
	}

	private JComponent createWorkPanel() {
		JPanel workPanel = new JPanel(new BorderLayout());

		ReferencesFromTableModel model =
			new ReferencesFromTableModel(references, serviceProvider, program);
		table = new GhidraTable(model);
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() < 2) {
					return;
				}

				int row = table.rowAtPoint(e.getPoint());
				if (row == -1) {
					return; // not sure if this can happen
				}

				okCallback();
			}
		});

		table.getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}

			setOkEnabled(table.getSelectedRow() != -1);
		});

		filterPanel = new GhidraTableFilterPanel<>(table, model);
		workPanel.add(new JScrollPane(table), BorderLayout.CENTER);
		workPanel.add(filterPanel, BorderLayout.SOUTH);
		return workPanel;
	}

	@Override
	protected void okCallback() {
		int selectedRow = table.getSelectedRow();
		if (selectedRow == -1) {
			setStatusText("You must make a selection or press Cancel");
			return;
		}

		close();
	}

	@Override
	public void close() {
		super.close();
		filterPanel.dispose();
	}

	@Override
	protected void cancelCallback() {
		table.clearSelection();
		close();
	}

	public Reference getSelectedReference() {
		int selectedRow = table.getSelectedRow();
		int modelRow = filterPanel.getModelRow(selectedRow);
		if (modelRow == -1) {
			return null;
		}

		return references.get(modelRow);
	}
}
