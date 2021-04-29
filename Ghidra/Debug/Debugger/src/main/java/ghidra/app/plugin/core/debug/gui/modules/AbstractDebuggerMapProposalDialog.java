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
package ghidra.app.plugin.core.debug.gui.modules;

import java.awt.BorderLayout;
import java.util.Collection;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.table.EnumeratedColumnTableModel;
import docking.widgets.table.GTable;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.table.GhidraTableFilterPanel;

public abstract class AbstractDebuggerMapProposalDialog<R> extends DialogComponentProvider {

	protected final EnumeratedColumnTableModel<R> tableModel = createTableModel();
	protected GTable table;
	protected GhidraTableFilterPanel<R> filterPanel;

	private Collection<R> adjusted;

	protected AbstractDebuggerMapProposalDialog(String title) {
		super(title, true, true, true, false);
		populateComponents();
	}

	protected abstract EnumeratedColumnTableModel<R> createTableModel();

	protected void populateComponents() {
		JPanel panel = new JPanel(new BorderLayout());

		table = new GTable(tableModel);
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		panel.add(new JScrollPane(table));

		filterPanel = new GhidraTableFilterPanel<>(table, tableModel);
		panel.add(filterPanel, BorderLayout.SOUTH);

		addWorkPanel(panel);

		addOKButton();
		addCancelButton();

		createActions();
	}

	protected void removeEntry(R entry) {
		tableModel.delete(entry);
	}

	protected void createActions() {
		// Extension point
	}

	@Override
	protected void okCallback() {
		adjusted = tableModel.getModelData();
		close();
	}

	@Override
	protected void cancelCallback() {
		adjusted = null;
		close();
	}

	public Collection<R> getAdjusted() {
		return adjusted;
	}

	public Collection<R> adjustCollection(PluginTool tool, Collection<R> collection) {
		tableModel.clear();
		tableModel.addAll(collection);
		tool.showDialog(this);
		return getAdjusted();
	}
}
