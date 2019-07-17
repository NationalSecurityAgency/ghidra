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
package ghidra.examples2;

import java.awt.BorderLayout;

import javax.swing.*;

import docking.widgets.table.GFilterTable;
import ghidra.app.services.GoToService;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.util.table.GhidraFilterTable;
import ghidra.util.table.GhidraTable;

public class SampleSearchTableProvider extends ComponentProviderAdapter
		implements OptionsChangeListener {

	private SampleSearchTablePlugin plugin;

	private JComponent component;
	private GFilterTable<SearchResults> filterTable;
	private SampleSearchTableModel model;

	public SampleSearchTableProvider(SampleSearchTablePlugin plugin, SampleSearcher searcher) {
		super(plugin.getTool(), "Sample Table Provider", plugin.getName());
		this.plugin = plugin;
		component = build(searcher);
		setTransient();
//		createActions();
	}

	private JComponent build(SampleSearcher searcher) {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));

		model = new SampleSearchTableModel(searcher, plugin.getTool());
		filterTable = new GhidraFilterTable<>(model);
		GhidraTable table = ((GhidraTable) filterTable.getTable());

		GoToService goToService = tool.getService(GoToService.class);
		if (goToService != null) {
			table.installNavigation(goToService, goToService.getDefaultNavigatable());
		}
		table.setNavigateOnSelectionEnabled(true);
		panel.add(filterTable);

		return panel;
	}

	public void dispose() {
		filterTable.dispose();
		filterTable.getTable().dispose();
		removeFromTool();
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		// TODO Auto-generated method stub

	}

}
