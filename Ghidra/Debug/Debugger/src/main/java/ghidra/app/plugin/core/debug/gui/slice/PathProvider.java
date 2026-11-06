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
package ghidra.app.plugin.core.debug.gui.slice;

import java.awt.BorderLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;

import javax.swing.*;

import docking.widgets.table.GTable;
import docking.widgets.table.GTableFilterPanel;
import ghidra.app.services.DebuggerListingService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.Address;

/**
 * Component provider for examining a path from root/seed to a selected node.
 */
public class PathProvider extends ComponentProviderAdapter {

	private final JPanel panel = new JPanel(new BorderLayout());
	private final GTable table;
	private final GTableFilterPanel<PathRow> filterPanel;

	public PathProvider(DebuggerTraceSlicePlugin plugin, List<PathRow> rows) {
		super(plugin.getTool(), "Path", plugin.getName());
		setTransient();

		PathTableModel tableModel = new PathTableModel(plugin.getTool(), rows);
		table = new GTable(tableModel);
		filterPanel = new GTableFilterPanel<PathRow>(table, tableModel);
		panel.add(new JScrollPane(table), BorderLayout.CENTER);
		panel.add(filterPanel, BorderLayout.SOUTH);

		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
					gotoSelected();
				}
			}
		});
		// TODO: Keyboard ENTER, too

		tool.addComponentProvider(this, false);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	void gotoSelected() {
		PathRow row = filterPanel.getSelectedItem();
		if (row == null) {
			return;
		}
		long snap = row.getSnap();
		Address address = row.getAddress();
		DebuggerTraceManagerService traceManager =
			tool.getService(DebuggerTraceManagerService.class);
		traceManager.activateSnap(snap);
		DebuggerListingService listingService = tool.getService(DebuggerListingService.class);
		if (address != null && !address.isRegisterAddress()) {
			listingService.goTo(address, true);
		}
	}
}
