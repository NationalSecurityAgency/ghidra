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
package ghidra.app.plugin.core.debug.gui.objects.components;

import static ghidra.app.plugin.core.debug.gui.DebuggerResources.GROUP_GENERAL;
import static ghidra.app.plugin.core.debug.gui.DebuggerResources.tableRowActivationAction;

import java.awt.BorderLayout;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.ToolBarData;
import docking.widgets.table.*;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractAttachAction;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractRefreshAction;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsPlugin;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.target.*;
import ghidra.util.MessageType;
import ghidra.util.Msg;
import ghidra.util.table.GhidraTableFilterPanel;

public class DebuggerAttachDialog extends DialogComponentProvider {

	protected class RefreshAction extends AbstractRefreshAction {
		public static final String GROUP = GROUP_GENERAL;

		public RefreshAction() {
			super(plugin);
			setToolBarData(new ToolBarData(ICON, GROUP));
			addAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			fetchAndDisplayAttachable();
		}
	}

	private final DebuggerObjectsPlugin plugin;
	private final DebuggerObjectsProvider provider;

	protected RefreshAction actionRefresh;
	protected JButton attachButton;

	private final RowObjectTableModel<TargetAttachable> processes =
		new DefaultEnumeratedColumnTableModel<>("Attachables",
			AttachableProcessesTableColumns.class);
	protected TargetAttacher attacher;
	private GTable processTable;

	public DebuggerAttachDialog(DebuggerObjectsProvider provider) {
		super(AbstractAttachAction.NAME, true, true, true, false);
		this.provider = provider;
		this.plugin = provider.getPlugin();

		populateComponents();
		createActions();
	}

	protected void populateComponents() {
		// TODO: Lost connection seems to cause stale tree and NPEs
		// TODO: Detached process causes stale tree and NPEs
		// TODO:    Looks like error is in GDB wrapper. Need tests for removed threads
		JPanel panel = new JPanel(new BorderLayout());

		processTable = new GTable(processes);
		processTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		panel.add(new JScrollPane(processTable));
		processTable.setAutoLookupColumn(AttachableProcessesTableColumns.NAME.ordinal());

		GhidraTableFilterPanel<TargetAttachable> filterPanel =
			new GhidraTableFilterPanel<>(processTable, processes);
		panel.add(filterPanel, BorderLayout.SOUTH);

		addWorkPanel(panel);

		processTable.getColumn(AttachableProcessesTableColumns.ID.getHeader()).setPreferredWidth(8);
		processTable.getColumn(AttachableProcessesTableColumns.NAME.getHeader())
				.setPreferredWidth(16);

		attachButton = new JButton();
		AbstractAttachAction.styleButton(attachButton);
		attachButton.setToolTipText("Attach to the selected target");
		attachButton.addActionListener(e -> this.attach());
		tableRowActivationAction(processTable, () -> this.attach());
		addButton(attachButton);

		addCancelButton();
	}

	protected void createActions() {
		actionRefresh = new RefreshAction();
	}

	protected void attach() {
		TargetAttachable proc = processes.getRowObject(processTable.getSelectedRow());
		if (proc == null) {
			return;
		}
		setStatusText("Attaching");
		attacher.attach(proc).thenAccept(__ -> {
			close();
		}).exceptionally(e -> {
			Msg.showError(this, getComponent(), "Could not attach", e);
			setStatusText("Could not attach: " + e.getMessage(), MessageType.ERROR);
			return null;
		});
	}

	public void fetchAndDisplayAttachable() {
		AtomicReference<TargetObject> available = new AtomicReference<>();
		AtomicReference<Map<String, ? extends TargetObject>> procs = new AtomicReference<>();
		AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			setStatusText("Fetching process list");
			provider.getModel().fetchModelObject(List.of("Available")).handle(seq::next);
		}, available).then(seq -> {
			available.get()
					.fetchElements()
					.handle(seq::next);
		}, procs).then(seq -> {
			List<TargetAttachable> modelData = processes.getModelData();
			modelData.clear();
			for (Object p : procs.get().values()) {
				if (p instanceof TargetAttachable) {
					modelData.add((TargetAttachable) p);
				}
			}
			processes.fireTableDataChanged(); // This may not be most efficient.
			setStatusText("");
			seq.exit();
		}).finish().exceptionally(e -> {
			Msg.showError(this, getComponent(), "Could not fetch process list", e);
			setStatusText("Could not fetch process list: " + e.getMessage(), MessageType.ERROR);
			return null;
		});
	}

	public void setAttacher(TargetAttacher attacher) {
		this.attacher = attacher;
	}

}
