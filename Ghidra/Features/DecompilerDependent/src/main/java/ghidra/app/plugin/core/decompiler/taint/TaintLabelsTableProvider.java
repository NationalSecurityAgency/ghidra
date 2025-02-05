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
package ghidra.app.plugin.core.decompiler.taint;

import java.awt.BorderLayout;
import java.util.Map;

import javax.swing.*;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import generic.theme.GIcon;
import ghidra.app.plugin.core.decompiler.taint.TaintLabelsTableModelFactory.TaintLabelsTableModel;
import ghidra.app.plugin.core.decompiler.taint.TaintState.QueryType;
import ghidra.app.plugin.core.decompiler.taint.sarif.SarifTaintGraphRunHandler;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.table.GhidraFilterTable;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import sarif.SarifService;

/**
 * Show the SARIF result as a table and build possible actions on the table
 */
public class TaintLabelsTableProvider extends ComponentProviderAdapter {

	private TaintPlugin plugin;
	private Program program;
	private JComponent mainPanel;

	private GhidraTable gtable;

	public GhidraFilterTable<Map<String, Object>> filterTable;
	private TaintLabelsTableModel model;

	// TODO: Put these in the Taint Options Manager.
	private static String clearTaintTagsIconString = "icon.clear";
	private static Icon clearTaintTagsIcon = new GIcon(clearTaintTagsIconString);
	private static String executeTaintQueryIconString = "icon.graph.default.display.program.graph";
	private static Icon executeTaintQueryIcon = new GIcon(executeTaintQueryIconString);

	public TaintLabelsTableProvider(String description, TaintPlugin plugin,
			TaintLabelsDataFrame df) {

		super(plugin.getTool(), description, plugin.getName());
		this.plugin = plugin;
		this.program = plugin.getCurrentProgram();

		TaintLabelsTableModelFactory factory =
			new TaintLabelsTableModelFactory(df.getColumnHeaders());

		this.model =
			factory.createModel("Source-Sink Query Results Table", plugin, program, df, this);
		this.mainPanel = buildPanel();

		filterTable.addSelectionListener(df);
		filterTable.getTable().getSelectionModel().addListSelectionListener(e -> {
			Msg.info(this, "list selection listener triggered.");
			plugin.getTool().contextChanged(this);
		});

		createActions();
	}

	private JComponent buildPanel() {
		filterTable = new GhidraFilterTable<>(this.model);
		GhidraTable table = filterTable.getTable();
		table.installNavigation(plugin.getTool());
		table.setName("DataTable");

		model.addTableModelListener(e -> {
			Msg.info(this, "TableModelListener fired");
			int rowCount = model.getRowCount();
			int unfilteredCount = model.getUnfilteredRowCount();
			model.getDataFrame().dumpTableToDebug();

			setSubTitle("" + rowCount + " items" +
				(rowCount != unfilteredCount ? " (of " + unfilteredCount + ")" : ""));
			filterTable.repaint();
		});

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(filterTable, BorderLayout.CENTER);

		return panel;
	}

	public void reloadModel() {
		model.reload();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	public GhidraTable getTable() {
		return gtable;
	}

	/**
	 * Add actions to various table features.
	 */
	public void createActions() {

		// Provides the icon in the toolbar that makes a selection based on what you have in the table.
		DockingAction selectionAction =
			new MakeProgramSelectionAction(plugin, filterTable.getTable());

		DockingAction clearTaintMarksAction =
			new DockingAction("Clear All Taint Marks", plugin.getName()) {

				@Override
				public void actionPerformed(ActionContext context) {
					// empty out the marker sets.
					plugin.getTaintState().clearMarkers();
					// clear the markers in the decompiler window.
					plugin.clearIcons();

					// load empty marker set and then reload the table.
					model.getDataFrame().loadData();
					model.reload();
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					return plugin.getTaintState().hasMarks();
				}
			};

		clearTaintMarksAction.setToolBarData(new ToolBarData(clearTaintTagsIcon));

		DockingAction queryAction =
			new DockingAction("Execute Source-Sink Query", plugin.getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					Msg.info(this, "Execute Source-Sink Query from Taint Labels Table");

					Program currentProgram = plugin.getCurrentProgram();
					if (currentProgram == null)
						return;

					TaintState state = plugin.getTaintState();

					Task queryTask = new Task("Source-Sink Query Task", true, true, true, true) {
						@Override
						public void run(TaskMonitor monitor) {
							state.setCancellation(false);
							monitor.initialize(program.getFunctionManager().getFunctionCount());
							// query index NOT the default query; use table data.
							boolean successful =
								state.queryIndex(currentProgram, tool, QueryType.SRCSINK);
							state.setCancellation(!successful || monitor.isCancelled());
							monitor.clearCancelled();
						}
					};

					// This task will block -- see params above.
					// The blocking is necessary because of the table provider we create below.
					// It is problematic to do GUI stuff in the thread.
					// We still get a progress bar and option to cancel.
					// 1. Query Index.
					tool.execute(queryTask);

					if (!state.wasCancelled()) {
						// 2. Show Table.
						SarifService sarifService = plugin.getSarifService();
						sarifService.getController()
								.setDefaultGraphHander(SarifTaintGraphRunHandler.class);
						sarifService.showSarif("query", state.getData());

						// 3. Set Initial Highlights
						plugin.consoleMessage("executing query...");
						TaintProvider provider = plugin.getProvider();
						provider.setTaint();
						plugin.consoleMessage("query complete");
						state.setCancellation(false);

					}
					else {
						plugin.consoleMessage("Source-Sink query was cancelled.");
					}
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					// TODO make this smarter.
					return true;
				}
			};

		queryAction.setToolBarData(new ToolBarData(executeTaintQueryIcon));

		addLocalAction(selectionAction);
		addLocalAction(clearTaintMarksAction);
		addLocalAction(queryAction);
	}
}
