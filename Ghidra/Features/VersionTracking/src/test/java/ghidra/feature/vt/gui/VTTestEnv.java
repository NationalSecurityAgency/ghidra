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
package ghidra.feature.vt.gui;

import static docking.test.AbstractDockingTest.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JTable;
import javax.swing.event.TableModelEvent;

import docking.action.DockingActionIf;
import docking.widgets.table.GTable;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.feature.vt.gui.plugin.*;
import ghidra.feature.vt.gui.provider.matchtable.VTMatchTableModel;
import ghidra.feature.vt.gui.provider.matchtable.VTMatchTableProvider;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import junit.framework.AssertionFailedError;

public class VTTestEnv extends TestEnv {

	private VTSessionDB session;
	private VTController controller;
	private VTPlugin plugin;
	private Program sourceProgram;
	private Program destinationProgram;
	private VTMatchTableProvider matchTableProvider;

	public VTTestEnv() throws Exception {

		PluginTool tool = getTool();
		tool.removePlugins(new Plugin[] { getPlugin(ProgramManagerPlugin.class) });
		tool.addPlugin(VTPlugin.class.getName());
		plugin = getPlugin(VTPlugin.class);
		controller = (VTController) getInstanceField("controller", plugin);
		matchTableProvider = (VTMatchTableProvider) getInstanceField("matchesProvider", plugin);
	}

	public VTSessionDB createSession(String sourceProgramName, String destinationProgramName,
			VTProgramCorrelatorFactory factory) throws Exception {
		sourceProgram = getProgram(sourceProgramName);
		destinationProgram = getProgram(destinationProgramName);

		session = VTSessionDB.createVTSession("Test", sourceProgram, destinationProgram, getTool());

		VTProgramCorrelator correlator = factory.createCorrelator(getTool(), sourceProgram,
			sourceProgram.getMemory(), destinationProgram, destinationProgram.getMemory(), null);

		int id = session.startTransaction("Correlate");
		correlator.correlate(session, TaskMonitor.DUMMY);
		session.endTransaction(id, true);
		SystemUtilities.runSwingNow(() -> controller.openVersionTrackingSession(session));
		return session;
	}

	public VTSessionDB addToSession(VTProgramCorrelatorFactory factory) throws Exception {

		if (session == null) {
			throw new AssertionFailedError("You must create the session before you can add items");
		}

		VTProgramCorrelator correlator = factory.createCorrelator(getTool(), sourceProgram,
			sourceProgram.getMemory(), destinationProgram, destinationProgram.getMemory(), null);

		int id = session.startTransaction("Correlate");
		correlator.correlate(session, TaskMonitor.DUMMY);
		session.endTransaction(id, true);

		return session;
	}

	public VTSessionDB createSession(String sourceProgramName, String destinationProgramName)
			throws Exception {
		sourceProgram = getProgram(sourceProgramName);
		destinationProgram = getProgram(destinationProgramName);
		return createAndOpenVTSession();
	}

	public VTSessionDB createSession(Program sourcePgm, Program destinationPgm) throws Exception {
		sourceProgram = sourcePgm;
		destinationProgram = destinationPgm;
		return createAndOpenVTSession();
	}

	private VTSessionDB createAndOpenVTSession() throws IOException {
		session = VTSessionDB.createVTSession("Test", sourceProgram, destinationProgram, getTool());

		runSwing(() -> controller.openVersionTrackingSession(session), false);

		waitForTasks();

		return session;
	}

	public VTProgramCorrelator correlate(VTProgramCorrelatorFactory factory, VTOptions options,
			TaskMonitor monitor) throws CancelledException {
		VTProgramCorrelator correlator = factory.createCorrelator(getTool(), sourceProgram,
			sourceProgram.getMemory(), destinationProgram, destinationProgram.getMemory(), options);

		int id = session.startTransaction("Correlate");
		correlator.correlate(session, monitor);
		session.endTransaction(id, true);
		return correlator;
	}

	private void releaseSession() {
		if (sourceProgram != null) {
			release(sourceProgram);
		}
		if (destinationProgram != null) {
			release(destinationProgram);
		}
	}

	@Override
	public void dispose() {
		releaseSession();
		super.dispose();
	}

	public VTController getVTController() {
		return controller;
	}

	public VTSession getSession() {
		return session;
	}

	public Program getSourceProgram() {
		return sourceProgram;
	}

	public PluginTool getSourceTool() {
		VTSubToolManager toolManager = plugin.getToolManager();
		return (PluginTool) invokeInstanceMethod("getSourceTool", toolManager);
	}

	public PluginTool getDestinationTool() {
		VTSubToolManager toolManager = plugin.getToolManager();
		return (PluginTool) invokeInstanceMethod("getDestinationTool", toolManager);
	}

	public Program getDestinationProgram() {
		return destinationProgram;
	}

	public VTPlugin getVersionTrackingPlugin() {
		return plugin;
	}

	public List<VTMatch> selectMatchesInMatchTable(final int... rows) {

		GTable table = (GTable) getInstanceField("matchesTable", matchTableProvider);
		VTMatchTableModel model = (VTMatchTableModel) table.getModel();
		waitForTableModel(model);

		selectRows(table, rows);

		List<VTMatch> matches = new ArrayList<>();

		for (int row : rows) {
			matches.add(model.getRowObject(row));
		}

		waitForSwing();

		return matches;
	}

	private void selectRows(final GTable table, final int... rows) {
		runSwing(() -> {
			table.clearSelection();
			for (int row : rows) {
				table.addRowSelectionInterval(row, row);
			}
		});
		waitForPostedSwingRunnables();
	}

	public int getSelectedMatchTableRow() {

		final GTable table = (GTable) getInstanceField("matchesTable", matchTableProvider);
		VTMatchTableModel model = (VTMatchTableModel) table.getModel();
		waitForTableModel(model);

		final int[] container = new int[1];
		runSwing(() -> container[0] = table.getSelectedRow());

		return container[0];
	}

	public VTMatch getSelectedMatch() {

		final GTable table = (GTable) getInstanceField("matchesTable", matchTableProvider);
		VTMatchTableModel model = (VTMatchTableModel) table.getModel();
		waitForTableModel(model);

		final int[] container = new int[1];
		runSwing(() -> container[0] = table.getSelectedRow());

		return model.getRowObject(container[0]);
	}

	public DockingActionIf getAction(String name) {
		return AbstractGhidraHeadedIntegrationTest.getAction(plugin, name);
	}

	public void performMatchTableAction(DockingActionIf action) {
		performAction(action, matchTableProvider.getActionContext(null), true);
	}

	public void focusMatchTable() {
		runSwing(() -> matchTableProvider.getComponent().requestFocus());
	}

	public void triggerMatchTableDataChanged() {
		final JTable table = (JTable) getInstanceField("matchesTable", matchTableProvider);

		runSwing(() -> table.tableChanged(new TableModelEvent(table.getModel())));
	}

	public VTMatchTableProvider getMatchTableProvider() {
		return matchTableProvider;
	}
}
