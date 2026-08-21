/* ###
 * IP: GHIDRA
 * NOTE: This disables auto analysis while differences are applied and restores auto analysis enablement at end.
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
package ghidra.app.plugin.core.diff;

import java.lang.reflect.InvocationTargetException;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;

import docking.widgets.dialogs.ReadTextDialog;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Command to apply diffs to current program.
 * 
 */
class ApplyDiffCommand extends BackgroundCommand<Program> implements AnalysisWorker {

	private AddressSetView p1AddressSet;
	private DiffController diffControl;
	private String title;
	private String applyMsg;
	private boolean applied;
	private ProgramDiffPlugin plugin;

	ApplyDiffCommand(ProgramDiffPlugin plugin, AddressSetView program1AddressSet,
			DiffController diffControl) {
		super("Apply Differences", false, true, true);
		this.plugin = plugin;
		this.p1AddressSet = program1AddressSet;
		this.diffControl = diffControl;
	}

	@Override
	public boolean analysisWorkerCallback(Program program, Object workerContext,
			TaskMonitor monitor) throws Exception, CancelledException {
		// Diff apply done with analysis disabled
		return diffControl.apply(p1AddressSet, monitor);
	}

	@Override
	public String getWorkerName() {
		return getName();
	}

	@Override
	public boolean applyTo(Program program, TaskMonitor monitor) {

		monitor.setMessage("ApplyDiffTask starting...");
		applied = false;
		if (plugin.isTaskInProgress()) {
			return false;
		}

		ProgramLocation restoreLocation = plugin.getProgramLocation();

		plugin.setTaskInProgress(true);
		String statusMsg = "One or more differences couldn't be applied.";
		title = "Program Diff: One or more differences couldn't be applied.";
		applyMsg = null;
		setStatusMsg(null);
		try {
			AutoAnalysisManager aaManager =
				AutoAnalysisManager.getAnalysisManager(plugin.getFirstProgram());
			boolean merged = aaManager.scheduleWorker(this, null, false, monitor);
			if (merged) {
				statusMsg = "Apply differences has finished." +
					" If your expected change didn't occur, check your Diff Apply Settings.";
				title = "Program Diff: Apply differences has finished.";
				applied = true;
			}
			else {
				applyMsg = diffControl.getApplyMessage();
			}
		}
		catch (InterruptedException e) {
			applyMsg = "Unexpected InterruptedException\n" + diffControl.getApplyMessage();
		}
		catch (InvocationTargetException e) {
			Throwable t = ExceptionUtils.getRootCause(e);
			String message = ExceptionUtils.getMessage(t);
			Msg.showError(this, plugin.getListingPanel(), "Error Applying Diff",
				"An error occurred while applying differences.\n" +
					"Only some of the differences may have been applied.",
				(t != null) ? t : e);
			applyMsg = message + diffControl.getApplyMessage();
		}
		catch (CancelledException e) {
			statusMsg = "User cancelled \"Apply Differences\". " +
				"Differences were only partially applied.";
			applyMsg = diffControl.getApplyMessage();
		}
		finally {
			setStatusMsg(statusMsg);
			plugin.getTool().setStatusInfo(statusMsg);
			plugin.setTaskInProgress(false);

			if (!monitor.isCancelled()) {
				updatePluginState(restoreLocation);
			}
		}
		return applied;
	}

	private void updatePluginState(ProgramLocation restoreLocation) {

		Runnable r = new Runnable() {
			@Override
			public void run() {
				plugin.adjustDiffDisplay();

				String name = plugin.getName();
				ProgramSelection selection = plugin.getCurrentSelection();
				Program program = plugin.getCurrentProgram();
				plugin.firePluginEvent(new ProgramSelectionPluginEvent(name, selection, program));
				plugin.programLocationChanged(restoreLocation, null);
				if (!StringUtils.isBlank(applyMsg)) {
					ReadTextDialog detailsDialog = new ReadTextDialog(title, applyMsg);
					plugin.getTool().showDialog(detailsDialog, plugin.getListingPanel());
				}
			}
		};

		// Note: a run later will not work here, since it may not happen before any
		// follow-on jobs
		Swing.runNow(r);
	}
}
