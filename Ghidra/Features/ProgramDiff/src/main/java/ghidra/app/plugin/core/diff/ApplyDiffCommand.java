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

import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.lang.reflect.InvocationTargetException;

import javax.swing.SwingUtilities;

import docking.widgets.dialogs.ReadTextDialog;

/**
 * Command to apply diffs to current program.
 * 
 */
class ApplyDiffCommand extends BackgroundCommand implements AnalysisWorker {

	private AddressSetView p1AddressSet;
	private DiffController diffControl;
	private String title;
	private String applyMsg;
	private boolean applied;
	private ProgramDiffPlugin plugin;

	/**
	 * Constructor.
	 */
	ApplyDiffCommand(ProgramDiffPlugin plugin, AddressSetView program1AddressSet,
			DiffController diffControl) {
		super("Apply Differences", false, true, true);
		this.plugin = plugin;
		this.p1AddressSet = program1AddressSet;
		this.diffControl = diffControl;
	}

	@Override
	public boolean analysisWorkerCallback(Program program, Object workerContext, TaskMonitor monitor)
			throws Exception, CancelledException {
		// Diff apply done with analysis disabled
		return diffControl.apply(p1AddressSet, monitor);
	}

	@Override
	public String getWorkerName() {
		return getName();
	}

	/**
	 * @see ghidra.framework.cmd.BackgroundCommand#applyTo(ghidra.framework.model.DomainObject, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		monitor.setMessage("ApplyDiffTask starting...");
		applied = false;
		final ProgramLocation origLocation = plugin.getProgramLocation();
		if (!plugin.isTaskInProgress()) {

			plugin.setTaskInProgress(true);
			String statusMsg = "One or more differences couldn't be applied.";
			title = "Program Diff: One or more differences couldn't be applied.";
			applyMsg = null;
			setStatusMsg(null);
			try {
				AutoAnalysisManager autoAnalysisManager =
					AutoAnalysisManager.getAnalysisManager(plugin.getFirstProgram());
				boolean merged = autoAnalysisManager.scheduleWorker(this, null, false, monitor);
				if (merged) {
					statusMsg =
						"Apply differences has finished."
							+ " If your expected change didn't occur, check your Diff Apply Settings.";
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
				Throwable t = e.getCause();
				String message = "";
				// Protect against dereferencing the getCause call above, which may return null.
				if (t != null) {
					String excMessage = t.getMessage();
					if (excMessage != null && excMessage.length() > 0) {
						message = excMessage + "\n";
					}
				}
				Msg.showError(this, plugin.getListingPanel(), "Error Applying Diff",
					"An error occurred while applying differences.\n"
						+ "Only some of the differences may have been applied.",
					(t != null) ? t : e);
				applyMsg = message + diffControl.getApplyMessage();
			}
			catch (CancelledException e) {
				statusMsg =
					"User cancelled \"Apply Differences\". "
						+ "Differences were only partially applied.";
				applyMsg = diffControl.getApplyMessage();
			}
			finally {
				setStatusMsg(statusMsg);
				plugin.getTool().setStatusInfo(statusMsg);
				plugin.setTaskInProgress(false);

				Runnable r = new Runnable() {
					@Override
					public void run() {
						plugin.adjustDiffDisplay();
						plugin.firePluginEvent(new ProgramSelectionPluginEvent(plugin.getName(),
							plugin.getCurrentSelection(), plugin.getCurrentProgram()));
						plugin.programLocationChanged(origLocation, null);
						if (applyMsg != null && applyMsg.length() > 0) {
							ReadTextDialog detailsDialog = new ReadTextDialog(title, applyMsg);
							plugin.getTool().showDialog(detailsDialog, plugin.getListingPanel());
						}
					}
				};
//				// The events were disabled while doing apply Diff. Now re-enable them by firing object restored event.
//				((DomainObjectAdapter)currentProgram).fireEvent(new DomainObjectChangeRecord(
//									DomainObject.DO_OBJECT_RESTORED));
//				((DomainObjectAdapter)currentProgram).flushEvents();
				if (!monitor.isCancelled()) {
					SwingUtilities.invokeLater(r);
				}
			}
		}
		return applied;
	}

}
