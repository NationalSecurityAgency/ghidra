/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.feature.vt.gui.wizard;

import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import java.awt.EventQueue;
import java.io.IOException;

import docking.wizard.WizardState;

public class CreateNewSessionTask extends Task {
	private final WizardState<VTWizardStateKey> state;
	private final VTController controller;

	public CreateNewSessionTask(VTController controller, WizardState<VTWizardStateKey> state) {
		super("Create New Version Tracking Session", true, true, true);
		this.controller = controller;
		this.state = state;
	}

	@Override
	public void run(TaskMonitor monitor) {
		VTSession session = null;
		String name = null;
		try {
			Program sourceProgram = (Program) state.get(VTWizardStateKey.SOURCE_PROGRAM);
			Program destinationProgram = (Program) state.get(VTWizardStateKey.DESTINATION_PROGRAM);

			session =
				VTSessionDB.createVTSession("New Session", sourceProgram, destinationProgram, this);

			DomainObjectAdapterDB dobj = null;
			if (session instanceof DomainObjectAdapterDB) {
				dobj = (DomainObjectAdapterDB) session;
			}
			sourceProgram.release(controller.getTool());
			destinationProgram.release(controller.getTool());
			if (dobj != null) {
				name = (String) state.get(VTWizardStateKey.SESSION_NAME);
				DomainFolder folder = (DomainFolder) state.get(VTWizardStateKey.NEW_SESSION_FOLDER);
				try {
					folder.createFile(name, dobj, monitor);
				}
				catch (InvalidNameException e) {
					Msg.showError(this, null, "Invalid Domain Object Name",
						"Please report this error; the name should have been checked already");
				}
			}

			final VTSession finalSession = session;
			EventQueue.invokeLater(new Runnable() {
				public void run() {
					controller.openVersionTrackingSession(finalSession);
					releaseDomainObject(finalSession);
				}
			});
		}
		catch (CancelledException e) {
			// the user cancelled; just cleanup
			releaseDomainObject(session);
		}
		catch (IOException e) {
			releaseDomainObject(session);
			Msg.showError(this, null, "Failed to Create Session", "Failed to create db file: " +
				name, e);
		}
	}

	private void releaseDomainObject(VTSession session) {
		if (session == null) {
			return;
		}

		((VTSessionDB) session).release(this);
	}
}
