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
package ghidra.feature.vt.gui.wizard.session;

import java.io.IOException;

import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class CreateNewSessionTask extends Task {
	private final NewSessionData data;
	private final VTController controller;

	public CreateNewSessionTask(VTController controller, NewSessionData data) {
		super("Create New Version Tracking Session", true, true, true);
		this.controller = controller;
		this.data = data;
	}

	@Override
	public void run(TaskMonitor monitor) {
		VTSessionDB session = null;
		String name = null;
		try {
			Program sourceProgram = data.getSourceProgram();
			Program destinationProgram = data.getDestinationProgram();

			session = new VTSessionDB("New Session", sourceProgram, destinationProgram, this);

			sourceProgram.release(controller.getTool());
			destinationProgram.release(controller.getTool());

			name = data.getSessionName();
			DomainFolder folder = data.getSessionFolder();
			try {
				folder.createFile(name, session, monitor);
			}
			catch (InvalidNameException e) {
				Msg.showError(this, null, "Invalid Domain Object Name",
					"Please report this error; the name should have been checked already");
			}

			controller.openVersionTrackingSession(session);
		}
		catch (CancelledException e) {
			// ignore
		}
		catch (IOException e) {
			Msg.showError(this, null, "Failed to Create Session",
				"Failed to create db file: " + name, e);
		}
		finally {
			if (session != null) {
				session.release(this);
			}
		}
	}

}
