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
package ghidra.framework.main.datatree;

import java.awt.Component;
import java.io.IOException;
import java.util.List;

import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.data.CheckinHandler;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.VersionExceptionHandler;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Task to perform a check on a list of DomainFiles.
 * 
 * 
 */
public class CheckInTask extends VersionControlTask implements CheckinHandler {

	private DomainFile df;
	private boolean newFile;
	private TaskMonitor monitor;

	/**
	 * Construct a new CheckInTask.
	 * @param tool tool that has the files to be checked in
	 * @param list list of domain files to be checked in
	 * @param parent parent of error dialog if an error occurs
	 */
	public CheckInTask(PluginTool tool, List<DomainFile> list, Component parent) {
		super("Check In", tool, list, parent);
	}

	private void promptUser() throws CancelledException {
		if (newFile) {
			newFile = false;
			monitor.checkCancelled();
			if (actionID != VersionControlDialog.APPLY_TO_ALL) {
				showDialog(false, df);
				// adding to version control
				if (actionID == VersionControlDialog.CANCEL) {
					monitor.cancel();
					Msg.info(this, "Check In was canceled");
					throw new CancelledException();
				}
			}
		}
	}

	@Override
	public void run(TaskMonitor myMonitor) {
		this.monitor = myMonitor;
		myMonitor.setMessage("Examining selected file(s)");
		String currentName = null;
		try {
			for (int i = 0; i < list.size() && actionID != VersionControlDialog.CANCEL; i++) {

				df = list.get(i);
				currentName = df.getName();
				newFile = true;

				if (i != 0) {
					try {
						// Give Swing a chance to update
						Thread.sleep(200);
					}
					catch (InterruptedException e2) {
						break;
					}
				}

				myMonitor.setMessage("Initiating Check In for " + currentName);
				try {
					df.checkin(this, myMonitor);
				}
				catch (VersionException e) {
					VersionExceptionHandler.showVersionError(parent, df.getName(),
						df.getContentType(), "Checkin", e);
				}
				if (myMonitor.isCancelled()) {
					break;
				}
			}
		}
		catch (CancelledException e) {
			Msg.info(this, "Check In Process was canceled");
			wasCanceled = true;
		}
		catch (IOException e) {
			RepositoryAdapter repo = df.getParent().getProjectData().getRepository();
			ClientUtil.handleException(repo, e, "Check In Process", parent);
		}
	}

	@Override
	public String getComment() throws CancelledException {
		promptUser();
		return comments;
	}

	@Override
	public boolean keepCheckedOut() throws CancelledException {
		promptUser();
		return keepCheckedOut;
	}

	@Override
	public boolean createKeepFile() throws CancelledException {
		promptUser();
		return createKeep;
	}

}
