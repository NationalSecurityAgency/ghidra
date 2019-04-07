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
package ghidra.framework.main.datatree;

import ghidra.framework.client.ClientUtil;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

class CopyFileVersionTask extends Task {

	private final DomainFile file;
	private final int version;
	private final DomainFolder destFolder;

	CopyFileVersionTask(DomainFile file, int version, DomainFolder destFolder) {
		super("Copy File Version", true, true, true);
		this.file = file;
		this.version = version;
		this.destFolder = destFolder;
	}

	@Override
	public void run(TaskMonitor monitor) {
		try {
			monitor.setMessage("Copying " + file.getName() + " version " + version + "...");
			if (file.copyVersionTo(version, destFolder, monitor) == null) {
				Msg.showError(this, null, "Version Copy Failed", "Failed to copy file version");
			}
		} catch (CancelledException e) {
		} catch (IOException e) {
			ClientUtil.handleException(AppInfo.getActiveProject().getRepository(), e, "Version Copy",
				null);
		}
	}

}
