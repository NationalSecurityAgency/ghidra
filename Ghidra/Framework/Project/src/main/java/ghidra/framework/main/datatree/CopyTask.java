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

import java.io.IOException;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class CopyTask extends Task {

	private DomainFolder destFolder;
	private DomainFolder srcFolder;
	private DomainFile srcFile;

	CopyTask(DomainFolder destFolder, DomainFolder srcFolder) {
		super("Copy " + srcFolder.getPathname(), true, false, true);
		if (destFolder == null) {
			throw new IllegalArgumentException("Both destFolder and srcFolder must be specified");
		}
		this.destFolder = destFolder;
		this.srcFolder = srcFolder;
	}

	CopyTask(DomainFolder destFolder, DomainFile srcFile) {
		super("Copy " + srcFile.getPathname(), true, true, true);
		this.destFolder = destFolder;
		this.srcFile = srcFile;
	}

	/**
	 * @see ghidra.util.task.Task#run(ghidra.util.task.TaskMonitor)
	 */
	@Override
    public void run(TaskMonitor monitor) {
		if (srcFolder != null) {
			copyFolder(monitor);
		}
		else {
			copyFile(monitor);
		}
	}

	private void copyFolder(TaskMonitor monitor) {
		try {
			// if folder is a root folder, copy the contents thereof
			if (srcFolder.getParent() == null) {
				DomainFolder[] folders = srcFolder.getFolders();
				for (DomainFolder element : folders) {
					element.copyTo(destFolder, monitor);
				}
				DomainFile[] files = srcFolder.getFiles();
				for (DomainFile element : files) {
					element.copyTo(destFolder, monitor);
				}
			}
			else {
				srcFolder.copyTo(destFolder, monitor);
			}
		}
		catch (CancelledException e) {
			// ignore
		}
		catch (IOException e) {
			String msg = e.getMessage();
			if (msg == null) {
				msg = e.toString();
			}
			Msg.showError(this, null, "Folder Copy Failed",
				"Could not copy folder " + srcFolder.getName() + ".\n" + msg);
		}
	}

	private void copyFile(TaskMonitor monitor) {
		try {
			srcFile.copyTo(destFolder, monitor);
		}
		catch (CancelledException e) {
			// ignore
		}
		catch (IOException e) {
			String msg = e.getMessage();
			if (msg == null) {
				msg = e.toString();
			}
			Msg.showError(this, null, "File Copy Failed",
				"Could not copy file " + srcFile.getName() + ".\n" + msg);
		}
	}
}
