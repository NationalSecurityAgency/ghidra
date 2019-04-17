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
package ghidra.framework.main.projectdata.actions;

import java.util.Objects;
import java.util.Set;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

class CountDomainFilesTask extends Task {

	private Set<DomainFolder> folders;
	private Set<DomainFile> files;

	private int fileCount;
	private boolean cancelled;

	public CountDomainFilesTask(Set<DomainFolder> folders, Set<DomainFile> files) {
		super("Counting Files", true, false, true);
		this.folders = Objects.requireNonNull(folders);
		this.files = Objects.requireNonNull(files);
	}

	@Override
	public void run(TaskMonitor monitor) {
		countFiles(monitor);
	}

	private void countFiles(TaskMonitor monitor) {
		try {
			fileCount = files.size();
			for (DomainFolder folder : folders) {
				monitor.checkCanceled();
				countFiles(folder, monitor);
			}
		}
		catch (CancelledException e) {
			cancelled = true;
		}
	}

	private void countFiles(DomainFolder folder, TaskMonitor monitor) throws CancelledException {
		for (DomainFile domainFile : folder.getFiles()) {
			if (!files.contains(domainFile)) {
				fileCount++;
			}
		}

		for (DomainFolder subFolder : folder.getFolders()) {
			monitor.checkCanceled();
			if (!folders.contains(subFolder)) {
				countFiles(subFolder, monitor);
			}
		}
	}

	boolean wasCancelled() {
		return cancelled;
	}

	int getFileCount() {
		return fileCount;
	}
}
