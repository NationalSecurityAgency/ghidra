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
package ghidra.app.plugin.core.datamgr;

import java.io.FileNotFoundException;
import java.io.IOException;

import docking.widgets.OptionDialog;
import generic.jar.ResourceFile;
import ghidra.app.services.Upgrade;
import ghidra.program.database.dtarchive.DataTypeArchiveFactory;
import ghidra.program.model.dtarchive.FileDataTypeArchive;
import ghidra.util.Msg;
import ghidra.util.VersionExceptionHandler;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

class OpenFileArchiveTask extends Task {
	private ResourceFile file;
	private FileDataTypeArchive archive = null;
	private Object consumer;
	private Upgrade upgradeStrategy;
	private boolean openForUpdate;

	OpenFileArchiveTask(ResourceFile file, boolean openForUpdate,
			Upgrade upgradeStrategy, Object consumer) {
		super("Opening File DataType Archive " + file.getName(), false, false, true);
		this.file = file;
		this.openForUpdate = openForUpdate;
		this.upgradeStrategy = upgradeStrategy;
		this.consumer = consumer;
	}

	FileDataTypeArchive getArchive() {
		return archive;
	}

	@Override
	public void run(TaskMonitor monitor) {
		try {
			archive = openArchive(monitor);
		}
		catch (FileNotFoundException e) {
			Msg.showError(this, null, "Open File Archive Failed",
				file.getAbsolutePath() + " not found!");
		}
		catch (IOException e) {
			Msg.showError(this, null, "Open File Archive Failed",
				e.getMessage() + ": " + file.getName());
		}
		catch (VersionException e) {
			VersionExceptionHandler.showVersionError(null, file.getName(), "Archive", "open", false,
				e);
		}
		catch (CancelledException e) {
			// user cancelled, nothing to report
		}

	}

	public FileDataTypeArchive openArchive(TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {

		if (!openForUpdate) {
			return DataTypeArchiveFactory.openReadOnly(file, consumer, monitor);
		}
		try {
			return DataTypeArchiveFactory.openForUpdate(file, false, consumer, monitor);
		}
		catch (VersionException e) {
			if (shouldUpgrade(e)) {
				return DataTypeArchiveFactory.openForUpdate(file, true, consumer, monitor);
			}
			throw e;
		}
	}

	private boolean shouldUpgrade(VersionException e) {
		if (!e.isUpgradable()) {
			return false;
		}
		switch (upgradeStrategy) {
			case YES:
				return true;
			case NO:
				return false;
			case ASK:
			default:
				return askToUpgrade();

		}
	}

	private boolean askToUpgrade() {
		return OptionDialog.showOptionDialog(null,
			"Upgrade File Archive: " + file.getName(),
			"File archive is an older version.\n" +
				"Do you want to upgrade it to the latest version?",
			"Upgrade",
			OptionDialog.QUESTION_MESSAGE) == OptionDialog.YES_OPTION;
	}
}
