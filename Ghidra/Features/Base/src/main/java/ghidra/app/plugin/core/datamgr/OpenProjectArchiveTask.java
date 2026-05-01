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

import java.io.IOException;

import docking.widgets.OptionDialog;
import ghidra.app.services.Recover;
import ghidra.app.services.Upgrade;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.program.database.dtarchive.DataTypeArchiveFactory;
import ghidra.program.model.dtarchive.ProjectDataTypeArchive;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

class OpenProjectArchiveTask extends Task {
	private DomainFile file;
	private int version;
	private ProjectDataTypeArchive archive = null;
	private Object consumer;
	private Recover recoverStrategy;
	private Upgrade upgradeStrategy;

	OpenProjectArchiveTask(DomainFile file, int version, Upgrade upgradeStrategy,
			Recover recoverStrategy, Object consumer) {
		super("Open Project Data Type Archive", true, true, true);
		this.file = file;
		this.upgradeStrategy = upgradeStrategy;
		this.recoverStrategy = recoverStrategy;
		this.consumer = consumer;
		this.version = version;
	}

	ProjectDataTypeArchive getArchive() {
		return archive;
	}

	@Override
	public void run(TaskMonitor monitor) {
		monitor.setMessage(getDescription());
		try {
			archive = openArchive(monitor);
		}
		catch (VersionException e) {
			String contentType = file.getContentType();
			VersionExceptionHandler.showVersionError(null, file.getName(),
				contentType, "Open", false, e);
		}
		catch (CancelledException e) {
			// do nothing, user cancelled
		}
		catch (IOException e) {
			if (file.isVersioned() && file.isInWritableProject()) {
				ClientUtil.handleException(AppInfo.getActiveProject().getRepository(), e,
					"Get Versioned Object", null);
			}
			else {
				Msg.showError(this, null, "Project Archive Open Error",
					"Error occurred while opening " + file.getName(), e);
			}
		}

	}

	private String getDescription() {
		String description = "Opening " + file.getName();
		if (version != DomainFile.DEFAULT_VERSION) {
			description += " (version " + version + ")";
		}
		return description;
	}

	public ProjectDataTypeArchive openArchive(TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {

		if (shouldOpenImmutable(file)) {
			return DataTypeArchiveFactory.openReadOnly(file, version, consumer, monitor);
		}
		boolean okToRecover = shouldRecover();
		try {
			return DataTypeArchiveFactory.openForUpdate(file, consumer, false, okToRecover,
				monitor);
		}
		catch (VersionException e) {
			if (shouldUpgrade(e)) {
				return DataTypeArchiveFactory.openForUpdate(file, consumer, true, okToRecover,
					monitor);
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
				return VersionExceptionHandler.isUpgradeOK(null, file, "Open File Archive", e);

		}
	}

	private boolean shouldOpenImmutable(DomainFile domainFile) {
		if (version != DomainFile.DEFAULT_VERSION) {
			return true;
		}
		if (domainFile.isReadOnly()) {
			return true;
		}
		return domainFile.isVersioned() && !domainFile.isCheckedOut();
	}

	private boolean shouldRecover() {
		if (!file.isInWritableProject()) {
			return false;
		}
		switch (recoverStrategy) {
			case YES:
				return true;
			case NO:
				return false;
			case ASK:
			default:
				return askToRecover();
		}
	}

	private boolean askToRecover() {
		if (!file.canRecover()) {
			return false;
		}
		int option = OptionDialog.showYesNoDialog(null, "Crash Recovery Data Found",
			"<html>" + HTMLUtilities.escapeHTML(file.getName()) + " has crash data.<br>" +
				"Would you like to recover unsaved changes?");
		return (option == OptionDialog.OPTION_ONE);
	}

}
