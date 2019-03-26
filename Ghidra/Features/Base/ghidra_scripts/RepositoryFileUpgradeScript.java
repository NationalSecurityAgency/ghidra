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
// Script upgrades all Program files within the current project.
// Since there should be no checkouts when an upgrade is performed,
// the script will optionally list any existing checkouts prior to starting
// the batch upgrade.
//
//@category Upgrade
import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.data.CheckinHandler;
import ghidra.framework.model.*;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;

public class RepositoryFileUpgradeScript extends GhidraScript {

	boolean includePrivatePrograms;

	@Override
	protected void run() throws Exception {
		RepositoryAdapter repository = null;
		try {
			Project project = state.getProject();
			if (project == null) {
				popup("No active project found!");
				return;
			}

			if (currentProgram != null) {
				popup("All programs must be closed before running this script!");
				return;
			}

			repository = project.getRepository();
			if (repository != null && !repository.isConnected()) {
				if (askYesNo("Connect?",
					"You are not connected to the repository server!  Connect now?")) {
					repository.connect();
					if (!repository.isConnected()) {
						return;
					}
				}
				else {
					popup("Operation cancelled - unable to proceed without connected repository.");
					return;
				}
			}

			ProjectData projectData = project.getProjectData();
			if (askYesNo("Find Active Checkouts?",
				"Would you like to query the repository for active checkouts before attempting upgrade?")) {
				int count = listCheckouts(projectData.getRootFolder());
				if (count == 0) {
					if (!askYesNo("Continue?",
						"Would you like to continue with Program file upgrades?")) {
						return;
					}
				}
				else {
					if (!askYesNo("Checkouts Found! Continue?",
						count + " checkouts were found and have been listed in the script log.\n" +
							"Checked-out files will be skipped during batch upgrade.\n \n" +
							"Would you like to continue with Program file upgrades?")) {
						return;
					}
				}
			}

			includePrivatePrograms = askYesNo("Upgrade Option",
				"Would you like to include private local files in upgrade?");

			int count = performProgramUpgrades(projectData.getRootFolder());
			popup(count + " Program files were upgraded");
		}
		catch (CancelledException e) {
			popup(getClass().getSimpleName() + " execution cancelled.");
		}
		catch (Exception e) {
			String operation = getClass().getSimpleName() + " execution";
			ClientUtil.handleException(repository, e, operation, null);
		}
	}

	private int listCheckouts(DomainFolder folder) throws IOException, CancelledException {
		int count = 0;
		for (DomainFile df : folder.getFiles()) {
			monitor.checkCanceled();
			count += listCheckouts(df);
		}
		for (DomainFolder subfolder : folder.getFolders()) {
			monitor.checkCanceled();
			count += listCheckouts(subfolder);
		}
		return count;
	}

	private int listCheckouts(DomainFile df) throws IOException {
		if (!df.isVersioned()) {
			return 0;
		}
		int count = 0;
		for (ItemCheckoutStatus checkout : df.getCheckouts()) {
			++count;
			String loc = checkout.getUser() + "@" + checkout.getProjectPath();
			println("Active checkout: " + df.getPathname() + " (" + loc + ")");
		}
		return count;
	}

	private int performProgramUpgrades(DomainFolder folder) throws IOException, CancelledException {
		int count = 0;
		for (DomainFile df : folder.getFiles()) {
			monitor.checkCanceled();
			if (performProgramUpgrade(df)) {
				++count;
			}
		}
		for (DomainFolder subfolder : folder.getFolders()) {
			monitor.checkCanceled();
			count += performProgramUpgrades(subfolder);
		}
		return count;
	}

	private boolean performProgramUpgrade(DomainFile df) throws IOException, CancelledException {
		if (!ProgramContentHandler.PROGRAM_CONTENT_TYPE.equals(df.getContentType())) {
			return false;
		}
		boolean versionedFile = df.isVersioned();
		if (!versionedFile && !includePrivatePrograms) {
			return false;
		}
		if (df.isReadOnly()) {
			printerr("Skipping read-only file: " + df.getPathname());
			return false;
		}
		if (df.isCheckedOut()) {
			printerr("Skipping locally checked-out file: " + df.getPathname());
			return false;
		}
		if (versionedFile && !df.checkout(true, monitor)) {
			printerr("Failed to get exclusive checkout for file: " + df.getPathname());
			return false;
		}

		boolean upgraded = false;
		try {
			upgraded = upgradeProgram(df);
		}
		catch (LanguageNotFoundException e) {
			printerr("Skipping file (" + e.getMessage() + "): " + df.getPathname());
			return false;
		}
		catch (VersionException e) {
			printerr("Program created with newer/unknown Ghidra version: " + df.getPathname());
			return false;
		}
		finally {
			if (versionedFile) {
				df.undoCheckout(false);
			}
		}
		return upgraded;
	}

	private boolean upgradeProgram(DomainFile df)
			throws VersionException, CancelledException, IOException {

		try {
			// Check if upgrade is needed and is possible
			DomainObject dobj = df.getDomainObject(this, false, false, monitor);
			dobj.release(this);
			return false; // no upgrade needed
		}
		catch (VersionException e) {
			if (!e.isUpgradable()) {
				throw e; // upgrade not possible
			}
		}

		boolean upgraded = false;
		DomainObject dobj = df.getDomainObject(this, true, false, monitor);
		try {
			if (dobj.isChanged()) {
				dobj.save("Batch Upgrade", monitor);
				dobj.release(this);
				dobj = null;
				if (df.isVersioned()) {
					df.checkin(checkinHandler, false, monitor);
					println("Repository file upgraded: " + df.getPathname());
				}
				else {
					println("Local file upgraded: " + df.getPathname());
				}
				upgraded = true;
			}
		}
		finally {
			if (dobj != null) {
				dobj.release(this);
			}
		}
		return upgraded;
	}

	CheckinHandler checkinHandler = new CheckinHandler() {

		@Override
		public boolean keepCheckedOut() throws CancelledException {
			return true;
		}

		@Override
		public String getComment() throws CancelledException {
			return "Batch Upgrade";
		}

		@Override
		public boolean createKeepFile() throws CancelledException {
			return false;
		}
	};

}
