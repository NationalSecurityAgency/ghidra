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

import java.io.IOException;
import java.util.List;

import docking.widgets.OptionDialog;
import ghidra.framework.client.*;
import ghidra.framework.main.datatable.DomainFileContext;
import ghidra.framework.main.datatable.DomainFileProviderContextAction;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.store.FileSystemSynchronizer;
import ghidra.util.HelpLocation;

/**
 * VersionControlAction is an abstract class that can be extended by each specific version
 * control action to be taken on a domain file.
 */
public abstract class VersionControlAction extends DomainFileProviderContextAction {

	protected static final String GROUP = "Repository";

	protected PluginTool tool;
	protected RepositoryAdapter repository;

	public VersionControlAction(String name, String owner, PluginTool tool) {
		super(name, owner);
		this.tool = tool;

		setHelpLocation(new HelpLocation("VersionControl", name));
		checkRepository();
	}

	/**
	 * Returns true if there is at least one of the provided domain files can be 
	 * or is version controlled.
	 */
	@Override
	public boolean isAddToPopup(DomainFileContext context) {

		if (!context.isInActiveProject()) {
			return false;
		}

		checkRepository();
		List<DomainFile> domainFiles = context.getSelectedFiles();
		for (DomainFile domainFile : domainFiles) {
			if (domainFile.getVersion() > 0) {
				return true; // Has at least one domain file that can be or is version controlled.
			}
		}
		return false;
	}

	/**
	 * Determines the project repository for tool associated with this action.
	 * The repository may be null.
	 */
	private void checkRepository() {
		Project project = tool.getProject();
		if (project != null) {
			repository = project.getRepository();
		}
		else if (repository != null) {
			repository = null;
		}
	}

	/**
	 * True if the file system is locked by another thread for a long running operation
	 * @return true if locked
	 */
	protected boolean isFileSystemBusy() {
		return FileSystemSynchronizer.isSynchronizing();
	}

	/**
	 * NOTE: do not call this from a non-Swing thread.
	 * @return true if the repository is null or is connected.
	 */
	protected boolean checkRepositoryConnected() {
		checkRepository();
		if (repository == null) {
			return true;
		}

		if (repository.verifyConnection()) {
			return true;
		}

		if (OptionDialog.showYesNoDialog(tool.getToolFrame(), "Lost Connection to Server",
			"The connection to the Ghidra Server has been lost.\n" +
				"Do you want to reconnect now?") == OptionDialog.OPTION_ONE) {
			try {
				repository.connect();
				return true;
			}
			catch (NotConnectedException e) {
				// message displayed by repository server adapter
				return false;
			}
			catch (IOException e) {
				ClientUtil.handleException(repository, e, "Repository Connection",
					tool.getToolFrame());
				return false;
			}
		}

		return false;
	}

	/**
	 * Checks if anything is preventing a particular domain file from closing.
	 * @param df the domain file to check
	 * @return true if the specified domain file can be closed.
	 */
	boolean canCloseDomainFile(DomainFile df) {
		Project project = tool.getProject();
		PluginTool[] tools = project.getToolManager().getRunningTools();
		for (PluginTool t : tools) {
			DomainFile[] files = t.getDomainFiles();
			for (DomainFile domainFile : files) {
				if (df == domainFile) {
					return t.canCloseDomainFile(df);
				}
			}
		}
		return true;
	}
}
