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
import java.lang.reflect.InvocationTargetException;
import java.util.List;

import javax.swing.SwingUtilities;

import docking.widgets.OptionDialog;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.archive.*;
import ghidra.app.plugin.core.datamgr.tree.ArchiveNode;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.DataTypeArchive;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

class OpenDomainFileTask extends Task {
	private DomainFile domainFile;
	private int version;
	private DataTypeManagerPlugin dtmPlugin;
	private DataTypeManagerHandler dtmHandler;
	private PluginTool tool;
	private DataTypeArchive dtArchive = null;

	OpenDomainFileTask(DomainFile domainFile, int version, PluginTool tool,
			DataTypeManagerPlugin dtmPlugin) {

		super("Open Project Data Type Archive", true, true, true);
		this.domainFile = domainFile;
		this.dtmPlugin = dtmPlugin;
		this.dtmHandler = dtmPlugin.getDataTypeManagerHandler();
		this.tool = tool;
		this.version = version;
	}

	DataTypeArchive getArchive() {
		return dtArchive;
	}

	/* (non-Javadoc)
	 * @see ghidra.util.task.Task#run(ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void run(TaskMonitor monitor) {

		if (isFileOpen()) {
			return;
		}
		boolean associateWithOriginalDomainFile = true;
		if (version != DomainFile.DEFAULT_VERSION) {
			openReadOnlyFile(monitor);
			associateWithOriginalDomainFile = false;
		}
		else if (domainFile.isReadOnly()) {
			openReadOnlyFile(monitor);
		}
		else if (domainFile.isVersioned() && !domainFile.isCheckedOut()) {
			openReadOnlyFile(monitor);
		}
		else {
			openUnversionedFile(monitor);
		}
		if (dtArchive != null) {
			openFileInTree(associateWithOriginalDomainFile);
			dtArchive.release(this);
		}
	}

	private boolean isFileOpen() {
		List<Archive> dtArchiveList = dtmHandler.getAllArchives();
		for (int i = 0; i < dtArchiveList.size(); i++) {
			Archive archive = dtArchiveList.get(i);
			if (archive instanceof ProjectArchive) {
				ProjectArchive projectArchive = (ProjectArchive) archive;
				DomainFile archiveDomainFile = projectArchive.getDomainFile();
				if (filesMatch(domainFile, archiveDomainFile)) {
					//            	archive = projectArchive;
					//            	dtmHandler.open // TODO
					return true;
				}
			}
		}

		return false;
	}

	private boolean filesMatch(DomainFile file1, DomainFile file2) {
		if (!file1.getPathname().equals(file2.getPathname())) {
			return false;
		}

		if (file1.isCheckedOut() != file2.isCheckedOut()) {
			return false;
		}

		if (!SystemUtilities.isEqual(file1.getProjectLocator(), file2.getProjectLocator())) {
			return false;
		}

		int otherVersion = file2.isReadOnly() ? file2.getVersion() : -1;
		return version == otherVersion;
	}

	private void openReadOnlyFile(TaskMonitor monitor) {
		String fileDescr =
			((version != DomainFile.DEFAULT_VERSION) ? "version " + version + " of " : "") +
				domainFile.getName();
		String contentType = null;
		try {
			monitor.setMessage("Opening " + fileDescr);
			contentType = domainFile.getContentType();
			dtArchive =
				(DataTypeArchive) domainFile.getReadOnlyDomainObject(this, version, monitor);
		}
		catch (CancelledException e) {
			// we don't care, the task has been canceled
		}
		catch (IOException e) {
			if (domainFile.isVersioned() && domainFile.isInWritableProject()) {
				ClientUtil.handleException(AppInfo.getActiveProject().getRepository(), e,
					"Get Versioned Object", null);
			}
			else {
				Msg.showError(this, null, "Project Archive Open Error",
					"Error occurred while opening " + fileDescr, e);
			}
		}
		catch (VersionException e) {
			VersionExceptionHandler.showVersionError(tool.getToolFrame(), domainFile.getName(),
				contentType, "Open", e);
		}
	}

	private void openUnversionedFile(TaskMonitor monitor) {
		monitor.setMessage("Opening " + domainFile.getName());
		String contentType = null;
		try {
			final boolean recoverFile = isRecoveryOK(domainFile);
			contentType = domainFile.getContentType();
			try {
				dtArchive =
					(DataTypeArchive) domainFile.getDomainObject(this, false, recoverFile, monitor);
			}
			catch (VersionException e) {
				if (VersionExceptionHandler.isUpgradeOK(null, domainFile, "Open", e)) {
					dtArchive = (DataTypeArchive) domainFile.getDomainObject(this, true,
						recoverFile, monitor);
				}
			}
		}
		catch (VersionException e) {
			VersionExceptionHandler.showVersionError(null, domainFile.getName(), contentType,
				"Open", e);
		}
		catch (CancelledException e) {
			// we don't care, the task has been canceled
		}
		catch (Exception e) {
			if (domainFile.isInWritableProject() && (e instanceof IOException)) {
				RepositoryAdapter repo = domainFile.getParent().getProjectData().getRepository();
				ClientUtil.handleException(repo, e, "Open File", null);
			}
			else {
				Msg.showError(this, null, "Error Opening " + domainFile.getName(),
					"Opening data type archive failed.\n" + e.getMessage());
			}
		}
	}

	private boolean isRecoveryOK(final DomainFile dfile)
			throws InterruptedException, InvocationTargetException {
		final boolean[] recoverFile = new boolean[] { false };
		if (dfile.isInWritableProject() && dfile.canRecover()) {
			Runnable r = () -> {
				int option = OptionDialog.showYesNoDialog(null, "Crash Recovery Data Found",
					"<html>" + HTMLUtilities.escapeHTML(dfile.getName()) + " has crash data.<br>" +
						"Would you like to recover unsaved changes?");
				recoverFile[0] = (option == OptionDialog.OPTION_ONE);
			};
			SwingUtilities.invokeAndWait(r);
		}
		return recoverFile[0];
	}

	private void openFileInTree(boolean associatedWithOriginalDomainFile) {
		DataTypesProvider provider = dtmPlugin.getProvider();
		GTree tree = provider.getGTree();
		DataTypeManagerHandler manager = dtmPlugin.getDataTypeManagerHandler();
		DomainFile df = associatedWithOriginalDomainFile ? domainFile : dtArchive.getDomainFile();
		Archive archive = manager.openArchive(dtArchive, df);
		GTreeNode node = getNodeForArchive(tree, archive);
		if (node != null) {
			tree.setSelectedNode(node);
		}
	}

	private GTreeNode getNodeForArchive(GTree tree, Archive archive) {
		GTreeNode rootNode = tree.getModelRoot();
		for (GTreeNode node : rootNode.getChildren()) {
			if (node instanceof ArchiveNode) {
				ArchiveNode archiveNode = (ArchiveNode) node;
				if (archiveNode.getArchive() == archive) {
					return archiveNode;
				}
			}
		}

		return null;
	}

}
