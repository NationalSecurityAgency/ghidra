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

import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DropTargetDropEvent;
import java.io.IOException;

import docking.widgets.tree.GTreeNode;
import ghidra.app.util.FileOpenDataFlavorHandler;
import ghidra.framework.client.*;
import ghidra.framework.main.GetVersionedObjectTask;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.task.TaskLauncher;

public final class LocalVersionInfoHandler
		implements DataTreeFlavorHandler, FileOpenDataFlavorHandler {

	@Override
	public void handle(PluginTool tool, Object obj, DropTargetDropEvent e, DataFlavor f) {
		VersionInfo info = (VersionInfo) obj;

		DomainFile file = tool.getProject().getProjectData().getFile(info.getDomainFilePath());
		GetVersionedObjectTask task =
			new GetVersionedObjectTask(this, file, info.getVersionNumber());
		tool.execute(task, 250);
		DomainObject versionedObj = task.getVersionedObject();

		if (versionedObj != null) {
			DomainFile vfile = versionedObj.getDomainFile();
			tool.acceptDomainFiles(new DomainFile[] { vfile });
			versionedObj.release(this);
		}
	}

	@Override
	public void handle(PluginTool tool, DataTree dataTree, GTreeNode destinationNode,
			Object transferData, int dropAction) {
		DomainFolder folder = getDomainFolder(destinationNode);

		VersionInfo info = (VersionInfo) transferData;
		RepositoryAdapter rep = tool.getProject().getProjectData().getRepository();
		try {
			if (rep != null) {
				rep.connect();
			}
			DomainFile file = tool.getProject().getProjectData().getFile(info.getDomainFilePath());
			if (file != null) {
				new TaskLauncher(new CopyFileVersionTask(file, info.getVersionNumber(), folder),
					dataTree, 500);
			}
		}
		catch (NotConnectedException exc) {
			// not sure why we squash this?
		}
		catch (IOException exc) {
			ClientUtil.handleException(rep, exc, "Repository Connection", tool.getToolFrame());
		}
	}

	private DomainFolder getDomainFolder(GTreeNode destinationNode) {
		if (destinationNode instanceof DomainFolderNode) {
			return ((DomainFolderNode) destinationNode).getDomainFolder();
		}
		else if (destinationNode instanceof DomainFileNode) {
			DomainFolderNode parent = (DomainFolderNode) destinationNode.getParent();
			return parent.getDomainFolder();
		}
		return null;
	}
}
