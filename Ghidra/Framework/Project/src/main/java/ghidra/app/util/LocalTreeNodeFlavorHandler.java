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
/**
 * 
 */
package ghidra.app.util;

import ghidra.framework.main.GetVersionedObjectTask;
import ghidra.framework.main.datatree.*;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;

import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DropTargetDropEvent;
import java.util.List;

final class LocalTreeNodeFlavorHandler implements FileOpenDataFlavorHandler {
	public void handle(PluginTool tool, Object obj, DropTargetDropEvent e, DataFlavor f) {
		if (f.equals(DataTreeDragNDropHandler.localDomainFileFlavor)) {
			List<?> files = (List<?>) obj;
			DomainFile[] domainFiles = new DomainFile[files.size()];
			for (int i = 0; i < files.size(); i++) {
				domainFiles[i] = (DomainFile) files.get(i);
			}
			tool.acceptDomainFiles(domainFiles);
		}
		else if (f.equals(DataTreeDragNDropHandler.localDomainFileTreeFlavor)) {
			List<?> files = (List<?>) obj;
			DomainFile[] domainFiles = new DomainFile[files.size()];
			for (int i = 0; i < files.size(); i++) {
				DomainFileNode node = (DomainFileNode) files.get(i);
				domainFiles[i] = node.getDomainFile();
			}
			tool.acceptDomainFiles(domainFiles);
		}
		else if (f.equals(VersionInfoTransferable.localVersionInfoFlavor)) {
			VersionInfo info = (VersionInfo) obj;
			Project project = tool.getProject();
			ProjectData projectData = project.getProjectData();
			DomainFile file = projectData.getFile(info.getDomainFilePath());
			DomainObject versionedObj = getVersionedObject(tool, file, info.getVersionNumber());

			if (versionedObj != null) {
				DomainFile domainFile = versionedObj.getDomainFile();
				if (domainFile != null) {
					tool.acceptDomainFiles(new DomainFile[] { domainFile });
				}
				versionedObj.release(this);
			}
		}
	}

	private DomainObject getVersionedObject(PluginTool tool, DomainFile file, int versionNumber) {
		GetVersionedObjectTask task = new GetVersionedObjectTask(this, file, versionNumber);
		tool.execute(task, 250);
		return task.getVersionedObject();
	}
}
