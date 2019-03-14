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
/**
 *
 */
package ghidra.framework.main.datatree;

import java.awt.datatransfer.DataFlavor;
import java.io.File;
import java.util.List;

import docking.widgets.tree.GTreeNode;
import ghidra.app.services.FileImporterService;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.DomainFolder;
import ghidra.util.Msg;
import util.CollectionUtils;

/**
 * A drag-and-drop handler for trees that is specific to List&ltFile&gt. (see
 * {@link DataFlavor#javaFileListFlavor}).
 */
final class JavaFileListHandler implements DataFlavorHandler {
	@Override
	public void handle(FrontEndTool tool, DataTree dataTree, GTreeNode destinationNode,
			Object transferData, int dropAction) {
		DomainFolder folder = getDomainFolder(destinationNode);

		FileImporterService im = tool.getService(FileImporterService.class);
		if (im == null) {
			Msg.showError(this, dataTree, "Could Not Import", "Could not find importer service");
			return;
		}

		List<File> fileList = CollectionUtils.asList((List<?>) transferData, File.class);
		if (fileList.size() == 1 && fileList.get(0).isFile()) {
			im.importFile(folder, fileList.get(0));
		}
		else {
			im.importFiles(folder, fileList);
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
