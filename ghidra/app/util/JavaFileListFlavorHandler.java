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
package ghidra.app.util;

import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DropTargetDropEvent;
import java.io.File;
import java.util.List;

import ghidra.app.services.FileImporterService;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.plugintool.PluginTool;
import util.CollectionUtils;

final class JavaFileListFlavorHandler implements FileOpenDataFlavorHandler {
	@Override
	public void handle(PluginTool tool, Object obj, DropTargetDropEvent e, DataFlavor f) {
		List<File> files = CollectionUtils.asList((List<?>) obj, File.class);

		FileImporterService im = tool.getService(FileImporterService.class);
		if (im == null) {
			tool.setStatusInfo("ERROR: Could not get importer service.");
			return;
		}

		DomainFolder rootFolder = tool.getProject().getProjectData().getRootFolder();

		if (files.size() == 1 && files.get(0).isFile()) {
			im.importFile(rootFolder, files.get(0));
		}
		else {
			im.importFiles(rootFolder, files);
		}
	}
}
