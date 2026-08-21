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
package ghidra.plugins.fsbrowser.filehandlers;

import java.util.List;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.framework.plugintool.PluginTool;
import ghidra.plugins.fsbrowser.*;
import ghidra.plugins.importer.batch.BatchImportDialog;

public class BatchImportFSBFileHandler implements FSBFileHandler {

	private FSBFileHandlerContext context;

	@Override
	public void init(FSBFileHandlerContext context) {
		this.context = context;
	}

	@Override
	public List<DockingAction> createActions() {
		return List.of(new ActionBuilder("FSB Import Batch", context.plugin().getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && ac.getSelectedCount() > 0)
				.popupMenuIcon(FSBIcons.IMPORT)
				.popupMenuPath("Batch Import")
				.popupMenuGroup("F", "B")
				.onAction(ac -> {
					// Do some fancy selection logic.
					// If the user selected a combination of files and folders,
					// ignore the folders.
					// If they only selected folders, leave them in the list.
					List<FSRL> files = ac.getFSRLs(true);
					if (files.isEmpty()) {
						return;
					}

					boolean allDirs = ac.isSelectedAllDirs();
					if (files.size() > 1 && !allDirs) {
						files = ac.getFileFSRLs();
					}

					PluginTool tool = context.plugin().getTool();
					OpenWithTarget openWith = OpenWithTarget.getDefault(tool);
					BatchImportDialog.showAndImport(tool, null, files, null, openWith.getPm());
				})
				.build());

	}

}
