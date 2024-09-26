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
import docking.widgets.SelectFromListDialog;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemRef;
import ghidra.plugins.fsbrowser.*;

public class ListMountedFSBFileHandler implements FSBFileHandler {

	private FSBFileHandlerContext context;

	@Override
	public void init(FSBFileHandlerContext context) {
		this.context = context;
	}

	@Override
	public List<DockingAction> createActions() {
		return List.of(new ActionBuilder("FSB List Mounted Filesystems", context.plugin().getName())
				.description("List Mounted Filesystems")
				.withContext(FSBActionContext.class)
				.enabledWhen(FSBActionContext::notBusy)
				.toolBarIcon(FSBIcons.LIST_MOUNTED)
				.toolBarGroup("ZZZZ")
				.popupMenuIcon(FSBIcons.LIST_MOUNTED)
				.popupMenuPath("List Mounted Filesystems")
				.popupMenuGroup("L")
				.onAction(ac -> {
					FSRLRoot fsFSRL = SelectFromListDialog.selectFromList(
						context.fsService().getMountedFilesystems(), "Select filesystem",
						"Choose filesystem to view", f -> f.toPrettyString());

					FileSystemRef fsRef;
					if (fsFSRL != null &&
						(fsRef = context.fsService().getMountedFilesystem(fsFSRL)) != null) {
						context.fsbComponent().getPlugin().createNewFileSystemBrowser(fsRef, true);
					}
				})
				.build());
	}

}
