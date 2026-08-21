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

import java.awt.Component;
import java.io.IOException;
import java.util.List;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import ghidra.app.util.importer.LibrarySearchPathManager;
import ghidra.formats.gfilesystem.*;
import ghidra.plugins.fsbrowser.*;
import ghidra.util.Msg;

public class LibrarySearchPathFSBFileHandler implements FSBFileHandler {

	private FSBFileHandlerContext context;

	@Override
	public void init(FSBFileHandlerContext context) {
		this.context = context;
	}

	@Override
	public List<DockingAction> createActions() {
		return List.of(new ActionBuilder("FSB Add Library Search Path", context.plugin().getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && ac.getFSRL(true) != null)
				.popupMenuPath("Add Library Search Path")
				.popupMenuGroup("F", "D")
				.popupMenuIcon(FSBIcons.LIBRARY)
				.description("Add file/folder to library search paths")
				.onAction(ac -> {
					Component parentComp = context.fsbComponent().getComponent();
					try {
						FSRL fsrl = ac.getFSRL(true);
						FileSystemService fsService = context.fsService();
						LocalFileSystem localFs = fsService.getLocalFS();
						String path = fsService.isLocal(fsrl)
								? localFs.getLocalFile(fsrl).getPath()
								: fsrl.toString();
						if (LibrarySearchPathManager.addPath(path)) {
							Msg.showInfo(this, parentComp, "Add Library Search Path",
								"Added '%s' to library search paths.".formatted(fsrl));
						}
						else {
							Msg.showInfo(this, parentComp, "Add Library Search Path",
								"Library search path '%s' already exists.".formatted(fsrl));
						}
					}
					catch (IOException e) {
						Msg.showError(this, parentComp, "Add Library Search Path", e);
					}
				})
				.build());
	}

}
