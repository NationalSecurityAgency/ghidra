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
import ghidra.formats.gfilesystem.FileSystemRef;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.plugins.fsbrowser.*;

public class OpenFsFSBFileHandler implements FSBFileHandler {

	private static final String FSB_OPEN_ROOT_FS = "FSB Open My Computer";
	public static final String FSB_OPEN_FILE_SYSTEM_CHOOSER = "FSB Open File System Chooser";
	public static final String FSB_OPEN_FILE_SYSTEM_IN_NEW_WINDOW =
		"FSB Open File System In New Window";
	public static final String FSB_OPEN_FILE_SYSTEM_NESTED = "FSB Open File System Nested";

	private FSBFileHandlerContext context;

	@Override
	public void init(FSBFileHandlerContext context) {
		this.context = context;
	}

	@Override
	public List<DockingAction> createActions() {
		return List.of(
			new ActionBuilder(FSB_OPEN_FILE_SYSTEM_NESTED, context.plugin().getName())
					.withContext(FSBActionContext.class)
					.enabledWhen(ac -> ac.notBusy() &&
						ac.getSelectedNode() instanceof FSBFileNode fileNode && fileNode.isLeaf() &&
						!fileNode.isSymlink())
					.popupMenuIcon(FSBIcons.OPEN_FILE_SYSTEM)
					.popupMenuPath("Open File System")
					.popupMenuGroup("C")
					.onAction(
						ac -> ac.getComponentProvider().openFileSystem(ac.getSelectedNode(), true))
					.build(),

			new ActionBuilder(FSB_OPEN_FILE_SYSTEM_IN_NEW_WINDOW, context.plugin().getName())
					.withContext(FSBActionContext.class)
					.enabledWhen(ac -> ac.notBusy() &&
						ac.getSelectedNode() instanceof FSBFileNode fileNode && fileNode.isLeaf() &&
						!fileNode.isSymlink())
					.popupMenuIcon(FSBIcons.OPEN_FILE_SYSTEM)
					.popupMenuPath("Open File System in new window")
					.popupMenuGroup("C")
					.onAction(
						ac -> ac.getComponentProvider().openFileSystem(ac.getSelectedNode(), false))
					.build(),

			new ActionBuilder(FSB_OPEN_ROOT_FS, context.plugin().getName())
					.description("Show the 'My Computer' location")
					.enabledWhen(ac -> !context.fsbComponent().getGTree().isBusy())
					.toolBarIcon(FSBIcons.MY_COMPUTER)
					.toolBarGroup("B")
					.onAction(ac -> {
						FileSystemService fsService = context.fsService();
						FileSystemRef fsRef =
							fsService.getMountedFilesystem(fsService.getLocalFS().getFSRL());
						context.plugin().createNewFileSystemBrowser(fsRef, true);
					})
					.build(),

			new ActionBuilder(FSB_OPEN_FILE_SYSTEM_CHOOSER, context.plugin().getName())
					.description("Open File System Chooser")
					.enabledWhen(ac -> !context.fsbComponent().getGTree().isBusy())
					.toolBarIcon(FSBIcons.OPEN_FILE_SYSTEM)
					.toolBarGroup("B")
					.onAction(ac -> context.plugin().openFileSystem())
					.build()
		);
	}

}
