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
package ghidra.file.formats.ios.prelink;

import java.util.ArrayList;
import java.util.List;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTreeNode;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.plugins.fsbrowser.*;
import ghidra.util.task.TaskLauncher;

public class MachoPrelinkFSBFileHandler implements FSBFileHandler {

	private FSBFileHandlerContext context;

	@Override
	public void init(FSBFileHandlerContext context) {
		this.context = context;
	}

	@Override
	public List<DockingAction> createActions() {
		return List.of(new ActionBuilder("FSB Load iOS Kernel", context.plugin().getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> {
					if (ac.isBusy() || ac.getSelectedNode() == null) {
						return false;
					}
					FSBRootNode rootNode = ac.getSelectedNode().getFSBRootNode();
					return rootNode != null && rootNode.getFSRef() != null &&
						rootNode.getFSRef().getFilesystem() instanceof MachoPrelinkFileSystem;
				})
				.popupMenuPath("Load iOS Kernel")
				.popupMenuIcon(FSBIcons.iOS)
				.popupMenuGroup("I")
				.onAction(ac -> {
					FSRL fsrl = ac.getFSRL(true);
					List<FSRL> fileList = new ArrayList<>();

					if (fsrl != null) {
						FSBNode selectedNode = ac.getSelectedNode();
						if (selectedNode instanceof FSBRootNode) {
							for (GTreeNode childNode : ac.getSelectedNode().getChildren()) {
								if (childNode instanceof FSBNode baseNode) {
									fileList.add(baseNode.getFSRL());
								}
							}
						}
						else if (selectedNode instanceof FSBFileNode ||
							selectedNode instanceof FSBDirNode) {
							fileList.add(fsrl);
						}
					}

					if (!fileList.isEmpty()) {
						if (OptionDialog.showYesNoDialog(null, "Load iOS Kernel?",
							"Performing this action will load the entire kernel and all KEXT files.\n" +
								"Do you want to continue?") == OptionDialog.YES_OPTION) {
							loadIOSKernel(fileList);
						}
					}
					else {
						ac.getComponentProvider()
								.getPlugin()
								.getTool()
								.setStatusInfo("Load iOS kernel -- nothing to do.");
					}
				})
				.build()

		);
	}

	private void loadIOSKernel(List<FSRL> fileList) {
		FileSystemBrowserPlugin fsbPlugin = context.plugin();
		OpenWithTarget openWith = OpenWithTarget.getRunningProgramManager(fsbPlugin.getTool());
		if (openWith.getPm() != null) {
			TaskLauncher
					.launch(new GFileSystemLoadKernelTask(fsbPlugin, openWith.getPm(), fileList));
		}
	}

}
