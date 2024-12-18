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
import docking.widgets.OptionDialog;
import ghidra.plugins.fsbrowser.*;

public class CloseFSBFileHandler implements FSBFileHandler {

	public static final String FSB_CLOSE = "FSB Close";
	private FSBFileHandlerContext context;

	@Override
	public void init(FSBFileHandlerContext context) {
		this.context = context;
	}

	@Override
	public List<DockingAction> createActions() {
		return List.of(new ActionBuilder(FSB_CLOSE, context.plugin().getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && ac.getSelectedNode() instanceof FSBRootNode)
				.description("Close")
				.toolBarIcon(FSBIcons.CLOSE)
				.toolBarGroup("ZZZZ")
				.popupMenuIcon(FSBIcons.CLOSE)
				.popupMenuPath("Close")
				.popupMenuGroup("ZZZZ")
				.onAction(ac -> {
					FSBNode selectedNode = ac.getSelectedNode();
					if (!(selectedNode instanceof FSBRootNode node)) {
						return;
					}
					if (node.getParent() == null) {
						// Close entire window
						if (OptionDialog.showYesNoDialog(ac.getSourceComponent(),
							"Close File System",
							"Do you want to close the filesystem browser for %s?"
									.formatted(node.getName())) == OptionDialog.YES_OPTION) {
							ac.getComponentProvider().componentHidden();	// cause component to close itself
						}
					}
					else {
						// Close file system that is nested in the container's tree and swap
						// in the saved node that was the original container file
						ac.getComponentProvider()
								.runTask(monitor -> node.swapBackPrevModelNodeAndDispose());
					}
				})
				.build());
	}

}
