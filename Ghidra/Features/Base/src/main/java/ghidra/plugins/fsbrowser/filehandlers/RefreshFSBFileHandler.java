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
import docking.widgets.tree.GTree;
import ghidra.plugins.fsbrowser.*;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class RefreshFSBFileHandler implements FSBFileHandler {

	private FSBFileHandlerContext context;

	@Override
	public void init(FSBFileHandlerContext context) {
		this.context = context;
	}

	@Override
	public List<DockingAction> createActions() {
		return List.of(new ActionBuilder("FSB Refresh", context.plugin().getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && ac.hasSelectedNodes())
				.popupMenuPath("Refresh")
				.popupMenuGroup("Z", "Z")
				.popupMenuIcon(FSBIcons.REFRESH)
				.toolBarIcon(FSBIcons.REFRESH)
				.description("Refresh file info")
				.onAction(ac -> ac.getComponentProvider()
						.runTask(
							monitor -> doRefreshInfo(ac.getSelectedNodes(), ac.getTree(), monitor)))
				.build());
	}

	void doRefreshInfo(List<FSBNode> nodes, GTree gTree, TaskMonitor monitor) {
		try {
			for (FSBNode node : nodes) {
				node.refreshNode(monitor);
			}

			gTree.refilterLater();	// force the changed modelNodes to be recloned and displayed (if filter active)
		}
		catch (CancelledException e) {
			// stop
		}
		Swing.runLater(() -> gTree.repaint());
	}

}
