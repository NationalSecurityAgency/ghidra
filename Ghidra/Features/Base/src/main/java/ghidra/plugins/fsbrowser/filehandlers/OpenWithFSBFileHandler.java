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

import java.util.*;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import ghidra.framework.model.DomainFile;
import ghidra.plugin.importer.ProjectIndexService;
import ghidra.plugins.fsbrowser.*;

public class OpenWithFSBFileHandler implements FSBFileHandler {

	private FSBFileHandlerContext context;

	@Override
	public void init(FSBFileHandlerContext context) {
		this.context = context;
	}

	@Override
	public List<DockingAction> getPopupProviderActions() {
		FileSystemBrowserPlugin plugin = context.plugin();
		List<DockingAction> results = new ArrayList<>();
		for (OpenWithTarget target : OpenWithTarget.getAll()) {
			DockingAction action =
				new ActionBuilder("FSB Open With " + target.getName(), plugin.getName())
						.withContext(FSBActionContext.class)
						.enabledWhen(ac -> ac.notBusy() && ac.hasSelectedLinkedNodes())
						.popupMenuIcon(target.getIcon())
						.popupMenuPath("Open With", target.getName())
						.popupMenuGroup(target.getPm() != null ? "A" : "B") // list running targets first
						.onAction(ac -> {
							FSBComponentProvider fsbComp = ac.getComponentProvider();
							ProjectIndexService projectIndex = fsbComp.getProjectIndex();
							List<DomainFile> filesToOpen = ac.getSelectedNodes()
									.stream()
									.map(node -> projectIndex.findFirstByFSRL(node.getFSRL()))
									.filter(Objects::nonNull)
									.toList();
							target.open(filesToOpen);
						})
						.build();
			action.getPopupMenuData().setParentMenuGroup("C");
			results.add(action);
		}
		return results;
	}

}
