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

import org.apache.commons.io.FilenameUtils;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.plugin.importer.ImporterUtilities;
import ghidra.plugins.fsbrowser.*;

public class ImportFSBFileHandler implements FSBFileHandler {

	public static final String FSB_IMPORT_SINGLE = "FSB Import Single";
	private FSBFileHandlerContext context;

	@Override
	public void init(FSBFileHandlerContext context) {
		this.context = context;
	}

	@Override
	public List<DockingAction> createActions() {
		return List.of(new ActionBuilder(FSB_IMPORT_SINGLE, context.plugin().getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && ac.getLoadableFSRL() != null)
				.popupMenuIcon(FSBIcons.IMPORT)
				.popupMenuPath("Import")
				.popupMenuGroup("F", "A")
				.onAction(ac -> {
					FSBNode node = ac.getSelectedNode();
					FSRL fsrl = node.getLoadableFSRL();
					if (fsrl == null) {
						return;
					}

					String suggestedPath = FilenameUtils
							.getFullPathNoEndSeparator(node.getFormattedTreePath())
							.replaceAll(":/", "/");

					FSBComponentProvider fsbComp = ac.getComponentProvider();
					FileSystemBrowserPlugin plugin = fsbComp.getPlugin();
					OpenWithTarget openWith = OpenWithTarget.getDefault(plugin.getTool());

					ac.getTree().runTask(monitor -> {
						if (!fsbComp.ensureFileAccessable(fsrl, node, monitor)) {
							return;
						}
						ImporterUtilities.showImportSingleFileDialog(fsrl, null, suggestedPath,
							plugin.getTool(), openWith.getPm(), monitor);
					});
				})
				.build());
	}

}
