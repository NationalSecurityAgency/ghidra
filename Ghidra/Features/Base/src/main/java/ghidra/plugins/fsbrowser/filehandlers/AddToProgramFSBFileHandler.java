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
import ghidra.plugin.importer.ImporterUtilities;
import ghidra.plugins.fsbrowser.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class AddToProgramFSBFileHandler implements FSBFileHandler {

	private FSBFileHandlerContext context;

	@Override
	public void init(FSBFileHandlerContext context) {
		this.context = context;
	}

	@Override
	public List<DockingAction> createActions() {
		return List.of(new ActionBuilder("FSB Add To Program", context.plugin().getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(ac -> ac.notBusy() && ac.getLoadableFSRL() != null)
				.popupMenuIcon(FSBIcons.IMPORT)
				.popupMenuPath("Add To Program")
				.popupMenuGroup("F", "C")
				.onAction(ac -> {
					FSRL fsrl = ac.getLoadableFSRL();
					if (fsrl == null) {
						return;
					}
					OpenWithTarget openWith =
						OpenWithTarget.getRunningProgramManager(context.plugin().getTool());
					if (openWith == null || openWith.getPm().getCurrentProgram() == null) {
						Msg.showError(this, ac.getSourceComponent(), "Unable To Add To Program",
							"No programs are open");
						return;
					}

					FSBComponentProvider fsbComp = ac.getComponentProvider();
					Program program = openWith.getPm().getCurrentProgram();
					if (program != null) {
						fsbComp.runTask(monitor -> {
							if (fsbComp.ensureFileAccessable(fsrl, ac.getSelectedNode(), monitor)) {
								ImporterUtilities.showAddToProgramDialog(fsrl, program,
									fsbComp.getTool(), monitor);
							}
						});
						return;
					}
				})
				.build());
	}

}
