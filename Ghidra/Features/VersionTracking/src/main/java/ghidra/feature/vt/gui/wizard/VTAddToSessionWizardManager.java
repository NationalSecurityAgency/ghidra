/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.feature.vt.gui.wizard;

import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.program.model.listing.Program;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;

import java.util.ArrayList;

import docking.wizard.*;

public class VTAddToSessionWizardManager extends AbstractMagePanelManager<VTWizardStateKey> {

	private final VTController controller;

	public VTAddToSessionWizardManager(VTController controller) {
		super(new WizardState<VTWizardStateKey>());
		this.controller = controller;
		Program sourceProgram = controller.getSourceProgram();
		Program destinationProgram = controller.getDestinationProgram();
		VTSession session = controller.getSession();

		WizardState<VTWizardStateKey> state = getState();
		state.put(VTWizardStateKey.SOURCE_PROGRAM, sourceProgram);
		state.put(VTWizardStateKey.DESTINATION_PROGRAM, destinationProgram);
		state.put(VTWizardStateKey.SOURCE_PROGRAM_FILE, sourceProgram.getDomainFile());
		state.put(VTWizardStateKey.DESTINATION_PROGRAM_FILE, destinationProgram.getDomainFile());
		state.put(VTWizardStateKey.EXISTING_SESSION, session);
		state.put(VTWizardStateKey.SESSION_NAME, session.getName());
		state.put(VTWizardStateKey.WIZARD_OP_DESCRIPTION, "Add to Version Tracking Session");
		state.put(VTWizardStateKey.SOURCE_SELECTION, controller.getSelectionInSourceTool());
		state.put(VTWizardStateKey.DESTINATION_SELECTION,
			controller.getSelectionInDestinationTool());

	}

	protected ArrayList<MagePanel<VTWizardStateKey>> createPanels() {
		ArrayList<MagePanel<VTWizardStateKey>> panels =
			new ArrayList<MagePanel<VTWizardStateKey>>();
		panels.add(new CorrelatorPanel(controller.getSession()));
		panels.add(new OptionsPanel());
		panels.add(new AddressSetOptionsPanel());
		panels.add(new LimitAddressSetsPanel(controller.getTool()));
		panels.add(new SummaryPanel());
		return panels;
	}

	@Override
	protected void doFinish() {
		try {
			Task task = new AddToSessionTask(controller, getState());
			new TaskLauncher(task, getWizardManager().getComponent());
		}
		finally {
			getWizardManager().completed(true);
		}
	}

}
