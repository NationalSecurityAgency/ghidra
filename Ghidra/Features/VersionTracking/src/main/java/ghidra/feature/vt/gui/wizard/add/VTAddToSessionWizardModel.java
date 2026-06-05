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
package ghidra.feature.vt.gui.wizard.add;

import java.util.List;

import docking.wizard.WizardModel;
import docking.wizard.WizardStep;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.program.model.listing.Program;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;

/**
 * Wizard model for adding correlation runs to an existing version tracking session.
 */
public class VTAddToSessionWizardModel extends WizardModel<AddToSessionData> {

	private final VTController controller;

	public VTAddToSessionWizardModel(VTController controller) {
		super("Add to Version Tracking Session", new AddToSessionData());
		this.controller = controller;
		Program sourceProgram = controller.getSourceProgram();
		Program destinationProgram = controller.getDestinationProgram();
		VTSession session = controller.getSession();

		data.setSourceProgram(sourceProgram);
		data.setDestinationProgram(destinationProgram);
		data.setSession(session);
		data.setSourceSelection(controller.getSelectionInSourceTool());
		data.setDestinationSelection(controller.getSelectionInDestinationTool());

	}

	@Override
	protected void addWizardSteps(List<WizardStep<AddToSessionData>> list) {
		list.add(new CorrelatorChooserStep(this, controller.getSession()));
		list.add(new OptionsStep(this));
		list.add(new AddressSetOptionsStep(this));
		list.add(new LimitAddressSetsStep(this, controller.getTool()));
		list.add(new SummaryStep(this));

	}

	@Override
	protected boolean doFinish() {
		Task task = new AddToSessionTask(controller, data);
		new TaskLauncher(task, wizardDialog.getComponent());
		return true;
	}
}
