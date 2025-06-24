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
package ghidra.feature.vt.gui.wizard.session;

import java.util.List;

import docking.wizard.WizardModel;
import docking.wizard.WizardStep;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;

/**
 * Wizard model for creating a new version tracking session.
 */
public class VTNewSessionWizardModel extends WizardModel<NewSessionData> {

	private final VTController controller;

	public VTNewSessionWizardModel(VTController controller) {
		this(controller, null, null);
	}

	public VTNewSessionWizardModel(VTController controller, DomainFile sourceFile,
			DomainFile destinationFile) {
		super("New Version Tracking Session", new NewSessionData());
		this.controller = controller;
		PluginTool tool = controller.getTool();
		data.setSourceFile(sourceFile, tool);
		data.setDestinationFile(destinationFile, tool);
		DomainFolder folder = tool.getProject().getProjectData().getRootFolder();
		data.setSessionFolder(folder);
	}

	@Override
	protected void addWizardSteps(List<WizardStep<NewSessionData>> list) {
		list.add(new SessionConfigurationStep(this, controller.getTool()));
		list.add(new PreconditionsStep(this));
		list.add(new SummaryStep(this));

	}

	@Override
	protected boolean doFinish() {
		Task task = new CreateNewSessionTask(controller, data);
		new TaskLauncher(task, wizardDialog.getComponent());
		return true;
	}

}
