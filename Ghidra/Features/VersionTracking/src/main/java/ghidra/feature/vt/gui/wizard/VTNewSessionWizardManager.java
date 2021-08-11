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
package ghidra.feature.vt.gui.wizard;

import java.util.ArrayList;
import java.util.List;

import docking.wizard.*;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;

public class VTNewSessionWizardManager extends AbstractMagePanelManager<VTWizardStateKey> {

	private final VTController controller;

	public VTNewSessionWizardManager(VTController controller) {
		super(new WizardState<VTWizardStateKey>());
		this.controller = controller;
		getState().put(VTWizardStateKey.WIZARD_OP_DESCRIPTION, "New Version Tracking Session");
	}

	public VTNewSessionWizardManager(VTController controller, DomainFile sourceFile,
			DomainFile destinationFile) {
		this(controller);
		getState().put(VTWizardStateKey.SOURCE_PROGRAM_FILE, sourceFile);
		getState().put(VTWizardStateKey.DESTINATION_PROGRAM_FILE, destinationFile);
	}

	@Override
	protected List<MagePanel<VTWizardStateKey>> createPanels() {
		List<MagePanel<VTWizardStateKey>> panels =
			new ArrayList<>();
		panels.add(new NewSessionPanel(controller.getTool()));
		panels.add(new PreconditionsPanel(this));
		panels.add(new SummaryPanel());
		return panels;
	}

	@Override
	protected void doFinish() {
		try {
			Task task = new CreateNewSessionTask(controller, getState());
			new TaskLauncher(task, getWizardManager().getComponent());
		}
		finally {
			getWizardManager().completed(true);
			cleanup();
		}
	}

	@Override
	public void cancel() {
		cleanup();
	}

	private void cleanup() {
		List<MagePanel<VTWizardStateKey>> panels = getPanels();
		for (MagePanel<VTWizardStateKey> magePanel : panels) {
			magePanel.dispose();
		}
	}

	public PluginTool getTool() {
		return controller.getTool();
	}

}
