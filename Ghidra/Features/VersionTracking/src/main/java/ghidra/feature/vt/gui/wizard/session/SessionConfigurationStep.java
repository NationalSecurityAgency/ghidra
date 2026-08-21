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

import javax.swing.JComponent;

import org.apache.commons.lang3.StringUtils;

import docking.wizard.WizardModel;
import docking.wizard.WizardStep;
import ghidra.app.util.task.OpenProgramRequest;
import ghidra.app.util.task.OpenProgramTask;
import ghidra.feature.vt.api.util.VTSessionFileUtil;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.InvalidNameException;
import ghidra.util.task.TaskLauncher;

/**
 * Wizard step in the new version tracking session wizard for choosing which programs to 
 * track and naming the session.
 */
public class SessionConfigurationStep extends WizardStep<NewSessionData> {

	private PluginTool tool;
	private SessionConfigurationPanel sessionPanel;

	protected SessionConfigurationStep(WizardModel<NewSessionData> model, PluginTool tool) {
		super(model, "New Version Tracking Session",
			new HelpLocation("VersionTrackingPlugin", "New_Session_Panel"));
		this.tool = tool;
		sessionPanel = new SessionConfigurationPanel(this::notifyStatusChanged);
	}

	@Override
	public void initialize(NewSessionData data) {
		sessionPanel.setSessionFolder(data.getSessionFolder());
		sessionPanel.setSourceFile(data.getSourceFile());
		sessionPanel.setDestinationFile(data.getDestinationFile());
	}

	@Override
	public boolean isValid() {
		setStatusMessage("");
		DomainFolder sessionFolder = sessionPanel.getSessionFolder();
		String sessionName = sessionPanel.getSessionName();
		DomainFile sourceFile = sessionPanel.getSourceFile();
		DomainFile destinationFile = sessionPanel.getDestinationFile();

		if (!isValid(sessionFolder, sessionName, sourceFile, destinationFile)) {
			return false;
		}

		return true;
	}

	@Override
	public void populateData(NewSessionData data) {
		data.setSessionName(sessionPanel.getSessionName());
		data.setSessionFolder(sessionPanel.getSessionFolder());
		data.setSourceFile(sessionPanel.getSourceFile(), tool);
		data.setDestinationFile(sessionPanel.getDestinationFile(), tool);
	}

	@Override
	public boolean canFinish(NewSessionData data) {
		return true;
	}

	@Override
	protected void dispose(NewSessionData data) {
		releaseProgram(data.getSourceProgram());
		releaseProgram(data.getDestinationProgram());
	}

	private void releaseProgram(Program program) {
		if (program != null) {
			if (program.getConsumerList().contains(tool)) {
				program.release(tool);
			}
		}
	}

	private boolean isValid(DomainFolder sessionFolder, String sessionName, DomainFile sourceFile,
			DomainFile destinationFile) {
		if (sessionFolder == null) {
			setStatusMessage("Choose a project folder to continue!");
			return false;
		}
		if (sourceFile == null) {
			setStatusMessage("Please choose a source program.");
			return false;
		}
		if (destinationFile == null) {
			setStatusMessage("Please choose a destination program.");
			return false;
		}
		if (sourceFile.equals(destinationFile)) {
			setStatusMessage("Source and destination files must be different.");
			return false;
		}
		if (StringUtils.isBlank(sessionName)) {
			setStatusMessage("Please enter a name for this session");
			return false;
		}
		try {
			tool.getProject().getProjectData().testValidName(sessionName, false);
		}
		catch (InvalidNameException e) {
			setStatusMessage("'" + sessionName + "' contains invalid characters");
			return false;
		}

		DomainFile file = sessionFolder.getFile(sessionName);
		if (file != null) {
			setStatusMessage(
				"'" + file.getPathname() + "' is the name of an existing project file");
			return false;
		}
		return true;
	}

	@Override
	public boolean apply(NewSessionData data) {

		if (data.getSourceProgram() == null) {
			Program program = openSourceProgram(data.getSourceFile());
			if (program == null) {
				return false;
			}
			data.setSourceProgram(program);
		}

		if (data.getDestinationProgram() == null) {
			Program program = openDestinationProgram(data.getDestinationFile());
			if (program == null) {
				return false;
			}
			data.setDestinationProgram(program);
		}
		return true;
	}

	private Program openSourceProgram(DomainFile file) {
		try {
			VTSessionFileUtil.validateSourceProgramFile(file, false);
		}
		catch (Exception e) {
			setStatusMessage(e.getMessage());
			return null;
		}

		Program program = openProgram(file);
		if (program == null) {
			setStatusMessage("Open source program failed for " + file.getPathname());
		}
		return program;
	}

	private Program openDestinationProgram(DomainFile file) {
		try {
			VTSessionFileUtil.validateDestinationProgramFile(file, false, false);
		}
		catch (Exception e) {
			setStatusMessage(e.getMessage());
			return null;
		}

		Program program = openProgram(file);
		if (program == null) {
			setStatusMessage("Open destination program failed for " + file.getPathname());
		}
		return program;
	}

	private Program openProgram(DomainFile domainFile) {

		OpenProgramTask openProgramTask = new OpenProgramTask(domainFile, tool);
		new TaskLauncher(openProgramTask, tool.getActiveWindow());
		OpenProgramRequest openProgramRequest = openProgramTask.getOpenProgram();
		return openProgramRequest != null ? openProgramRequest.getProgram() : null;
	}

	@Override
	public JComponent getComponent() {
		return sessionPanel;
	}

}
