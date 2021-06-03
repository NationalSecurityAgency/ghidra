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
package help.screenshot;

import java.io.IOException;

import org.junit.Test;

import docking.DockingWindowManager;
import docking.ErrLogDialog;
import docking.widgets.OkDialog;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class IntroScreenShots extends GhidraScreenShotGenerator {

	public IntroScreenShots() {
		super();
	}

	@Override
	public void prepareTool() {
		tool = getFrontEndTool();
	}

	@Override
	public void loadProgram() {
		// don't need to load a program
	}

	@Test
	public void testEmpty_ghidra() {
		performAction("Close Project", "FrontEndPlugin", true);
		Msg.info("RecoverySnapshotMgrPlugin", "Recovery snapshot timer set to 5 minute(s)");
		captureToolWindow(600, 500);
	}

	@Test
	public void testErr_Dialog() {
		runSwing(() -> {
			ErrLogDialog dialog = ErrLogDialog.createExceptionDialog("Unexpected Error",
				"Oops, this is really bad!", new Throwable());
			DockingWindowManager.showDialog(null, dialog);
		}, false);
		waitForSwing();
		captureDialog();

	}

	@Test
	public void testOpen_ghidra() throws InvalidNameException, CancelledException, IOException {
		program = env.getProgram("WinHelloCPP.exe");
		Project project = env.getProject();
		ProjectData projectData = project.getProjectData();
		projectData.getRootFolder().createFile("WinHelloCpp.exe", program, TaskMonitor.DUMMY);
		projectData.getRootFolder().createFile("AnotherProgram.exe", program, TaskMonitor.DUMMY);
		waitForSwing();
		Msg.info("ProjectImpl", "Opening project: " + tool.getProject().getName());
		captureToolWindow(600, 500);
	}

	@Test
	public void testSimple_err_dialog() {

		OkDialog.showError("Some Resonable Error",
			"Your operation did not complete because... (i.e File Not Found)");
		captureDialog();
	}

}
