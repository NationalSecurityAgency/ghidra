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
// This script reads the source map information for the current address and uses it to open
// a source file in eclipse at the appropriate line.  If there are multiple source map entries
// at the current address, the script displays a table to allow the user to select which ones
// to send to eclipse.  The source file paths can be adjusted via 
// 
// Window -> Source Files and Transforms
//
// from the Code Browser.  The path to the eclipse installation directory can be set via 
//
// Edit -> Tool Options -> Eclipse Integration
//
// from the Ghidra Project Manager.
//@category SourceMapping
import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.services.EclipseIntegrationService;
import ghidra.util.task.MonitoredRunnable;
import ghidra.util.task.TaskBuilder;

public class OpenSourceFileAtLineInEclipseScript extends OpenSourceFileAtLineInVSCodeScript {

	private EclipseIntegrationService eclipseService;

	@Override
	protected boolean verifyAndSetIdeExe() {
		eclipseService = state.getTool().getService(EclipseIntegrationService.class);
		if (eclipseService == null) {
			popup("Eclipse service not configured for tool");
			return false;
		}
		try {
			ideExecutableFile = eclipseService.getEclipseExecutableFile();
		}
		catch (FileNotFoundException e) {
			printerr(e.getMessage());
			return false;
		}
		return true;
	}

	@Override
	protected void openInIde(String transformedPath, int lineNumber) {
		// transformedPath is a file uri path so it uses forward slashes 
		// File constructor on windows can accept such paths
		File localSourceFile = new File(transformedPath);
		if (!localSourceFile.exists()) {
			popup(transformedPath + " does not exist");
			return;
		}

		MonitoredRunnable r = m -> {
			try {
				List<String> args = new ArrayList<>();
				args.add(ideExecutableFile.getAbsolutePath());
				args.add(localSourceFile.getAbsolutePath() + ":" + lineNumber);
				new ProcessBuilder(args).redirectErrorStream(true).start();
			}
			catch (Exception e) {
				eclipseService.handleEclipseError(
					"Unexpected exception occurred while launching Eclipse.", false,
					null);
				return;
			}
		};

		new TaskBuilder("Opening File in Eclipse", r)
				.setHasProgress(false)
				.setCanCancel(true)
				.launchModal();
		return;

	}

}
