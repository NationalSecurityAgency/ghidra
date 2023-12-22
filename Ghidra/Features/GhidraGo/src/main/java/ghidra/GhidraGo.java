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
package ghidra;

import java.io.IOException;
import java.nio.file.Path;

import docking.framework.DockingApplicationConfiguration;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.go.GhidraGoSender;
import ghidra.app.plugin.core.go.exception.*;
import ghidra.framework.*;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.util.*;

/**
 * <h1>GhidraGo Client</h1>
 * <p>The first argument is expected to be non-null and a valid {@link GhidraURL}</p>
 * <p>If the {@link GhidraURL} is valid, the URL is processed in an existing Ghidra, or
 * a new Ghidra is started and used to process the URL.</p>
 * <p>A valid {@link GhidraURL} in this case must be pointing to a remote (shared project) 
 * Program.</p>
 * <p>In the event that a Ghidra is running and does not have an active project, the URL cannot be 
 * processed.</p>
 */
public class GhidraGo implements GhidraLaunchable {
	
	private GhidraGoSender sender;

	/**
	 * Initializes a new GhidraGoSender and processes the {@link GhidraURL}
	 * @param layout the layout passed from main.Ghidra
	 * @param args the CLI args passed to GhidraGo. args should contain a single {@link GhidraURL}.
	 * @throws Exception in the event of an error
	 */
	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
		try {
			ApplicationConfiguration configuration = null;
			if (!Application.isInitialized()) {
				System.setProperty(ApplicationProperties.APPLICATION_NAME_PROPERTY, "GhidraGo");
				configuration = new DockingApplicationConfiguration();
				Application.initializeApplication(layout, configuration);
			}
			if (args != null && args.length > 0) {
				ghidra.framework.protocol.ghidra.Handler.registerHandler();
				sender = new GhidraGoSender();

				startGhidraIfNeeded(layout);

				sender.send(args[0]);
				// if configuration is null, probably running inside a test
				if (configuration != null) {
					// calling System.exit explicitly is necessary, otherwise the Loading... screen
					// persists instead of closing when complete.
					System.exit(0);
				}
			}
			else {
				throw new IllegalArgumentException(
					"A valid GhidraURL locating a program, program name, or path to a program name " +
						"must be specified as the first command line argument.");
			}
		}
		catch (FailedToStartGhidraException e) {
			logOrShowError("GhidraGo Start Ghidra Exception",
				"Failed to start Ghidra from GhidraGo", e);
			System.exit(-1);
		}
		catch (StopWaitingException e) {
			System.exit(-1);
		}
		catch (Exception e) {
			logOrShowError("GhidraGo Exception", "An unexpected exception occurred in GhidraGo", e);
			// calling System.exit explicitly is necessary, otherwise the Loading... screen
			// persists instead of closing when complete.
			System.exit(-1);
		}
	}

	private void logOrShowError(String errorTitle, String errorMessage, Exception e) {
		if (SystemUtilities.isInHeadlessMode()) {
			Msg.error(this, errorMessage, e);
		}
		else {
			Swing.runNow(() -> Msg.showError(this, null, errorTitle, errorMessage, e));
		}
	}

	private void startGhidraIfNeeded(GhidraApplicationLayout layout)
			throws StopWaitingException, FailedToStartGhidraException {
		// if there is no listening Ghidra
		if (!sender.isGhidraListening()) {

			// attempt to start a Ghidra within a locked action
			// do not wait for the lock if another GhidraGo has been started.
			try {
				boolean success = sender.doLockedAction(false, () -> {
					try {
						Process ghidraProcess = startGhidra(layout);
						sender.waitForListener(ghidraProcess);
						return true;
					}
					catch (StopWaitingException e) {
						return true;
					}
					catch (StartedGhidraProcessExitedException | IOException e) {
						return false;
					}
				});
				if (!success) {
					// GhidraGo attempted to start ghidra and failed
					throw new FailedToStartGhidraException();
				}
			}
			catch (UnableToGetLockException e) {
				// When another GhidraGo has the lock,
				// wait for there to be a listener without starting the process
				sender.waitForListener();
			}
		}
	}

	/**
	 * Determines the execution platform and executes the appropriate shell/bash script to start 
	 * Ghidra. 
	 * @throws IOException in the event that the execution failed
	 */
	private Process startGhidra(GhidraApplicationLayout layout) throws IOException {
		ResourceFile file = layout.getApplicationInstallationDir();
		Path ghidraRunPath;

		if (SystemUtilities.isInDevelopmentMode()) {
			if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS) {
				ghidraRunPath = Path.of(file.getAbsolutePath(),
					"/ghidra/Ghidra/RuntimeScripts/Windows/ghidraRun.bat");
			}
			else {
				ghidraRunPath = Path.of(file.getAbsolutePath(),
					"/ghidra/Ghidra/RuntimeScripts/Linux/ghidraRun");
			}
		}
		else {
			if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS) {
				ghidraRunPath = Path.of(file.getAbsolutePath(), "/ghidraRun.bat");
			}
			else {
				ghidraRunPath = Path.of(file.getAbsolutePath(), "/ghidraRun");
			}
		}

		Msg.info(this, "Starting new Ghidra using ghidraRun script at " + ghidraRunPath);
		return Runtime.getRuntime().exec(ghidraRunPath.toString());
	}
}
