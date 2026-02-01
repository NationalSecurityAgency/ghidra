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
package ghidra.jython;

import java.io.IOException;

import org.python.util.jython;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.framework.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

/**
 * Launcher entry point for running Ghidra from within Jython.
 */
public class JythonRun implements GhidraLaunchable {

	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) {
		
		// Initialize the application
		ApplicationConfiguration configuration = new HeadlessGhidraApplicationConfiguration();
		Application.initializeApplication(layout, configuration);
		
		// Setup jython home directory
		try {
			JythonUtils.setupJythonHomeDir();
		}
		catch (IOException e) {
			Msg.showError(JythonRun.class, null, "Jython home directory", e.getMessage());
			System.exit(1);
		}

		// Setup jython cache directory
		try {
			JythonUtils.setupJythonCacheDir(configuration.getTaskMonitor());
		}
		catch (IOException e) {
			Msg.showError(JythonRun.class, null, "Jython cache directory", e.getMessage());
			System.exit(1);
		}
		catch (CancelledException e) {
			Msg.showError(JythonRun.class, null, "Operation cancelled", e.getMessage());
			System.exit(1);
		}
		
		// Pass control to Jython
		jython.main(args);
	}
}
