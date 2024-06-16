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
package ghidra.dbg.isf;

import java.io.File;
import java.io.IOException;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.base.project.GhidraProject;
import ghidra.framework.*;
import ghidra.framework.model.ProjectLocator;
import ghidra.util.Msg;

// To be run using runISFServer 

public class IsfServerLauncher implements GhidraLaunchable {

	private GhidraProject project = null;
	private IsfServer server;
	private int port;

	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {

		ApplicationConfiguration config = new HeadlessGhidraApplicationConfiguration();
		if (!Application.isInitialized()) {
			Application.initializeApplication(layout, config);
		}

		GhidraProject proj = parseArgs(args);
		server = new IsfServer(proj, port);
		server.startServer();
	}

	GhidraProject parseArgs(String[] args) throws IOException {
		if (args != null && args.length < 1) {
			usage();
			return null;
		}
		port = Integer.parseInt(args[0]);
		if (args.length > 1) {
			String projectLocation = args[1];
			String projectName = args[2];

			File dir = new File(projectLocation);
			if (dir.exists()) {
				ProjectLocator locator = new ProjectLocator(dir.getAbsolutePath(), projectName);

				if (locator.getProjectDir().exists()) {
					project = GhidraProject.openProject(projectLocation, projectName);
				}
			}
		}
		return project;
	}

	public int getPort() {
		return port;
	}

	public void close() {
		server.stopServer();
		if (project != null) {
			project.close();
		}
	}

	public void usage() {
		Msg.error(this, "Usage: runISFServer <port> <project_location> <project_name> ");
	}

}
