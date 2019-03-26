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
package ghidra.app.plugin.core.eclipse;

import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.services.EclipseIntegrationService;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Task} to launch Eclipse.
 */
class EclipseConnectorTask extends Task {

	private EclipseIntegrationService eclipseService;
	private String address;
	private int port;
	private EclipseConnection connection;

	/**
	 * Constructs a new Eclipse connector task.
	 * 
	 * @param eclipseService The Eclipse integration service.
	 * @param port The port to connect to Eclipse on.
	 */
	public EclipseConnectorTask(EclipseIntegrationService eclipseService, int port) {
		super("Eclipse Launcher Task", true, true, true);
		this.eclipseService = eclipseService;
		this.address = "127.0.0.1";
		this.port = port;
		this.connection = new EclipseConnection();
	}

	@Override
	public void run(TaskMonitor monitor) {

		// Try to establish a socket connection to an already-running Eclipse.
		// If we can connect, we are done.
		try {
			connection = new EclipseConnection(null, new Socket(address, port));
			return;
		}
		catch (IOException e) {
			// Eclipse may not be started, so we'll try to launch it
		}

		// Get required Eclipse components.  If Eclipse hasn't been setup yet in Ghidra, present
		// the user with the options window, and when they close that window, try again to get
		// the required Eclipse components.
		File eclipseExecutableFile;
		try {
			eclipseExecutableFile = eclipseService.getEclipseExecutableFile();
		}
		catch (FileNotFoundException e1) {
			eclipseService.handleEclipseError(e1.getMessage(), true, null);
			try {
				eclipseExecutableFile = eclipseService.getEclipseExecutableFile();
			}
			catch (FileNotFoundException e2) {
				eclipseService.handleEclipseError(
					"Failed to launch Eclipse.  The required Eclipse components have not been configured.",
					false, null);
				return;
			}
		}

		// Make sure GhidraDev is installed in Eclipse.  If it's not, offer to install it for the 
		// user.  After offering, check again to see if it's installed.
		if (!isGhidraDevInstalled(eclipseService)) {
			eclipseService.offerGhidraDevInstallation(monitor);
			if (!isGhidraDevInstalled(eclipseService)) {
				eclipseService.handleEclipseError(
					"Failed to launch Eclipse.  The GhidraDev plugin has not been installed.",
					false, null);
				return;
			}
		}

		// Launch Eclipse
		monitor.setIndeterminate(true);
		monitor.setMessage("Launching Eclipse...");
		Process process = null;
		try {
			ProcessBuilder processBuilder = createEclipseProcessBuilder(eclipseExecutableFile,
				eclipseService.getEclipseWorkspaceDir());
			processBuilder.redirectErrorStream(true);
			processBuilder.directory(eclipseExecutableFile.getParentFile());
			process = processBuilder.start();
		}
		catch (Exception e) {
			eclipseService.handleEclipseError(
				"Unexpected exception occurred while launching Eclipse.", false, null);
			return;
		}

		// Try to establish a socket connection to the Eclipse we just started
		int maxWaits = 200;
		monitor.setIndeterminate(false);
		monitor.initialize(maxWaits);
		monitor.setMessage("Connecting to Eclipse on port " + port + "...");
		for (int i = 0; i < maxWaits; i++) {
			if (monitor.isCancelled()) {
				return;
			}
			if (!process.isAlive()) {
				break;
			}

			try {
				connection = new EclipseConnection(process, new Socket(address, port));
				return;
			}
			catch (UnknownHostException e) {
				return;
			}
			catch (IOException e) {
				// We expect this while Eclipse is not yet initialized
			}

			try {
				Thread.sleep(500);
			}
			catch (InterruptedException ie) {
				// ignore and try again
			}
			monitor.incrementProgress(1);
		}
		eclipseService.handleEclipseError("Failed to connect to Eclipse on port " + port + ".", true,
			null);
	}

	/**
	 * Gets the Eclipse connection.
	 * 
	 * @return The Eclipse connection.
	 */
	public EclipseConnection getConnection() {
		return connection;
	}

	/**
	 * Creates a {@link ProcessBuilder} to launch Eclipse.
	 * 
	 * @param eclipseExecutableFile The Eclipse executable file.
	 * @param eclipseWorkspaceDir The Eclipse workspace directory.  Could be null.
	 * @return A {@link ProcessBuilder} to launch Eclipse.
	 */
	private ProcessBuilder createEclipseProcessBuilder(File eclipseExecutableFile,
			File eclipseWorkspaceDir) {
		List<String> args = new ArrayList<>();
		args.add(eclipseExecutableFile.getAbsolutePath());

		if (eclipseWorkspaceDir != null) {
			args.add("-data");
			args.add(eclipseWorkspaceDir.getAbsolutePath());
		}

		args.add("--launcher.appendVmargs");
		args.add("-vmargs");
		args.add("-Dghidra.install.dir=" + Application.getInstallationDirectory());

		// Eclipse on OS X can have file locking issues if the user home directory is networked.
		// The following property is set in the launch script if we should disable file locking
		// via the appropriate Eclipse JVM arg.
		if (Boolean.getBoolean("eclipse.filelock.disable")) {
			Msg.info(this, "Disabling Eclipse file locking...");
			args.add("-Dosgi.locking=none");
		}

		return new ProcessBuilder(args);
	}

	/**
	 * Checks to see if the GhidraDev plugin is installed in Eclipse.
	 * 
	 * @param service An {@link EclipseIntegrationService}.
	 * @return True if the GhidraDev plugin is installed in Eclipse; otherwise, false.
	 */
	private boolean isGhidraDevInstalled(EclipseIntegrationService service) {
		try {
			return eclipseService.isEclipseFeatureInstalled(
				(dir, filename) -> filename.contains("ghidradev"));
		}
		catch (FileNotFoundException e) {
			return false;
		}
	}
}
