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

import java.io.File;

import javax.swing.ToolTipManager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import docking.framework.SplashScreen;
import ghidra.base.help.GhidraHelpService;
import ghidra.framework.Application;
import ghidra.framework.GhidraApplicationConfiguration;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.data.DomainObjectAdapter;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.dialog.ExtensionUtils;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.framework.remote.InetNameLookup;
import ghidra.framework.store.LockException;
import ghidra.program.database.ProgramDB;
import ghidra.util.*;
import ghidra.util.exception.UsrException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Main Ghidra application class. Creates
 * the .ghidra folder that contains the user preferences and tools if it does
 * not exist. Initializes JavaHelp and attempts to restore the last opened
 * project.
 * <p> A list of classes for plugins, data types, and language providers is
 * maintained so that a search of the classpath is not done every time
 * Ghidra is run. The list is maintained in the GhidraClasses.xml file
 * in the user's .ghidra folder. A search of the classpath is done if the
 * (1) GhidraClasses.xml file is not found, (2) the classpath is different
 * from when the last time Ghidra was run, (3) a class in the file was
 * not found,  or (4) a modification date specified in the classes file for
 * a jar file is older than the actual jar file's modification date.
 * 
 * <p><strong>Note</strong>: The Plugin path is a user preference that
 * indicates locations for where classes for plugins and data types should
 * be searched; the Plugin path can include jar files just like a classpath.
 * The Plugin path can be changed by using the <i>Edit Plugin Path</i> dialog,
 * displayed from the <i>Edit-&gt;Edit Plugin Path...</i> menu option on the main
 * Ghidra project window.
 * 
 * @see ghidra.GhidraLauncher
 */
public class GhidraRun implements GhidraLaunchable {

	private Logger log; // intentionally load later, after initialization

	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) {

		Runnable mainTask = () -> {

			GhidraApplicationConfiguration configuration = new GhidraApplicationConfiguration();
			configuration.setTaskMonitor(new StatusReportingTaskMonitor());
			Application.initializeApplication(layout, configuration);

			log = LogManager.getLogger(GhidraRun.class);
			log.info("User " + SystemUtilities.getUserName() + " started Ghidra.");

			initializeTooltips();

			updateSplashScreenStatusMessage("Populating Ghidra help...");
			GhidraHelpService.install();

			ExtensionUtils.cleanupUninstalledExtensions();

			// Allows handling of old content which did not have a content type property
			DomainObjectAdapter.setDefaultContentClass(ProgramDB.class);

			updateSplashScreenStatusMessage("Checking for previous project...");
			SystemUtilities.runSwingLater(() -> {
				String projectPath = processArguments(args);
				openProject(projectPath);
			});
		};

		// Automatically disable reverse name lookup if failure occurs
		InetNameLookup.setDisableOnFailure(true);

		// Start main thread in GhidraThreadGroup
		Thread mainThread = new Thread(new GhidraThreadGroup(), mainTask, "Ghidra");
		mainThread.start();
	}

	private String processArguments(String[] args) {
		//TODO remove this special handling when possible
		if (args.length == 1 && (args[0].startsWith("-D") || args[0].indexOf(" -D") >= 0)) {
			args = args[0].split(" ");
		}
		String projectPath = null;
		for (String arg : args) {
			if (arg.startsWith("-D")) {
				String[] split = arg.substring(2).split("=");
				if (split.length == 2) {
					System.setProperty(split[0], split[1]);
				}
			}
			else {
				projectPath = arg;
			}
		}
		return projectPath;
	}

	private void updateSplashScreenStatusMessage(final String message) {
		SystemUtilities.runSwingNow(() -> SplashScreen.updateSplashScreenStatus(message));
	}

	private void initializeTooltips() {
		int currentDelay = ToolTipManager.sharedInstance().getDismissDelay();
		ToolTipManager.sharedInstance().setDismissDelay(currentDelay * 2);
	}

	/**
	 * Open the specified project or the last active project if projectPath is null.
	 * Makes the project window visible.
	 * @param projectPath optional project to be opened (specifies project file)
	 */
	private void openProject(String projectPath) {

		updateSplashScreenStatusMessage("Creating project manager...");
		ProjectManager pm = new GhidraProjectManager();
		updateSplashScreenStatusMessage("Creating front end tool...");

		// Show this warning before creating the tool.   If we create the tool first, then we may
		// see odd dialog behavior caused tool plugins creating dialogs during initialization.
		if (Application.isTestBuild()) {
			Msg.showWarn(GhidraRun.class, null, "Unsupported Ghidra Distribution",
				"WARNING! Please be aware that this is an unsupported and uncertified\n" +
					"build of Ghidra!  This software may be unstable and data created\n" +
					"may be incompatible with future releases.");
		}

		FrontEndTool tool = new FrontEndTool(pm);

		boolean reopen = true;
		ProjectLocator projectLocator = null;
		if (projectPath != null) {
			File projectFile = new File(projectPath);
			String name = projectFile.getName();
			if (!name.endsWith(ProjectLocator.getProjectExtension())) {
				Msg.showInfo(GhidraRun.class, null, "Invalid Project",
					"The specified file is not a project file: " + projectPath);
			}
			else {
				projectLocator = new ProjectLocator(projectFile.getParent(), name);
				reopen = false;
			}
		}
		if (projectLocator == null) {
			updateSplashScreenStatusMessage("Checking for last opened project...");
			projectLocator = pm.getLastOpenedProject();
		}

		tool.setVisible(true);

		if (projectLocator != null) {
			openProject(tool, projectLocator, reopen);
		}
	}

	private void openProject(FrontEndTool tool, ProjectLocator projectLocator, boolean reopen) {
		SplashScreen.updateSplashScreenStatus(
			(reopen ? "Reopening" : "Opening") + " project: " + projectLocator.getName());

		Runnable r = () -> doOpenProject(tool, projectLocator, reopen);
		TaskLauncher.launchModal("Opening Project", () -> Swing.runNow(r));
	}

	private void doOpenProject(FrontEndTool tool, ProjectLocator projectLocator, boolean reopen) {
		try {
			ProjectManager pm = tool.getProjectManager();
			Project activeProject = pm.openProject(projectLocator, true, false);
			if (activeProject == null) {
				return;
			}

			tool.setActiveProject(activeProject);

			RepositoryAdapter repository = activeProject.getRepository();
			if (repository != null && !repository.isConnected()) {
				Msg.showInfo(GhidraRun.class, null, "Working Off-Line ",
					"Even though you are not connected to the Ghidra Server,\n" +
						"you can still work off-line on checked out files or private files.\n" +
						"You can also try reconnecting to the server by selecting the connect\n" +
						"button on the Ghidra Project Window.\n \n" +
						"See the Ghidra Help topic 'Project Repository' for troubleshooting\n" +
						"a failed connection.");
			}

		}
		catch (Throwable t) {
			if (t instanceof UsrException) {
				if (t instanceof LockException) {
					Msg.showInfo(GhidraRun.class, null, "Project is Locked",
						"Can't open project: " + projectLocator.toString() +
							"\nProject is already locked");

				}
				else {
					Msg.showInfo(GhidraRun.class, null, "Project Open Failed",
						"Failed to " + (reopen ? "reopen last" : "open") + " project: " +
							projectLocator.toString() + "\n\n" + t.getClass().getSimpleName() +
							": " + t.getMessage());
				}
			}
			else {
				Msg.showError(GhidraRun.class, null, "Project Open Failed",
					"Failed to " + (reopen ? "reopen last" : "open") + " project: " +
						projectLocator.toString() + "\n\n" + t.getClass().getSimpleName() + ": " +
						t.getMessage(),
					t);

			}
			tool.setActiveProject(null);
		}
	}

	private class GhidraProjectManager extends DefaultProjectManager {
		// this exists just to allow access to the constructor
	}
}

class StatusReportingTaskMonitor extends TaskMonitorAdapter {
	@Override
	public synchronized void setCancelEnabled(boolean enable) {
		// Not permitted
	}

	@Override
	public void setMessage(String message) {
		SplashScreen.updateSplashScreenStatus(message);
	}
}
