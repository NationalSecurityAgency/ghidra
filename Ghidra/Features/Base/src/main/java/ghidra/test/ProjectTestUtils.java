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
package ghidra.test;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.*;

import generic.test.AbstractGenericTest;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.store.LockException;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.project.test.TestProjectManager;
import ghidra.util.*;
import ghidra.util.exception.*;

/**
 * Ghidra framework and program test utilities
 */
public class ProjectTestUtils {

	/** Names that can be ignored when deleting files during cleanup */
	private static Set<String> ignoredDeleteNames = new HashSet<>(Arrays.asList("application.log"));

	/**
	 * Open the project for the given directory and name.
	* If the project does not exist, create one. 
	* Only once instance of a given project may be open at any given
	* point in time.  Be sure to close the project if you will be
	* re-opening.
	 * @param directory directory for the project
	 * @param name name of the project
	 * @return the project
	 * @throws IOException if there was a problem creating the project
	 * @throws LockException if the project is already open
	 * @throws IllegalArgumentException if the name has illegal characters such that a URL could
	 * not be created
	 */
	public static Project getProject(String directory, String name)
			throws IOException, LockException {

		ProjectManager pm = TestProjectManager.get();
		ProjectLocator url = new ProjectLocator(directory, name);

		File dir = new File(directory);
		if (!dir.isDirectory()) {
			throw new AssertException("Test directory does not exist: " + dir);
		}

		File projDir = url.getProjectDir();
		if (projDir.exists()) {
			try {
				return pm.openProject(url, true, false);
			}
			catch (NotFoundException e) {
				throw new RuntimeException("Bad project directory: " + projDir);
			}
			catch (NotOwnerException e) {
				// I suppose this can't happen since we are not using a shared project
			}
		}

		try {
			return pm.createProject(url, null, true);
		}
		catch (MalformedURLException e) {
			throw new IllegalArgumentException("Bad project name: " + name);
		}
	}

	/**
	 * Remove entire project.  Note: this will not remove the parent <code>directory</code> of
	 * the project.
	 * 
	 * @param directory directory of the project.
	 * @param name The name of the project to delete
	 * @return True if the project was deleted.
	 */
	public static boolean deleteProject(String directory, String name) {
		ProjectLocator locator = new ProjectLocator(directory, name);
		File lockFile = locator.getProjectLockFile();

		if (!deleteLockFile(lockFile)) {
			throw new AssertException(
				"Project is in use and can't be deleted: " + locator.getProjectDir());
		}

		File projectDir = locator.getProjectDir();
		boolean success = deleteDir(locator.getProjectDir());
		if (!success) {
			// make sure the dir exists before failing
			if (projectDir.exists()) {
				return false;
			}
		}

		locator.getMarkerFile().delete();
		return true;
	}

	// this method is a test to see if we can prevent project from locking and
	// failing tests
	private static boolean deleteLockFile(File lockFile) {

		if (!lockFile.exists()) {
			return true;
		}

		boolean deleted = lockFile.delete();

		// give the system some time to release resources if the file was not
		// deleted
		if (!deleted) {
			Msg.warn(ProjectTestUtils.class, "deleteLockFile(): " + "unable to delete file " +
				lockFile.getAbsolutePath() + "- trying again.");
			for (int i = 0; i < 6; i++) {
				AbstractGenericTest.waitForPostedSwingRunnables();
				try {
					Thread.sleep(1000);
				}
				catch (Exception e) {
					// don't care, we tried
				}
			}
			deleted = lockFile.delete();
		}

		File secondLockFile = new File(lockFile.getAbsolutePath() + "~");
		if (secondLockFile.exists()) {
			deleted = secondLockFile.delete();
		}

		return deleted;
	}

	private static boolean deleteDir(File dir) {
		File[] files = dir.listFiles();
		if (files == null) {
			return dir.delete();
		}

		for (File file : files) {
			if (file.isDirectory()) {
				// use a dummy monitor as not to ruin our progress
				if (!deleteDir(file)) {
					Msg.debug(ProjectTestUtils.class, "Unable to delete directory: " + file);
					return false;
				}
			}
			else {
				if (!file.delete()) {
					if (!ignoredDeleteNames.contains(file.getName())) {
						Msg.debug(ProjectTestUtils.class, "Unable to delete file: " + file);
						return false;
					}

				}
			}
		}

		return dir.delete();
	}

	/**
	 * Create an empty program file within the specified project folder.
	 * @param proj active project.
	 * @param progName name of program and domain file to be created.
	 * @param language a specified language, or 0 if it does not matter.
	 * @param compilerSpec the compiler spec
	 * @param folder domain folder within the specified project which the
	 * user has permission to write.  If null, the root data folder will be used.
	 * @return new domain file.
	 * @throws InvalidNameException if the filename is invalid
	 * @throws CancelledException if the opening is cancelled 
	 * @throws LanguageNotFoundException if the language cannot be found
	 * @throws IOException if there is an exception creating the program or domain file
	 */
	public static DomainFile createProgramFile(Project proj, String progName, Language language,
			CompilerSpec compilerSpec, DomainFolder folder) throws InvalidNameException,
			CancelledException, LanguageNotFoundException, IOException {

		if (folder == null) {
			folder = proj.getProjectData().getRootFolder();
		}

		Object consumer = new Object();
		Program p = new ProgramDB(progName, language, compilerSpec, consumer);
		try {
			return folder.createFile(progName, p, null);
		}
		finally {
			p.release(consumer);
		}
	}

	/**
	 * Launch a tool.
	 * @param project the project to which the tool belongs
	 * @param toolName name of the tool to get from the active workspace.
	 * If null, launch a new empty tool in the active workspace.
	 * @return the tool
	 */
	public static PluginTool getTool(Project project, String toolName) {

		ToolManager tm = project.getToolManager();

		// first get the active workspace that will contain the tool
		Workspace[] workspaces = tm.getWorkspaces();

		// the front end will know which one is the active one; just
		// use the first one for the testing
		Workspace activeWorkspace = workspaces[0];

		PluginTool tool = null;
		if (toolName == null) {
			// create a new empty tool
			tool = activeWorkspace.createTool();
		}
		else {
			// if the toolName is specified, get the tool from the project
			// toolchest, and run the tool in the workspace
			ToolChest toolChest = project.getLocalToolChest();
			ToolTemplate toolTemplate = toolChest.getToolTemplate(toolName);
			tool = activeWorkspace.runTool(toolTemplate);
		}

		return tool;
	}

	/**
	 * Save a tool to the project tool chest.
	 * @param project The project which with the tool is associated.
	 * @param tool The tool to be saved
	 * @return The tool template for the given tool.
	 */
	public static ToolTemplate saveTool(Project project, PluginTool tool) {
		// save the tool to the project tool chest
		ToolChest toolChest = project.getLocalToolChest();
		ToolTemplate toolTemplate = tool.saveToolToToolTemplate();
		toolChest.addToolTemplate(toolTemplate);
		return toolTemplate;
	}

	/**
	 * Remove the specified tool if it exists.
	 * @param project the project
	 * @param toolName the tool name
	 * @return true if it existed and was removed from the local tool chest.
	 */
	public static boolean deleteTool(Project project, String toolName) {
		ToolChest toolChest = project.getLocalToolChest();
		return toolChest.remove(toolName);
	}

}
