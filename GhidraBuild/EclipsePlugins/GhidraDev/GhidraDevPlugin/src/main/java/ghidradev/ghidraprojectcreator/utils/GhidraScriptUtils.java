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
package ghidradev.ghidraprojectcreator.utils;

import java.io.*;
import java.text.ParseException;
import java.util.*;

import org.eclipse.core.resources.*;
import org.eclipse.core.runtime.*;
import org.eclipse.jdt.core.*;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.GModule;
import ghidradev.Activator;

/**
 * Utility methods for working with Ghidra scripts in Eclipse.
 */
public class GhidraScriptUtils {

	public static File userScriptsDir =
		new File(System.getProperty("user.home") + "/ghidra_scripts");

	/**
	 * Creates a new Ghidra script project with the given name.
	 * 
	 * @param projectName The name of the project to create.
	 * @param projectDir The directory the project will be created in.
	 * @param createRunConfig Whether or not to create a new run configuration for the project.
	 * @param runConfigMemory The run configuration's desired memory.  Could be null.
	 * @param linkUserScripts Whether or not to link in the user scripts directory.
	 * @param linkSystemScripts Whether or not to link in the system scripts directories.
	 * @param ghidraLayout The Ghidra layout to link the project to.
	 * @param jythonInterpreterName The name of the Jython interpreter to use for Python support.
	 *   Could be null if Python support is not wanted.
	 * @param monitor The progress monitor to use during project creation.
	 * @return The created project.
	 * @throws IOException If there was a file-related problem with creating the project.
	 * @throws ParseException If there was a parse-related problem with creating the project.
	 * @throws CoreException If there was an Eclipse-related problem with creating the project.
	 */
	public static IJavaProject createGhidraScriptProject(String projectName, File projectDir,
			boolean createRunConfig, String runConfigMemory, boolean linkUserScripts,
			boolean linkSystemScripts, GhidraApplicationLayout ghidraLayout,
			String jythonInterpreterName, IProgressMonitor monitor)
			throws IOException, ParseException, CoreException {

		List<IClasspathEntry> classpathEntries = new ArrayList<>();

		// Create empty Ghidra project
		IJavaProject javaProject = GhidraProjectUtils.createEmptyGhidraProject(projectName,
			projectDir, createRunConfig, runConfigMemory, ghidraLayout, jythonInterpreterName,
			monitor);

		// Link each module's ghidra_scripts directory to the project
		if (linkSystemScripts) {
			for (GModule module : ghidraLayout.getModules().values()) {
				File moduleDir = module.getModuleRoot().getFile(false);
				File moduleScriptsDir = new File(moduleDir, "ghidra_scripts");
				if (!moduleScriptsDir.exists()) {
					continue;
				}

				IPath moduleScriptsDirPath = new Path(moduleScriptsDir.getAbsolutePath());
				String moduleName = moduleDir.getName();
				String scriptsDirName = "Ghidra " + moduleName + " scripts";

				IFolder link = javaProject.getProject().getFolder(scriptsDirName);
				link.createLink(moduleScriptsDirPath, IResource.NONE, monitor);

				classpathEntries.add(JavaCore.newSourceEntry(link.getFullPath()));
			}
		}

		// Link in the user's personal ghidra_scripts directory
		if (linkUserScripts) {
			if (!userScriptsDir.isDirectory()) {
				if (!userScriptsDir.mkdirs()) {
					throw new CoreException(new Status(IStatus.ERROR, Activator.PLUGIN_ID,
						IStatus.ERROR, "Failed to create " + userScriptsDir, null));
				}
			}
			IFolder link = javaProject.getProject().getFolder("Home scripts");
			link.createLink(new Path(userScriptsDir.getAbsolutePath()), IResource.NONE, monitor);
			classpathEntries.add(JavaCore.newSourceEntry(link.getFullPath()));
		}

		// Update the project's classpath
		GhidraProjectUtils.addToClasspath(javaProject, classpathEntries, monitor);

		return javaProject;
	}

	/**
	 * Create a Ghidra script with the given name in the in the user's ghidra_scripts, and link it in 
	 * to the provided project.
	 * 
	 * @param scriptFolder The folder to create the script in.
	 * @param scriptName The name of the script to create.
	 * @param scriptAuthor The script's author.
	 * @param scriptCategory The script's category.
	 * @param scriptDescription The script's description lines.
	 * @param monitor The progress monitor to use during script creation.
	 * @return The script file (which could be opened in an editor by default). 
	 * @throws IOException If there was a file-related problem with creating the script.
	 * @throws CoreException If there was an Eclipse-related problem with creating the script.
	 */
	public static IFile createGhidraScript(IFolder scriptFolder, String scriptName,
			String scriptAuthor, String scriptCategory, String[] scriptDescription,
			IProgressMonitor monitor) throws CoreException, IOException {

		// Create the scripts folder directory, if necessary
		if (!scriptFolder.exists()) {
			GhidraProjectUtils.createFolder(scriptFolder, monitor);
		}

		IFile scriptFile = scriptFolder.getFile(scriptName);
		
		// Does the script exist already?  If so, it's a problem.
		if (scriptFile.exists()) {
			throw new IOException("File already exists: " + scriptFile);
		}

		// Create the script file, and fill in a useful entry point
		try (PrintWriter writer =
			new PrintWriter(new FileWriter(scriptFile.getLocation().toFile()))) {
			if (scriptName.endsWith(".java")) {
				Arrays.stream(scriptDescription).forEach(line -> writer.println("//" + line));
				writer.println("//@author " + scriptAuthor);
				writer.println("//@category " + scriptCategory);
				writer.println("//@keybinding");
				writer.println("//@menupath");
				writer.println("//@toolbar");
				writer.println();
				writer.println("import ghidra.app.script.GhidraScript;");
				writer.println();
				writer.println("public class " + scriptName.substring(0, scriptName.length() - 5) +
						" extends GhidraScript {");
				writer.println();
				writer.println("\t@Override");
				writer.println("\tprotected void run() throws Exception {");
				writer.println("\t\t//TODO: Add script code here");
				writer.println("\t}");
				writer.println("}");
			}
			else if (scriptName.endsWith(".py")) {
				Arrays.stream(scriptDescription).forEach(line -> writer.println("#" + line));
				writer.println("#@author " + scriptAuthor);
				writer.println("#@category " + scriptCategory);
				writer.println("#@keybinding");
				writer.println("#@menupath");
				writer.println("#@toolbar");
				writer.println();
				writer.println("#TODO: Add script code here");
			}
		}
		catch (IOException e) {
			throw new IOException("Failed to create: " + scriptFile);
		}

		// Refresh project to it sees the new script
		scriptFile.getProject().refreshLocal(IResource.DEPTH_INFINITE, monitor);

		return scriptFile;
	}
}
