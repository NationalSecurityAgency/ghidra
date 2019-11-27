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
import java.nio.file.Files;
import java.text.ParseException;
import java.util.*;
import java.util.regex.Pattern;

import org.eclipse.core.resources.*;
import org.eclipse.core.runtime.*;
import org.eclipse.jdt.core.*;
import org.eclipse.jdt.core.refactoring.IJavaRefactorings;
import org.eclipse.jdt.core.refactoring.descriptors.RenameJavaElementDescriptor;
import org.eclipse.ltk.core.refactoring.*;

import ghidra.GhidraApplicationLayout;
import ghidra.util.exception.CancelledException;
import utilities.util.FileUtilities;

/**
 * Utility methods for working with Ghidra modules in Eclipse.
 */
public class GhidraModuleUtils {

	public enum ModuleTemplateType {
		ANALYZER("Analyzer", "Extends Ghidra analysis"),
		PLUGIN("Plugin", "Extends the Ghidra user interface"),
		LOADER("Loader", "Loads/imports a binary file format into Ghidra"),
		FILESYSTEM("FileSystem", "Opens a file system format for browsing or batch import"),
		EXPORTER("Exporter", "Exports/saves a Ghidra program to a specific file format"),
		PROCESSOR("Processor", "Enables disassembly/decompilation of a processor/architecture");

		private String name;
		private String description;

		private ModuleTemplateType(String name, String description) {
			this.name = name;
			this.description = description;
		}

		public String getName() {
			return name;
		}

		public String getDescription() {
			return description;
		}
	}

	/**
	 * Creates a new Ghidra module project with the given name.
	 * 
	 * @param projectName The name of the project to create.
	 * @param projectDir The directory the project will be created in.
	 * @param createRunConfig Whether or not to create a new run configuration for the project.
	 * @param runConfigMemory The run configuration's desired memory.  Could be null.
	 * @param ghidraLayout The Ghidra layout to link the project to.
	 * @param jythonInterpreterName The name of the Jython interpreter to use for Python support.
	 *   Could be null if Python support is not wanted.
	 * @param monitor The progress monitor to use during project creation.
	 * @return The created project.
	 * @throws IOException If there was a file-related problem with creating the project.
	 * @throws ParseException If there was a parse-related problem with creating the project.
	 * @throws CoreException If there was an Eclipse-related problem with creating the project.
	 */
	public static IJavaProject createGhidraModuleProject(String projectName, File projectDir,
			boolean createRunConfig, String runConfigMemory, GhidraApplicationLayout ghidraLayout,
			String jythonInterpreterName, IProgressMonitor monitor)
			throws IOException, ParseException, CoreException {

		// Create empty Ghidra project
		IJavaProject javaProject =
			GhidraProjectUtils.createEmptyGhidraProject(projectName, projectDir, createRunConfig,
				runConfigMemory, ghidraLayout, jythonInterpreterName, monitor);
		IProject project = javaProject.getProject();

		// Create source directories
		List<IFolder> sourceFolders = new ArrayList<>();
		sourceFolders.add(project.getFolder("src/main/java"));
		sourceFolders.add(project.getFolder("src/main/help"));
		sourceFolders.add(project.getFolder("src/main/resources"));
		sourceFolders.add(project.getFolder("ghidra_scripts"));
		for (IFolder sourceFolder : sourceFolders) {
			GhidraProjectUtils.createFolder(sourceFolder, monitor);
		}

		// Put the source directories in the project's classpath
		List<IClasspathEntry> classpathEntries = new LinkedList<>();
		for (IFolder sourceFolder : sourceFolders) {
			classpathEntries.add(JavaCore.newSourceEntry(sourceFolder.getFullPath()));
		}
		GhidraProjectUtils.addToClasspath(javaProject, classpathEntries, monitor);

		return javaProject;
	}

	/**
	 * Manually add in the source from the Skeleton (which should exist in the Ghidra installation 
	 * directory), and then look at what's in the templates set to know what to keep and what to 
	 * discard.
	 * 
	 * @param javaProject The project whose source is to be configured.
	 * @param projectDir The project's directory.
	 * @param ghidraLayout The Ghidra layout the project is linked to.
	 * @param moduleTemplateTypes The templates to include in the source.
	 * @param monitor The progress monitor to use during source configuration.
	 * @return The primary module source file (which could be opened in an editor by default). 
	 * @throws IOException If there was a file-related problem with configuring the source.
	 * @throws CoreException If there was an Eclipse-related problem with configuring the source.
	 */
	public static IFile configureModuleSource(IJavaProject javaProject, File projectDir,
			GhidraApplicationLayout ghidraLayout, Set<ModuleTemplateType> moduleTemplateTypes,
			IProgressMonitor monitor) throws CoreException, IOException {

		final String SKELETON_PKG = "skeleton";
		final String SKELETON_CLASS = "Skeleton";

		IProject project = javaProject.getProject();

		// Create a list of files to exclude.  Use the provided templates list to know what
		// source files should be included in the project.
		List<String> excludeRegexes = new ArrayList<>();
		for (ModuleTemplateType moduleTemplateType : ModuleTemplateType.values()) {
			if (!moduleTemplateTypes.contains(moduleTemplateType)) {
				if (moduleTemplateType.equals(ModuleTemplateType.PROCESSOR)) {
					excludeRegexes.add("languages");
					excludeRegexes.add("buildLanguage\\.xml");
					excludeRegexes.add("sleighArgs\\.txt");
				}
				else {
					excludeRegexes.add(SKELETON_CLASS + moduleTemplateType.getName() + "\\.java");
				}
			}
		}

		// Copy the skeleton files
		File ghidraInstallDir = ghidraLayout.getApplicationInstallationDir().getFile(false);
		File skeletonDir = Files.find(ghidraInstallDir.toPath(), 4, (path, attrs) -> {
			return attrs.isDirectory() && path.getFileName().toString().equals("Skeleton");
		}).map(p -> p.toFile()).findFirst().orElse(null);
		if (skeletonDir == null) {
			throw new IOException("Failed to find skeleton directory.");
		}
		try {
			FileUtilities.copyDir(skeletonDir, projectDir, f -> {
				return excludeRegexes.stream().map(r -> Pattern.compile(r)).noneMatch(
					p -> p.matcher(f.getName()).matches());
			}, null);
		}
		catch (CancelledException | IOException e) {
			throw new IOException("Failed to copy skeleton directory: " + projectDir);
		}

		// Refresh project so it sees the new files
		project.refreshLocal(IResource.DEPTH_INFINITE, monitor);

		// Update language ant properties file
		GhidraModuleUtils.writeAntProperties(project, ghidraLayout);

		// Refactor/rename the source files, package, and help files
		String packageName = project.getName().toLowerCase();
		for (ModuleTemplateType moduleTemplateType : moduleTemplateTypes) {
			IType skeletonClass = javaProject.findType(
				SKELETON_PKG + "." + SKELETON_CLASS + moduleTemplateType.getName(), monitor);
			if (skeletonClass != null) {
				renameJavaElement(skeletonClass.getCompilationUnit(),
					project.getName() + moduleTemplateType.getName(), monitor);
			}
		}
		IJavaElement skeletonPackage = javaProject.findElement(new Path(SKELETON_PKG));
		if (skeletonPackage != null) {
			renameJavaElement(skeletonPackage, packageName, monitor);
		}
		IJavaElement helpTopic = javaProject.findElement(new Path("help/topics/skeleton"));
		if (helpTopic != null) {
			renameJavaElement(helpTopic, "help.topics." + packageName, monitor);
		}

		// Return the primary source file in the project (the first java file we see in the package)
		IFolder packageFolder = project.getFolder("/src/main/java").getFolder(packageName);
		if (packageFolder.exists()) {
			for (IResource resource : packageFolder.members()) {
				if (resource instanceof IFile && resource.getName().endsWith(".java")) {
					return (IFile) resource;
				}
			}
		}
		return null;
	}

	/**
	 * Writes project-specific ant properties, which get imported by the module project's language
	 * build.xml file to allow building against a Ghidra that lives in an external location. If the 
	 * given project is not a Ghidra module project, or if the Ghidra module project does not have a 
	 * language buildLanguage.xml ant file, this method has no effect.
	 * 
	 * @param project The project to receive the ant properties.
	 * @param ghidraLayout The layout that contains the Ghidra installation directory that the project
	 *   is currently linked against.
	 * @throws IOException if there was a problem writing the ant properties file.
	 */
	public static void writeAntProperties(IProject project, GhidraApplicationLayout ghidraLayout)
			throws IOException {
		if (!GhidraProjectUtils.isGhidraModuleProject(project)) {
			return;
		}

		IFolder dataFolder = project.getFolder("data");
		if (!dataFolder.exists()) {
			return;
		}
		IFile buildXmlFile = dataFolder.getFile("buildLanguage.xml");
		if (!buildXmlFile.exists()) {
			return;
		}

		File ghidraInstallDir = ghidraLayout.getApplicationInstallationDir().getFile(false);
		File antFile = new File(project.getLocation().toFile(), ".antProperties.xml"); // hidden

		try (PrintWriter writer = new PrintWriter(new FileWriter(antFile))) {
			writer.println(
				"<!-- This file is generated on each \"Link Ghidra\" command.  Do not modify. -->");
			writer.println();
			writer.println("<project>");
			writer.println("  <property name=\"ghidra.install.dir\" value=\"" +
				ghidraInstallDir.getAbsolutePath() + "\" />");
			writer.println("</project>");
		}
	}

	/**
	 * Renames the given Java element to the given new name.  Currently only supports renaming 
	 * packages and compilation units.
	 * 
	 * @param element The Java element to rename.
	 * @param newName The desired new name of the element.
	 * @param monitor The progress monitor.
	 * @throws CoreException If there is an Eclipse-related problem with the rename.
	 * @throws IllegalArgumentException If the given Java element is not a package or compilation unit.
	 */
	private static void renameJavaElement(IJavaElement element, String newName,
			IProgressMonitor monitor) throws CoreException, IllegalArgumentException {
		String id;
		if (element.getElementType() == IJavaElement.PACKAGE_FRAGMENT) {
			id = IJavaRefactorings.RENAME_PACKAGE;
		}
		else if (element.getElementType() == IJavaElement.COMPILATION_UNIT) {
			id = IJavaRefactorings.RENAME_COMPILATION_UNIT;
		}
		else {
			throw new IllegalArgumentException("Can only rename packages and compilation units!");
		}
		RefactoringContribution contribution = RefactoringCore.getRefactoringContribution(id);
		RenameJavaElementDescriptor descriptor =
			(RenameJavaElementDescriptor) contribution.createDescriptor();
		descriptor.setProject(element.getResource().getProject().getName());
		descriptor.setNewName(newName);
		descriptor.setJavaElement(element);
		RefactoringStatus status = new RefactoringStatus();
		Refactoring refactoring = descriptor.createRefactoring(status);
		refactoring.checkInitialConditions(monitor);
		refactoring.checkFinalConditions(monitor);
		Change change = refactoring.createChange(monitor);
		change.perform(monitor);
	}
}
