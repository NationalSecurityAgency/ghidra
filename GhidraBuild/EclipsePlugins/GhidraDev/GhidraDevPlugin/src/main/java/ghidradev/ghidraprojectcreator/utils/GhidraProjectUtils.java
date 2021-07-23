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

import javax.naming.OperationNotSupportedException;

import org.eclipse.core.resources.*;
import org.eclipse.core.runtime.*;
import org.eclipse.debug.core.ILaunchConfiguration;
import org.eclipse.jdt.core.*;
import org.eclipse.jdt.internal.launching.StandardVMType;
import org.eclipse.jdt.junit.JUnitCore;
import org.eclipse.jdt.launching.*;
import org.eclipse.jface.viewers.ISelection;
import org.eclipse.jface.viewers.IStructuredSelection;
import org.eclipse.ui.part.FileEditorInput;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.GModule;
import ghidra.launch.JavaConfig;
import ghidradev.Activator;
import ghidradev.EclipseMessageUtils;
import utility.module.ModuleUtilities;

/**
 * Utility methods for working with Eclipse Ghidra projects.
 */
public class GhidraProjectUtils {

	/**
	 * The name of the linked project folder that points to the installation of 
	 * Ghidra that it is using.
	 */
	public static final String GHIDRA_FOLDER_NAME = "Ghidra";

	/**
	 * Characters that we are not going to allow in our Ghidra project and file.
	 */
	public static final String ILLEGAL_FILENAME_CHARS = " `~!@#$%^&*()-+=[]{}\\|;:'\"<>,./?";

	/**
	 * Characters that we are not going to allow to start our Ghidra project and file names.
	 */
	public static final String ILLEGAL_FILENAME_START_CHARS = "0123456789";

	/**
	 * Gets all of the open Java projects in the workspace.
	 * 
	 * @return A collection of the open Java projects in the workspace.
	 */
	public static Collection<IJavaProject> getJavaProjects() {
		List<IJavaProject> javaProjects = new ArrayList<>();
		for (IProject project : ResourcesPlugin.getWorkspace().getRoot().getProjects()) {
			if (project.isOpen() && isJavaProject(project)) {
				javaProjects.add(JavaCore.create(project));
			}
		}
		return javaProjects;
	}

	/**
	 * Checks to see if the given project is a Java project.
	 * 
	 * @param project The project to check.
	 * @return True if the given project is a Java project; otherwise, false.
	 */
	public static boolean isJavaProject(IProject project) {
		try {
			return project != null && project.hasNature(JavaCore.NATURE_ID);
		}
		catch (CoreException e) {
			EclipseMessageUtils.error("Java project check failed", e);
			return false;
		}
	}

	/**
	 * Checks to see if the given project is a Ghidra project.
	 * 
	 * @param project The project to check.
	 * @return True if the given project is a Ghidra project; otherwise, false.
	 */
	public static boolean isGhidraProject(IProject project) {
		return isJavaProject(project) && project.getFolder(GHIDRA_FOLDER_NAME).exists();
	}

	/**
	 * Checks to see if the given Java project is a Ghidra module project.
	 * 
	 * @param project The project to check.
	 * @return True if the given project is a Ghidra module project; otherwise, false.
	 */
	public static boolean isGhidraModuleProject(IProject project) {
		return isGhidraProject(project) &&
			project.getFile(ModuleUtilities.MANIFEST_FILE_NAME).exists();
	}

	/**
	 * Gets all of the open Ghidra projects in the workspace.
	 * 
	 * @return A collection of the open Ghidra projects in the workspace.
	 */
	public static Collection<IJavaProject> getGhidraProjects() {
		List<IJavaProject> ghidraProjects = new ArrayList<>();
		for (IJavaProject javaProject : getJavaProjects()) {
			if (isGhidraProject(javaProject.getProject())) {
				ghidraProjects.add(javaProject);
			}
		}
		return ghidraProjects;
	}

	/**
	 * Gets the open Ghidra project with the given name.
	 * 
	 * @param name The name of the project to get.
	 * @return The open Ghidra project with the given name, or null if it doesn't exist.
	 */
	public static IJavaProject getGhidraProject(String name) {
		for (IJavaProject javaProject : getGhidraProjects()) {
			if (javaProject.getProject().getName().equals(name)) {
				return javaProject;
			}
		}
		return null;
	}

	/**
	 * Gets the selected project, or null if a project is not selected.  If multiple things
	 * are selected, only the first selected item is considered.
	 * 
	 * @param selection A selection from which to get a project.
	 * @return The selected project, or null if a project is not selected.
	 */
	public static IProject getSelectedProject(ISelection selection) {
		IProject project = null;

		if (selection instanceof IStructuredSelection) {
			IStructuredSelection structuredSelection = (IStructuredSelection) selection;
			Object firstElement = structuredSelection.getFirstElement();
			if (firstElement instanceof IResource) {
				project = ((IResource) (firstElement)).getProject();
			}
			else if (firstElement instanceof IJavaElement) {
				project = ((IJavaElement) (firstElement)).getResource().getProject();
			}
		}
		return project;
	}

	/**
	 * Tries to get the given project object's enclosing project.
	 * 
	 * @param projectObj The project object to get the enclosing project of.
	 * @return The given project object's enclosing project.  Could be null if it could not be
	 *   determined.
	 */
	public static IProject getEnclosingProject(Object projectObj) {
		IProject project = null;

		if (projectObj instanceof List) {
			List<?> list = (List<?>) projectObj;
			if (list.size() == 1) {
				projectObj = list.iterator().next();
			}
		}

		if (projectObj instanceof FileEditorInput) {
			FileEditorInput fileEditorInput = (FileEditorInput) projectObj;
			project = fileEditorInput.getFile().getProject();
		}
		else if (projectObj instanceof IResource) {
			IResource resource = (IResource) projectObj;
			project = resource.getProject();
		}
		else if (projectObj instanceof IJavaElement) {
			IJavaElement javaElement = (IJavaElement) projectObj;
			IResource resource = javaElement.getResource();
			if (resource != null) {
				project = resource.getProject();
			}
		}

		return project;
	}

	/**
	 * Creates the given folder, including any necessary but nonexistent parent directories.
	 * 
	 * @param folder The folder to create.
	 * @param monitor The progress monitor to use during folder creation.
	 * @throws CoreException If there was an Eclipse-related problem with creating the folder.
	 */
	public static void createFolder(IFolder folder, IProgressMonitor monitor) throws CoreException {
		IContainer parent = folder.getParent();
		if (parent instanceof IFolder) {
			createFolder((IFolder) parent, monitor);
		}
		if (!folder.exists()) {
			folder.create(false, true, monitor);
		}
	}

	/**
	 * Updates the Java project's classpath to include the given list of classpath entries.
	 * 
	 * @param javaProject The Java project that will get the new classpath entries.
	 * @param classpathEntries A list of classpath entries to add to the Java project's classpath.
	 * @param monitor The progress monitor.
	 * @throws JavaModelException If there was an issue adding to the Java project's classpath.
	 */
	public static void addToClasspath(IJavaProject javaProject,
			List<IClasspathEntry> classpathEntries, IProgressMonitor monitor)
			throws JavaModelException {
		for (IClasspathEntry entry : javaProject.getRawClasspath()) {
			classpathEntries.add(entry);
		}
		javaProject.setRawClasspath(
			classpathEntries.toArray(new IClasspathEntry[classpathEntries.size()]), monitor);
	}

	/**
	 * Updates the Java project's classpath to include the given classpath entry.
	 * 
	 * @param javaProject The Java project that will get the new classpath entries.
	 * @param classpathEntry The classpath entry to add to the Java project's classpath.
	 * @param monitor The progress monitor.
	 * @throws JavaModelException If there was an issue adding to the Java project's classpath.
	 */
	public static void addToClasspath(IJavaProject javaProject, IClasspathEntry classpathEntry,
			IProgressMonitor monitor) throws JavaModelException {
		List<IClasspathEntry> entryList = new ArrayList<>();
		entryList.add(classpathEntry);
		addToClasspath(javaProject, entryList, monitor);
	}

	/**
	 * Creates a new empty Ghidra project with the given name.
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
	public static IJavaProject createEmptyGhidraProject(String projectName, File projectDir,
			boolean createRunConfig, String runConfigMemory, GhidraApplicationLayout ghidraLayout,
			String jythonInterpreterName, IProgressMonitor monitor)
			throws IOException, ParseException, CoreException {

		// Get Ghidra's Java configuration
		JavaConfig javaConfig =
			new JavaConfig(ghidraLayout.getApplicationInstallationDir().getFile(false));

		// Make new Java project
		IWorkspace workspace = ResourcesPlugin.getWorkspace();
		IProject project = workspace.getRoot().getProject(projectName);
		IProjectDescription projectDescription = workspace.newProjectDescription(projectName);
		projectDescription.setLocation(new Path(projectDir.getAbsolutePath()));
		projectDescription.setNatureIds(new String[] { JavaCore.NATURE_ID });
		ICommand command = projectDescription.newCommand();
		command.setBuilderName(JavaCore.BUILDER_ID);
		projectDescription.setBuildSpec(new ICommand[] { command });
		project.create(projectDescription, monitor);
		IJavaProject javaProject = JavaCore.create(project);
		project.open(monitor);

		// Clear the project's classpath
		javaProject.setRawClasspath(new IClasspathEntry[0], monitor);

		// Configure Java compiler for the project
		configureJavaCompiler(javaProject, javaConfig);

		// Setup bin folder
		IFolder binFolder = project.getFolder("bin");
		javaProject.setOutputLocation(binFolder.getFullPath(), monitor);

		// Add Eclipse's built-in JUnit to classpath
		addToClasspath(javaProject, JavaCore.newContainerEntry(JUnitCore.JUNIT4_CONTAINER_PATH),
			monitor);

		// Link in Ghidra to the project
		linkGhidraToProject(javaProject, ghidraLayout, javaConfig, jythonInterpreterName, monitor);

		// Create run configuration (if necessary)
		if (createRunConfig) {
			try {
				ILaunchConfiguration launchConfig =
					GhidraLaunchUtils.createLaunchConfig(javaProject, GhidraLaunchUtils.GUI_LAUNCH,
						project.getName(), runConfigMemory).doSave();
				GhidraLaunchUtils.addToFavorites(launchConfig);
			}
			catch (CoreException e) {
				EclipseMessageUtils.showErrorDialog(
					"Failed to create a Ghidra run configuration for the new project.  Please do it manually.");
			}
		}

		return javaProject;
	}

	/**
	 * Links the Ghidra layout to the given Java project.  This effectively makes the project's 
	 * build path "Ghidra aware." 
	 * <p>
	 * If the project already has a Ghidra installation directory linked to it, that link is deleted
	 * and the new Ghidra installation directory is freshly linked back in.
	 * 
	 * @param javaProject The Java project to link.
	 * @param ghidraLayout The Ghidra layout to link the project to.
	 * @param javaConfig Ghidra's Java configuration.
	 * @param jythonInterpreterName The name of the Jython interpreter to use for Python support.
	 *   Could be null if Python support is not wanted.
	 * @param monitor The progress monitor used during link.
	 * @throws IOException If there was a file-related problem with linking in Ghidra.
	 * @throws CoreException If there was an Eclipse-related problem with linking in Ghidra.
	 */
	public static void linkGhidraToProject(IJavaProject javaProject,
			GhidraApplicationLayout ghidraLayout, JavaConfig javaConfig,
			String jythonInterpreterName, IProgressMonitor monitor)
			throws CoreException, IOException {

		// Gets the Ghidra installation directory to link to from the Ghidra layout
		File ghidraInstallDir = ghidraLayout.getApplicationInstallationDir().getFile(false);

		// Get the Java VM used to launch the Ghidra to link to
		IVMInstall vm = getGhidraVm(javaConfig);
		IPath vmPath =
			new Path(JavaRuntime.JRE_CONTAINER).append(vm.getVMInstallType().getId()).append(
				vm.getName());

		// Get the project's existing linked Ghidra installation folder and path (it may not exist)
		IFolder ghidraFolder =
			javaProject.getProject().getFolder(GhidraProjectUtils.GHIDRA_FOLDER_NAME);
		IPath oldGhidraInstallPath = ghidraFolder.exists()
				? new Path(ghidraFolder.getLocation().toFile().getAbsolutePath())
				: null;

		// Loop through the project's existing classpath to decide what to keep (things that aren't
		// related to Ghidra), and things to not keep (things that will be added fresh from the new
		// Ghidra).
		IClasspathEntry vmEntryCandidate = null;
		List<IClasspathEntry> classpathEntriesToKeep = new ArrayList<>();
		for (IClasspathEntry entry : javaProject.getRawClasspath()) {

			// If the project is not linked to an old Ghidra, save off the project's existing VM.  
			// We'll decide whether or not to keep it later.
			if (entry.getEntryKind() == IClasspathEntry.CPE_CONTAINER &&
				entry.getPath().toString().startsWith(JavaRuntime.JRE_CONTAINER)) {
				if (oldGhidraInstallPath == null) {
					vmEntryCandidate = entry;
				}
			}
			else if (entry.getEntryKind() == IClasspathEntry.CPE_CONTAINER &&
				entry.getPath().toString().startsWith(JUnitCore.JUNIT_CONTAINER_ID)) {
				// Keep existing JUnit
				classpathEntriesToKeep.add(entry);
			}
			else if (entry.getEntryKind() == IClasspathEntry.CPE_PROJECT) {
				// Keep all project dependencies
				classpathEntriesToKeep.add(entry);
			}
			else {
				// If the project is linked to an old Ghidra, keep the list of source folders that are
				// linked to the Ghidra installation (after updating their paths to point to the new
				// Ghidra installation).
				IFolder entryFolder = null;
				if (entry.getEntryKind() == IClasspathEntry.CPE_SOURCE) {
					entryFolder = ResourcesPlugin.getWorkspace().getRoot().getFolder(entry.getPath());
				}
				if (entryFolder != null && entryFolder.isLinked() &&
					oldGhidraInstallPath != null &&
					oldGhidraInstallPath.isPrefixOf(entryFolder.getLocation())) {
					String origPath = entryFolder.getLocation().toString();
					String newPath = ghidraInstallDir.getAbsolutePath() +
						origPath.substring(oldGhidraInstallPath.toString().length());
					entryFolder.createLink(new Path(newPath), IResource.REPLACE, monitor);
					classpathEntriesToKeep.add(JavaCore.newSourceEntry(entryFolder.getFullPath()));
				}
				// If it's anything else that doesn't live in the old Ghidra installation, keep it. 
				else if (oldGhidraInstallPath == null ||
					!oldGhidraInstallPath.isPrefixOf(entry.getPath())) {
					classpathEntriesToKeep.add(entry);
				}
			}
		}

		// If we detected a VM to potentially keep, we should ask the user if they are OK with using 
		// the VM that Ghidra wants to use.  Changing it automatically might cause problems for their 
		// existing Java project.
		if (vmEntryCandidate == null || (!vmEntryCandidate.getPath().equals(vmPath) &&
			EclipseMessageUtils.showConfirmDialog("Java Conflict",
				"Current Java: " + JavaRuntime.getVMInstall(javaProject).getName() +
					"\nGhidra Java: " + vm.getName() +
					"\n\nPress OK to use Ghidra's Java, or cancel to keep current Java."))) {
			classpathEntriesToKeep.add(JavaCore.newContainerEntry(vmPath));
		}
		else {
			classpathEntriesToKeep.add(vmEntryCandidate);
		}

		// Add the Ghidra libraries from the new Ghidra installation directory to the classpath
		List<IClasspathEntry> libraryClasspathEntries =
			getGhidraLibraryClasspathEntries(ghidraLayout);
		classpathEntriesToKeep.addAll(libraryClasspathEntries);

		// Set classpath
		javaProject.setRawClasspath(
			classpathEntriesToKeep.toArray(new IClasspathEntry[classpathEntriesToKeep.size()]),
			null);

		// Update link to the Ghidra installation directory
		ghidraFolder.createLink(new Path(ghidraInstallDir.getAbsolutePath()), IResource.REPLACE,
			monitor);

		// Update language ant properties file, if applicable
		GhidraModuleUtils.writeAntProperties(javaProject.getProject(), ghidraLayout);

		// Setup Python for the project
		if (PyDevUtils.isSupportedPyDevInstalled()) {
			try {
				PyDevUtils.setupPythonForProject(javaProject, libraryClasspathEntries,
					jythonInterpreterName, monitor);
			}
			catch (OperationNotSupportedException e) {
				EclipseMessageUtils.showErrorDialog("PyDev error",
					"Failed to setup Python for the project.  PyDev version is not supported.");
			}
		}
	}

	/**
	 * Gets the appropriate classpath attribute for Ghidra's javadoc in the provided layout.
	 *  
	 * @param ghidraLayout The Ghidra layout that contains the javadoc to get.
	 * @return The appropriate classpath attribute for Ghidra's javadoc in the provided layout.
	 * @throws FileNotFoundException If the javadoc was not found in the provided layout.
	 */
	private static IClasspathAttribute getGhidraJavadoc(GhidraApplicationLayout ghidraLayout)
			throws FileNotFoundException {
		File ghidraInstallDir = ghidraLayout.getApplicationInstallationDir().getFile(false);
		File ghidraJavadocFile = new File(ghidraInstallDir, "docs/GhidraAPI_javadoc.zip");
		if (!ghidraJavadocFile.isFile()) {
			throw new FileNotFoundException("Ghidra javadoc file does not exist!");
		}
		String ghidraJavadocPath = String.format("jar:file:%s%s!/api/",
			(ghidraJavadocFile.getAbsolutePath().startsWith("/") ? "" : "/"),
			ghidraJavadocFile.getAbsolutePath());
		return JavaCore.newClasspathAttribute("javadoc_location", ghidraJavadocPath);
	}

	/**
	 * Gets a list of classpath entries for Ghidra's module libraries.
	 * 
	 * @param ghidraLayout The Ghidra layout that contains the classpath entries to get.
	 * @return A list of classpath entries for Ghidra's module libraries.
	 * @throws FileNotFoundException If the javadoc was not found in the provided layout.
	 */
	private static List<IClasspathEntry> getGhidraLibraryClasspathEntries(
			GhidraApplicationLayout ghidraLayout) throws FileNotFoundException {

		IClasspathAttribute ghidraJavadocAttr = getGhidraJavadoc(ghidraLayout);
		List<IClasspathEntry> classpathEntries = new ArrayList<>();
		for (GModule module : ghidraLayout.getModules().values()) {
			File moduleDir = module.getModuleRoot().getFile(false);
			File libDir = new File(moduleDir, "lib");
			if (!libDir.isDirectory()) {
				continue;
			}
			for (File f : libDir.listFiles()) { // assuming no relevant subdirs exist in lib/
				String name = f.getName();
				if (!name.endsWith(".jar")) {
					continue;
				}

				IPath jarPath = new Path(f.getAbsolutePath());

				String baseJarName = name.substring(0, name.length() - 4);
				File srcZipFile = new File(libDir, baseJarName + "-src.zip");
				IPath srcPath = srcZipFile.exists() ? new Path(srcZipFile.getAbsolutePath()) : null;

				classpathEntries.add(JavaCore.newLibraryEntry(jarPath, srcPath, null, null,
					new IClasspathAttribute[] { ghidraJavadocAttr }, false));
			}
		}
		return classpathEntries;
	}

	/**
	 * Gets the required VM used to build and run the Ghidra defined by the given layout.
	 * 
	 * @param javaConfig Ghidra's Java configuration.
	 * @return The required VM used to build and run the Ghidra defined by the given layout.
	 * @throws IOException If there was a file-related problem with getting the VM.
	 * @throws CoreException If there was an Eclipse-related problem with creating the project.
	 */
	private static IVMInstall getGhidraVm(JavaConfig javaConfig) throws IOException, CoreException {

		File requiredJavaHomeDir = javaConfig.getSavedJavaHome(); // safe to assume it's valid

		// First look for a matching VM in Eclipse's existing list.
		// NOTE: Mac has its own VM type, so be sure to check it for VM matches too.
		IVMInstall vm = null;
		IVMInstallType standardType =
			JavaRuntime.getVMInstallType(StandardVMType.ID_STANDARD_VM_TYPE);
		IVMInstallType macType =
			JavaRuntime.getVMInstallType("org.eclipse.jdt.internal.launching.macosx.MacOSXType");
		if (standardType == null) {
			throw new CoreException(new Status(IStatus.ERROR, Activator.PLUGIN_ID, IStatus.ERROR,
				"Failed to find the standard Java VM type.", null));
		}
		for (IVMInstall existingVm : standardType.getVMInstalls()) {
			if (requiredJavaHomeDir.equals(existingVm.getInstallLocation())) {
				vm = existingVm;
				break;
			}
		}
		if (macType != null && vm == null) {
			for (IVMInstall existingVm : macType.getVMInstalls()) {
				if (requiredJavaHomeDir.equals(existingVm.getInstallLocation())) {
					vm = existingVm;
					break;
				}
			}
		}

		// If we didn't find a match, create a new standard type entry
		if (vm == null) {
			long unique = System.currentTimeMillis(); // This loop seems to be the accepted way to get a unique VM id
			while (standardType.findVMInstall(String.valueOf(unique)) != null) {
				unique++;
			}
			VMStandin vmStandin = new VMStandin(standardType, String.valueOf(unique));
			String dirName = requiredJavaHomeDir.getName();
			if (requiredJavaHomeDir.getAbsolutePath().contains("Contents/Home")) {
				dirName = requiredJavaHomeDir.getParentFile().getParentFile().getName();
			}
			vmStandin.setName(Activator.PLUGIN_ID + "_" + dirName);
			vmStandin.setInstallLocation(requiredJavaHomeDir);
			vm = vmStandin.convertToRealVM();
		}

		return vm;
	}

	/**
	 * Configures the default Java compiler behavior for the given java project.
	 * 
	 * @param jp The Java project to configure.
	 * @param javaConfig Ghidra's Java configuration.
	 */
	private static void configureJavaCompiler(IJavaProject jp, JavaConfig javaConfig) {

		final String WARNING = JavaCore.WARNING;
		final String IGNORE = JavaCore.IGNORE;
		final String ERROR = JavaCore.ERROR;

		// Compliance
		jp.setOption(JavaCore.COMPILER_SOURCE, javaConfig.getCompilerComplianceLevel());
		jp.setOption(JavaCore.COMPILER_COMPLIANCE, javaConfig.getCompilerComplianceLevel());
		jp.setOption(JavaCore.COMPILER_CODEGEN_TARGET_PLATFORM,
			javaConfig.getCompilerComplianceLevel());

		// Code style
		jp.setOption(JavaCore.COMPILER_PB_STATIC_ACCESS_RECEIVER, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_INDIRECT_STATIC_ACCESS, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_UNQUALIFIED_FIELD_ACCESS, IGNORE);
		jp.setOption(JavaCore.COMPILER_PB_UNDOCUMENTED_EMPTY_BLOCK, IGNORE);
		jp.setOption(JavaCore.COMPILER_PB_SYNTHETIC_ACCESS_EMULATION, IGNORE);
		jp.setOption(JavaCore.COMPILER_PB_METHOD_WITH_CONSTRUCTOR_NAME, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_PARAMETER_ASSIGNMENT, IGNORE);
		jp.setOption(JavaCore.COMPILER_PB_NON_NLS_STRING_LITERAL, IGNORE);

		// Potential programming problems
		jp.setOption(JavaCore.COMPILER_PB_MISSING_SERIAL_VERSION, IGNORE);
		jp.setOption(JavaCore.COMPILER_PB_NO_EFFECT_ASSIGNMENT, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_POSSIBLE_ACCIDENTAL_BOOLEAN_ASSIGNMENT, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_FINALLY_BLOCK_NOT_COMPLETING, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_EMPTY_STATEMENT, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_HIDDEN_CATCH_BLOCK, ERROR);
		jp.setOption(JavaCore.COMPILER_PB_VARARGS_ARGUMENT_NEED_CAST, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_AUTOBOXING, IGNORE);
		jp.setOption(JavaCore.COMPILER_PB_INCOMPLETE_ENUM_SWITCH, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_FALLTHROUGH_CASE, IGNORE);
		jp.setOption(JavaCore.COMPILER_PB_NULL_REFERENCE, WARNING);

		// Name shadowing and conflicts
		jp.setOption(JavaCore.COMPILER_PB_FIELD_HIDING, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_LOCAL_VARIABLE_HIDING, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_TYPE_PARAMETER_HIDING, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_OVERRIDING_PACKAGE_DEFAULT_METHOD, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_INCOMPATIBLE_NON_INHERITED_INTERFACE_METHOD, ERROR);

		// Deprecated and restricted API
		jp.setOption(JavaCore.COMPILER_PB_DEPRECATION, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_FORBIDDEN_REFERENCE, ERROR);
		jp.setOption(JavaCore.COMPILER_PB_DISCOURAGED_REFERENCE, WARNING);

		// Unnecessary code
		jp.setOption(JavaCore.COMPILER_PB_UNUSED_LOCAL, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_UNUSED_PARAMETER, IGNORE);
		jp.setOption(JavaCore.COMPILER_PB_UNUSED_IMPORT, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_UNUSED_PRIVATE_MEMBER, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_UNNECESSARY_ELSE, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_UNNECESSARY_TYPE_CHECK, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_UNUSED_DECLARED_THROWN_EXCEPTION, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_UNUSED_LABEL, WARNING);

		// Generic types
		jp.setOption(JavaCore.COMPILER_PB_UNCHECKED_TYPE_OPERATION, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_RAW_TYPE_REFERENCE, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_FINAL_PARAMETER_BOUND, WARNING);

		// Annotations
		jp.setOption(JavaCore.COMPILER_PB_MISSING_OVERRIDE_ANNOTATION, IGNORE);
		jp.setOption(JavaCore.COMPILER_PB_MISSING_DEPRECATED_ANNOTATION, IGNORE);
		jp.setOption(JavaCore.COMPILER_PB_ANNOTATION_SUPER_INTERFACE, ERROR);
		jp.setOption(JavaCore.COMPILER_PB_UNHANDLED_WARNING_TOKEN, WARNING);
		jp.setOption(JavaCore.COMPILER_PB_SUPPRESS_WARNINGS, JavaCore.ENABLED);
	}
}
