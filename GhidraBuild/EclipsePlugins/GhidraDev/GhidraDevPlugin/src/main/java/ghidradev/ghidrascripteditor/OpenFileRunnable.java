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
package ghidradev.ghidrascripteditor;

import java.awt.Dimension;
import java.io.File;
import java.util.*;

import org.eclipse.core.resources.*;
import org.eclipse.core.runtime.*;
import org.eclipse.jdt.core.IJavaProject;
import org.eclipse.jface.viewers.LabelProvider;
import org.eclipse.jface.viewers.StructuredSelection;
import org.eclipse.jface.window.Window;
import org.eclipse.jface.wizard.WizardDialog;
import org.eclipse.ui.*;
import org.eclipse.ui.dialogs.ElementListSelectionDialog;
import org.eclipse.ui.ide.IDE;

import ghidradev.EclipseMessageUtils;
import ghidradev.ghidraprojectcreator.utils.GhidraProjectUtils;
import ghidradev.ghidraprojectcreator.wizards.CreateGhidraScriptProjectWizard;

public class OpenFileRunnable implements Runnable {
	private String filePath;

	public OpenFileRunnable(String filePath) {
		this.filePath = filePath;
	}

	@Override
	public void run() {
		List<IFile> projectFiles = findMatchingFiles(filePath);
		IFile[] filesToOpen = maybePromptUserForFilesToOpen(projectFiles);
		openFiles(filesToOpen);
	}

	private void openFiles(IFile[] userFileChoices) {
		if (userFileChoices == null) {
			return; // user cancelled
		}

		for (IFile file : userFileChoices) {
			openFile(file);
		}
	}

	private void openFile(IFile file) {
		IWorkbenchPage page = EclipseMessageUtils.getWorkbenchPage();
		try {
			IDE.openEditor(page, file);
		}
		catch (PartInitException e) {
			EclipseMessageUtils.showErrorDialog("Unable to Open Script",
				"Couldn't open editor for " + filePath);
		}
		page.getWorkbenchWindow().getShell().forceActive();
	}

	private IFile[] maybePromptUserForFilesToOpen(List<IFile> projectFiles) {
		if (projectFiles.size() == 0) {
			return null;
		}

		if (projectFiles.size() == 1) {
			return new IFile[] { projectFiles.get(0) };
		}

		// look for any project ending in 'scripts' and assume that is the preferred project
		for (IFile iFile : projectFiles) {
			IProject project = iFile.getProject();
			String projectName = project.getName();
			if (projectName.toLowerCase().endsWith("scripts")) {
				return new IFile[] { projectFiles.get(0) };
			}
		}

		IWorkbenchPage page = EclipseMessageUtils.getWorkbenchPage();
		ElementListSelectionDialog dialog = new ElementListSelectionDialog(
			page.getWorkbenchWindow().getShell(), new LabelProvider());
		dialog.setTitle("Choose a File");
		List<DisplayableIFile> displayableFiles = formatStrings(projectFiles);
		dialog.setMultipleSelection(true);
		dialog.setElements(displayableFiles.toArray(new DisplayableIFile[displayableFiles.size()]));
		dialog.setMessage("Select a file to open");

		Dimension size = calculatePreferredSizeInCharacters(displayableFiles);
		dialog.setSize(size.width, size.height);

		dialog.open();
		Object[] results = dialog.getResult();
		IFile[] resultFiles = new IFile[results.length];
		for (int i = 0; i < results.length; i++) {
			resultFiles[i] = ((DisplayableIFile) results[i]).getFile();
		}
		return resultFiles;
	}

	private List<IFile> findMatchingFiles(String path) {
		Collection<IJavaProject> javaProjects = GhidraProjectUtils.getGhidraProjects();
		List<IFile> projectFiles = findMatchingFilesInProjects(path, javaProjects);
		if (projectFiles.isEmpty()) {
			try {
				for (IJavaProject javaProject : javaProjects) {
					javaProject.getProject().refreshLocal(IResource.DEPTH_INFINITE,
						new NullProgressMonitor());
				}
			}
			catch (CoreException e1) {
				EclipseMessageUtils.showErrorDialog("Unable to Open Script",
					"Unexpected Exception refreshing project");
				return new ArrayList<IFile>();
			}
		}

		projectFiles = findMatchingFilesInProjects(path, javaProjects);
		if (projectFiles.isEmpty()) {
			boolean createProject = EclipseMessageUtils.showConfirmDialog("Unable to Open Script",
				"File does not exist in any Eclipse project in your workspace.\n\n" +
					"Would you like to create a new Ghidra Scripting project?");
			if (createProject) {
				INewWizard wizard = new CreateGhidraScriptProjectWizard();
				wizard.init(PlatformUI.getWorkbench(), new StructuredSelection());
				WizardDialog dialog = new WizardDialog(
					PlatformUI.getWorkbench().getActiveWorkbenchWindow().getShell(), wizard);
				dialog.setBlockOnOpen(true);
				if (dialog.open() == Window.OK) {
					return findMatchingFilesInProjects(path,
						GhidraProjectUtils.getGhidraProjects());
				}
			}
			return new ArrayList<IFile>();
		}
		return projectFiles;
	}

	private Dimension calculatePreferredSizeInCharacters(List<DisplayableIFile> files) {
		int width = 0;
		int height = 10;
		for (DisplayableIFile file : files) {
			String displayString = file.getDisplayString();
			width = Math.max(width, displayString.length());
		}
		width = Math.min(width + 7, 100);
		height = Math.min(height, files.size() + 3);
		return new Dimension(width, height);
	}

	private List<IFile> findMatchingFilesInProjects(String pathString,
			Collection<IJavaProject> javaProjects) {
		List<IFile> files = new ArrayList<IFile>();
		for (IJavaProject javaProject : javaProjects) {
			IProject project = javaProject.getProject();
			if (!project.isOpen()) {
				continue;
			}

			try {
				IPath path = findPathFromFolder(pathString, project);
				if (path != null) {
					IFile file = project.getFile(path);
					files.add(file);
				}
			}
			catch (CoreException e) {
				EclipseMessageUtils.error("Unexpected exception accessing project members", e);
			}
		}
		return files;
	}

	private IPath findPathFromFolder(String pathString, IResource resource) throws CoreException {
		if (!(resource instanceof IContainer)) {
			return null;
		}

		IContainer container = (IContainer) resource;
		IResource[] members = container.members();
		for (IResource member : members) {
			IPath location = member.getLocation();

			// compare as files in order to bypass path separator issues
			File fileForPath = new File(pathString);
			File fileForLocation = location.toFile();
			if (fileForLocation.equals(fileForPath)) {
				return member.getProjectRelativePath();
			}

			IPath pathFromFolder = findPathFromFolder(pathString, member);
			if (pathFromFolder != null) {
				return pathFromFolder;
			}
		}
		return null;
	}

	private List<DisplayableIFile> formatStrings(List<IFile> projectFiles) {
		List<DisplayableIFile> list = new ArrayList<DisplayableIFile>();
		for (IFile file : projectFiles) {
			list.add(new DisplayableIFile(file));
		}

		return list;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class DisplayableIFile {
		private final IFile file;
		private final String displayString;

		private DisplayableIFile(IFile file) {
			this.file = file;

			String format = "";
			String[] strings = file.toString().split("/");
			for (int i = 1; i < strings.length - 1; i++) {
				format += strings[i] + "/";
			}
			displayString =
				format.substring(0, format.length() - 1) + " - " + strings[strings.length - 1];
		}

		IFile getFile() {
			return file;
		}

		String getDisplayString() {
			return displayString;
		}

		@Override
		public String toString() {
			return getDisplayString();
		}
	}
}
