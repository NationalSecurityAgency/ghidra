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
package ghidradev.ghidrasymbollookup;

import java.util.*;
import java.util.regex.Pattern;

import org.eclipse.cdt.core.CCorePlugin;
import org.eclipse.cdt.core.browser.ITypeReference;
import org.eclipse.cdt.core.browser.IndexTypeInfo;
import org.eclipse.cdt.core.dom.ast.IASTFileLocation;
import org.eclipse.cdt.core.index.*;
import org.eclipse.cdt.core.model.CoreModel;
import org.eclipse.cdt.core.model.ICProject;
import org.eclipse.cdt.internal.ui.browser.opentype.ElementSelectionDialog;
import org.eclipse.cdt.internal.ui.browser.opentype.OpenTypeMessages;
import org.eclipse.core.resources.*;
import org.eclipse.core.runtime.*;
import org.eclipse.swt.widgets.Display;
import org.eclipse.ui.ide.IDE;

import ghidradev.EclipseMessageUtils;

public class OpenDeclarations {

	private IProject project;
	private HashMap<String, IMarker> symbolMap;

	public OpenDeclarations(IProject project) {
		this.project = project;
		this.symbolMap = new HashMap<String, IMarker>();
	}

	public void setProject(IProject newProject) {
		project = newProject;
	}

	public boolean open(String filename, int lineNumber) {
		openSingleFileAtLineNumber(filename, lineNumber);
		return true;
	}

	public boolean open(String symbolName) {
		IIndex index = null;
		if (symbolMap.containsKey(symbolName)) {
			EclipseMessageUtils.info("Re-using editor for symbol: " + symbolName);
			openFileFromMap(symbolName);
			return true;
		}

		EclipseMessageUtils.info("Searching index for symbol: " + symbolName);
		List<IIndexName> indexNames = new ArrayList<>();
		ICProject cProject = CoreModel.getDefault().getCModel().getCProject(project.getName());
		IIndexManager manager = CCorePlugin.getIndexManager();

		try {
			index = manager.getIndex(cProject);

			// we may be called before Eclipse has run the CDT plugin's init
			waitForIndexInitialization(index);

			index.acquireReadLock();

			IIndexBinding[] bindings = index.findBindings(Pattern.compile(symbolName), false,
				IndexFilter.ALL, new NullProgressMonitor());
			EclipseMessageUtils.info("Found \"" + bindings.length + "\" bindings for symbol");
			for (IIndexBinding binding : bindings) {
				IIndexName[] names = index.findNames(binding, IIndex.FIND_DEFINITIONS);
				for (IIndexName name : names) {
					indexNames.add(name);
				}
			}

			if (indexNames.size() == 0) {
				EclipseMessageUtils.info("Found no definitions, looking for declarations...");
				for (IIndexBinding binding : bindings) {
					IIndexName[] names = index.findNames(binding, IIndex.FIND_DECLARATIONS);
					for (IIndexName name : names) {
						indexNames.add(name);
					}
				}
			}
			if (indexNames.size() == 1) {
				EclipseMessageUtils.info("Found single match - opening editor");
				openSingleFile(indexNames.get(0).getFileLocation(), symbolName);
				return true;
			}
			else if (indexNames.size() > 1) {
				EclipseMessageUtils.info("Found multiple matches - showing dialog");
				openMultipleFileDialog(symbolName);
				return true;
			}
			return false;

		}
		catch (Exception e) {
			EclipseMessageUtils.error("Unexpected exception searching C index: " + e.getMessage(),
				e);
			return false;
		}
		finally {
			if (index != null) {
				index.releaseReadLock();
			}
		}
	}

	private void waitForIndexInitialization(IIndex index) throws CoreException {
		int waitCount = 0;
		while (waitCount < 2) {
			waitCount++;
			try {
				index.acquireReadLock();

				IIndexFile[] allFiles = index.getAllFiles();
				if (allFiles.length == 0) {
					EclipseMessageUtils.info("C Index is not yet initialized--waiting...");
					index.releaseReadLock();
					Thread.sleep(1000);
				}
			}
			catch (InterruptedException e) {
				// don't care; try again
			}
			finally {
				index.releaseReadLock();
			}
		}

	}

	private void openSingleFile(IASTFileLocation location, String functionName) {
		String pathToFix = location.getFileName();
		String projectName = project.getName();
		int index = pathToFix.indexOf(projectName);
		if (index == -1) {
			EclipseMessageUtils.error("Error opening the file containing " + pathToFix);
			return;
		}
		String relativePath = pathToFix.substring(index);
		final IPath path = new Path(relativePath).removeFirstSegments(1); // strip off project name
		final int offset = location.getNodeOffset();
		final int length = location.getNodeLength();
		final String fName = functionName;
		Display.getDefault().asyncExec(() -> {
			try {
				IFile file = project.getFile(path);
				IMarker marker = file.createMarker(IMarker.TEXT);
				marker.setAttribute(IMarker.CHAR_START, offset);
				marker.setAttribute(IMarker.CHAR_END, offset + length);
				IDE.openEditor(EclipseMessageUtils.getWorkbenchPage(), marker);
				symbolMap.put(fName, marker);
				EclipseMessageUtils.getWorkbenchPage().getWorkbenchWindow().getShell().forceActive();
			}
			catch (CoreException e) {
				EclipseMessageUtils.error("Error opening the file containing " + fName, e);
			}
		});
	}

	private void openMultipleFileDialog(String functionName) {
		final ElementSelectionDialog dialog = new ElementSelectionDialog(
			EclipseMessageUtils.getWorkbenchPage().getWorkbenchWindow().getShell());
		configureDialog(dialog, functionName);
		final String fName = functionName;
		Display.getDefault().asyncExec(() -> {
			EclipseMessageUtils.getWorkbenchPage().getWorkbenchWindow().getShell().forceActive();
			dialog.open();
			Object[] results = dialog.getResult();
			if (results == null) {
				return; // user cancelled the dialog
			}

			for (Object result : results) {
				if (result instanceof IndexTypeInfo) {
					ITypeReference reference = ((IndexTypeInfo) result).getResolvedReference();
					IPath path = reference.getPath();
					path = path.removeFirstSegments(1);
					IFile file = project.getFile(path);
					try {
						IMarker marker = file.createMarker(IMarker.TEXT);
						marker.setAttribute(IMarker.CHAR_START, reference.getOffset());
						marker.setAttribute(IMarker.CHAR_END,
							reference.getOffset() + reference.getLength());
						IDE.openEditor(EclipseMessageUtils.getWorkbenchPage(), marker);
						symbolMap.put(fName, marker);
					}
					catch (CoreException e) {
						EclipseMessageUtils.error("Error opening file chosen from selection dialog",
							e);
					}
				}
			}
		});
	}

	private void openSingleFileAtLineNumber(final String relativeFilename, final int lineNumber) {
		final IPath path = new Path(relativeFilename).removeFirstSegments(1); // strip off project
		Display.getDefault().asyncExec(() -> {
			try {
				IFile file = project.getFile(path);
				IMarker marker = file.createMarker(IMarker.TEXT);
				marker.setAttribute(IMarker.LINE_NUMBER, lineNumber);
				IDE.openEditor(EclipseMessageUtils.getWorkbenchPage(), marker);
				EclipseMessageUtils.getWorkbenchPage().getWorkbenchWindow().getShell().forceActive();
			}
			catch (CoreException e) {
				EclipseMessageUtils.error("Error opening the file containing at line " + lineNumber,
					e);
			}
		});
	}

	private void configureDialog(ElementSelectionDialog dialog, String functionName) {
		dialog.setTitle(OpenTypeMessages.OpenTypeDialog_title);
		dialog.setMessage(OpenTypeMessages.OpenTypeDialog_message);
		dialog.setDialogSettings(getClass().getName());
		dialog.setIgnoreCase(true);
		if (functionName.length() > 0 && functionName.length() < 80) {
			dialog.setFilter(functionName, true);
		}
	}

	private void openFileFromMap(String functionName) {
		final IMarker marker = symbolMap.get(functionName);
		Display.getDefault().asyncExec(() -> {
			try {
				IDE.openEditor(EclipseMessageUtils.getWorkbenchPage(), marker);
				EclipseMessageUtils.getWorkbenchPage().getWorkbenchWindow().getShell().forceActive();
			}
			catch (CoreException e) {
				EclipseMessageUtils.error("Error opening file from map", e);
			}
		});
	}
}
