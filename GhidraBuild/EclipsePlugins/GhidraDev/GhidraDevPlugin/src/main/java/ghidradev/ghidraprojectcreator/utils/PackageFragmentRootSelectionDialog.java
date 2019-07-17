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

import org.eclipse.core.resources.ResourcesPlugin;
import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.Status;
import org.eclipse.jdt.core.*;
import org.eclipse.jdt.ui.JavaElementLabelProvider;
import org.eclipse.jdt.ui.StandardJavaElementContentProvider;
import org.eclipse.jface.viewers.Viewer;
import org.eclipse.jface.viewers.ViewerFilter;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.ui.dialogs.ElementTreeSelectionDialog;
import org.eclipse.ui.dialogs.ISelectionStatusValidator;

import ghidradev.Activator;

/**
 * A dialog that lets you choose a Java package fragment root, which is basically a top-level
 * source folder.
 */
public class PackageFragmentRootSelectionDialog extends ElementTreeSelectionDialog {

	/**
	 * Creates a new package fragment root selection dialog.
	 * 
	 * @param shell The parent shell for the dialog.
	 * @param title The title of the dialog.
	 * @param message The message of the dialog.
	 * @param errorMessage the error message to display if an invalid selection is made.
	 */
	public PackageFragmentRootSelectionDialog(Shell shell, String title, String message,
			String errorMessage) {
		super(shell, new JavaElementLabelProvider(JavaElementLabelProvider.SHOW_DEFAULT),
			new StandardJavaElementContentProvider());
		setTitle(title);
		setMessage(message);
		setAllowMultiple(false);
		setInput(JavaCore.create(ResourcesPlugin.getWorkspace().getRoot()));

		setValidator(new ISelectionStatusValidator() {

			@Override
			public IStatus validate(Object[] sel) {
				if (sel.length == 1 && sel[0] instanceof IPackageFragmentRoot) {
					return new Status(IStatus.OK, Activator.PLUGIN_ID, IStatus.OK, "", null);
				}
				return new Status(IStatus.ERROR, Activator.PLUGIN_ID, IStatus.ERROR, errorMessage,
					null);
			}
		});

		addFilter(new ViewerFilter() {
			@Override
			public boolean select(Viewer viewer, Object parentObject, Object element) {

				if (element instanceof IPackageFragmentRoot) {
					IPackageFragmentRoot packageFragmentRoot = (IPackageFragmentRoot) element;
					return !packageFragmentRoot.isArchive() && !packageFragmentRoot.isExternal();
				}

				return element instanceof IJavaModel || element instanceof IJavaProject;
			}
		});
	}

	/**
	 * Gets the selected package fragment root.
	 * 
	 * @return The selected package fragment root. Could be null if there is not a valid
	 * selection.
	 */
	public IPackageFragmentRoot getPackageFragmentRoot() {
		Object[] result = getResult();
		if (result.length == 1 && result[0] instanceof IPackageFragmentRoot) {
			return (IPackageFragmentRoot) result[0];
		}
		return null;
	}
}
