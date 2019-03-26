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
package ghidradev;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.eclipse.core.resources.IFile;
import org.eclipse.core.runtime.*;
import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.ui.*;
import org.eclipse.ui.ide.IDE;
import org.eclipse.ui.progress.UIJob;
import org.eclipse.ui.statushandlers.StatusManager;

public class EclipseMessageUtils {

	private static IWorkbenchPage workbenchPage = getWorkbenchPage();
	private static Shell shell = workbenchPage.getWorkbenchWindow().getShell();

	/**
	 * Prevent instantiation.
	 */
	private EclipseMessageUtils() {
		// Nothing to do
	}

	/**
	 * Shows an information dialog with a custom title and message.
	 * 
	 * @param title The title of the information dialog.
	 * @param message The message of the information dialog.
	 */
	public static void showInfoDialog(final String title, final String message) {
		Display.getDefault().syncExec(() -> {
			shell.forceActive();
			MessageDialog.openInformation(shell, title, message);
		});
	}

	/**
	 * Shows a confirmation dialog with a custom title and message.
	 * 
	 * @param title The title of the confirmation dialog.
	 * @param message The message of the confirmation dialog.
	 * @return True of ok was pressed; false if canceled was pressed.
	 */
	public static boolean showConfirmDialog(final String title, final String message) {
		AtomicBoolean okPressed = new AtomicBoolean();
		Display.getDefault().syncExec(() -> {
			shell.forceActive();
			okPressed.set(MessageDialog.openConfirm(shell, title, message));
		});
		return okPressed.get();
	}

	/**
	 * Shows a question dialog with a custom title and message.
	 * 
	 * @param title The title of the question dialog.
	 * @param message The message of the question dialog.
	 * @return True of yes was pressed; false if no was pressed.
	 */
	public static boolean showQuestionDialog(final String title, final String message) {
		AtomicBoolean yesPressed = new AtomicBoolean();
		Display.getDefault().syncExec(() -> {
			shell.forceActive();
			yesPressed.set(MessageDialog.openQuestion(shell, title, message));
		});
		return yesPressed.get();
	}

	/**
	 * Shows an error dialog with a custom title and message.
	 * 
	 * @param title The title of the error dialog.
	 * @param message The message of the error dialog.
	 */
	public static void showErrorDialog(final String title, final String message) {
		Display.getDefault().syncExec(() -> {
			shell.forceActive();
			MessageDialog.openError(shell, title, message);
		});
	}

	/**
	 * Shows an error dialog with a default title and custom message.
	 * 
	 * @param message The message of the error dialog.
	 */
	public static void showErrorDialog(final String message) {
		showErrorDialog(Activator.PLUGIN_ID + " error", message);
	}

	/**
	 * Shows a warning dialog with a custom title and custom message.
	 * 
	 * @param title The title of the warning dialog.
	 * @param message The message of the error dialog.
	 */
	public static void showWarnDialog(final String title, final String message) {
		Display.getDefault().syncExec(() -> {
			shell.forceActive();
			MessageDialog.openWarning(shell, title, message);
		});
	}

	/**
	 * Shows an error dialog that a wizard can use to display information about an exception that
	 * occurred while wizard'ing.
	 *  
	 * @param wizardShell The wizard's shell.
	 * @param e The exception that occurred.
	 * @return The displayed message.
	 */
	public static String showWizardErrorDialog(Shell wizardShell, InvocationTargetException e) {
		String message = null;
		Throwable cause = e.getCause();
		if (cause != null) {
			message = cause.getClass().getSimpleName();
			if (cause.getMessage() != null && !cause.getMessage().isEmpty()) {
				message += ": " + cause.getMessage();
			}
		}
		else {
			message = e.getClass().getSimpleName();
		}
		MessageDialog.openError(wizardShell, "Error", message);
		return message;
	}

	/**
	 * Logs an info message.
	 * 
	 * @param message The message to display.
	 */
	public static void info(String message) {
		StatusManager.getManager().handle(new Status(IStatus.INFO, Activator.PLUGIN_ID, message));
	}

	/**
	 * Logs an error message.
	 * 
	 * @param message The message to display.
	 */
	public static void error(String message) {
		StatusManager.getManager().handle(new Status(IStatus.ERROR, Activator.PLUGIN_ID, message));
	}

	/**
	 * Logs an error message with the responsible error included.
	 * 
	 * @param message The message to display.
	 * @param t The responsible throwable.
	 */
	public static void error(String message, Throwable t) {
		StatusManager.getManager().handle(
			new Status(IStatus.ERROR, Activator.PLUGIN_ID, message, t));
	}

	public static IWorkbenchPage getWorkbenchPage() {
		IWorkbench workbench = PlatformUI.getWorkbench();
		IWorkbenchWindow workbenchWindow = getWorkbenchWindow(workbench);
		if (workbenchWindow == null) {
			error("Couldn't get workbench window");
			return null;
		}
		IWorkbenchPage wbp = getPage(workbenchWindow);
		if (wbp == null) {
			error("Couldn't get workbench page");
			return null;
		}
		return wbp;
	}

	private static IWorkbenchWindow getWorkbenchWindow(IWorkbench workbench) {
		IWorkbenchWindow workbenchWindow = workbench.getActiveWorkbenchWindow();
		if (workbenchWindow != null) {
			return workbenchWindow;
		}
		IWorkbenchWindow[] windows = workbench.getWorkbenchWindows();
		for (IWorkbenchWindow window : windows) {
			if (window != null) {
				return window;
			}
		}
		return null;
	}

	private static IWorkbenchPage getPage(IWorkbenchWindow workbenchWindow) {
		IWorkbenchPage wbp = workbenchWindow.getActivePage();
		if (wbp != null) {
			return wbp;
		}
		IWorkbenchPage[] pages = workbenchWindow.getPages();
		for (IWorkbenchPage page : pages) {
			if (page != null) {
				return page;
			}
		}
		return null;
	}

	/**
	 * Displays the given file in an editor using the Java perspective.  
	 * If something goes wrong, this method has no effect. 
	 * 
	 * @param file The file to display.
	 * @param workbench The workbench.
	 */
	public static void displayInEditor(IFile file, IWorkbench workbench) {
		new UIJob("Display in editor") {
			@Override
			public IStatus runInUIThread(IProgressMonitor m) {
				try {
					IWorkbenchWindow window = workbench.getActiveWorkbenchWindow();
					IDE.openEditor(window.getActivePage(), file);
					workbench.showPerspective("org.eclipse.jdt.ui.JavaPerspective", window);
					return Status.OK_STATUS;
				}
				catch (NullPointerException | WorkbenchException e) {
					return Status.CANCEL_STATUS;
				}
			}
		}.schedule();
	}
}
