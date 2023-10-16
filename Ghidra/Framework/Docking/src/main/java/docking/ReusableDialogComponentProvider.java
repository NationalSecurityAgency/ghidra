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
package docking;

import java.awt.Component;

import javax.swing.SwingUtilities;

import generic.theme.*;
import ghidra.util.task.Task;

/**
 * A version of {@link DialogComponentProvider} for clients to extend when they intend for their
 * dialog to be reused.   Typically, dialogs are used once and then no longer referenced.
 * Alternatively, some clients create a dialog and use it for the lifetime of their code.  This
 * is typical of non-modal plugins.
 * <p>
 * If you extend this class, then you must call the {@link #dispose()} method when you are done
 * with the dialog, such as in your plugin's {@code dispose()} method.
 * <p>
 * The primary benefit of using this dialog is that any updates to the current theme will update
 * this dialog, even when the dialog is not visible.  For dialogs that extend
 * {@link DialogComponentProvider} directly, they only receive theme updates if they are visible.
 * 
 * @see DialogComponentProvider
 */
public class ReusableDialogComponentProvider extends DialogComponentProvider {

	private ThemeListener themeListener = this::themeChanged;

	protected ReusableDialogComponentProvider(String title) {
		this(title, true, true, true, false);
	}

	/**
	 * Constructs a new ReusableDialogComponentProvider.
	 * @param title the title for this dialog.
	 * @param modal true if this dialog should be modal.
	 * @param includeStatus true if this dialog should include a status line.
	 * @param includeButtons true if this dialog will have a button panel at the bottom.
	 * @param canRunTasks true means this dialog can execute tasks
	 *        ({@link #executeProgressTask(Task, int)} and it will show a progress monitor when
	 *        doing so.
	 */
	protected ReusableDialogComponentProvider(String title, boolean modal, boolean includeStatus,
			boolean includeButtons, boolean canRunTasks) {
		super(title, modal, includeStatus, includeButtons, canRunTasks);
		Gui.addThemeListener(themeListener);
	}

	private void themeChanged(ThemeEvent ev) {
		// if we are visible, then we don't need to update as the system updates all visible components
		if (isVisible()) {
			return;
		}
		Component component = dialog != null ? dialog : rootPanel;
		SwingUtilities.updateComponentTreeUI(component);
	}

	@Override
	public void close() {
		// Overridden to *not* all dispose() when closed, since this dialog is meant to be reused
		closeDialog();
	}

	@Override
	public void dispose() {
		super.dispose();
		Gui.removeThemeListener(themeListener);
	}
}
