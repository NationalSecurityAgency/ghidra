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
package docking.options.editor;

import java.awt.Color;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;

import javax.swing.tree.TreePath;

import docking.DialogComponentProvider;
import ghidra.framework.options.Options;

/**
 * Dialog for editing options within a tool.
 */
public class OptionsDialog extends DialogComponentProvider {
	private OptionsPanel panel;
	private boolean hasChanges;

	private OptionsEditorListener listener;

	/**
	 * Construct a new OptionsDialog.
	 * 
	 * @param title dialog title
	 * @param rootNodeName name to display for the root node in the tree
	 * @param options editable options
	 * @param listener listener notified when the apply button is hit.
	 */
	public OptionsDialog(String title, String rootNodeName, Options[] options,
			OptionsEditorListener listener) {
		this(title, rootNodeName, options, listener, false);
	}

	public OptionsDialog(String title, String rootNodeName, Options[] options,
			OptionsEditorListener listener, boolean showRestoreDefaultsButton) {
		super("OptionsDialog.Foofoo", true, false, true, false);
		this.listener = listener;
		panel = new OptionsPanel(rootNodeName, options, showRestoreDefaultsButton,
			new OptionsPropertyChangeListener());

		setTitle(title);
		setBackground(Color.lightGray);

		addWorkPanel(panel);
		addOKButton();
		addCancelButton();
		addApplyButton();
		setApplyEnabled(false);
		setMinimumSize(1000, 600);

		setFocusComponent(panel.getFocusComponent());
	}

	public void dispose() {
		panel.dispose();
	}

	public TreePath getSelectedPath() {
		return panel.getSelectedPath();
	}

	public void setSelectedPath(TreePath path) {
		panel.setSelectedPath(path);
	}

	private void setHasChanges(boolean hasChanges) {
		this.hasChanges = hasChanges;
		setApplyEnabled(hasChanges);
	}

	@Override
	protected void cancelCallback() {
		if (panel.cancel()) {
			close();
		}
	}

	@Override
	protected void okCallback() {
		if (hasChanges) {
			if (!applyChanges()) {
				return; // don't close on failure
			}
		}
		close();
	}

	@Override
	protected void applyCallback() {
		applyChanges();
	}

	private boolean applyChanges() {
		if (listener != null) {
			listener.beforeChangesApplied();
		}
		try {
			if (panel.apply()) {
				setHasChanges(false);
				return true;
			}
		}
		finally {
			if (listener != null) {
				listener.changesApplied();
			}
		}
		return false;
	}

	public void displayCategory(String category, String filterText) {
		if (panel != null) {
			panel.displayCategory(category, filterText);
		}
	}

//=========================================================
// Inner Classes
//=========================================================	

	class OptionsPropertyChangeListener implements PropertyChangeListener {
		@Override
		public void propertyChange(PropertyChangeEvent evt) {
			if (evt.getPropertyName().equals("apply.enabled")) {
				setHasChanges((Boolean) evt.getNewValue());
			}
		}
	}
}
