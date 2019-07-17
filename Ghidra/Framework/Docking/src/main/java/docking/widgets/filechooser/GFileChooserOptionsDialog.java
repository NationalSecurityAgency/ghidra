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
package docking.widgets.filechooser;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GLabel;
import ghidra.framework.preferences.Preferences;
import ghidra.util.layout.PairLayout;

class GFileChooserOptionsDialog extends DialogComponentProvider {

	static final String SHOW_DOT_FILES_PROPERTY_NAME = "G_FILE_CHOOSER.ShowDotFiles";
	private static final String SHOW_DOT_FILES_DEFAULT = "false";

	private JCheckBox showDotFilesCheckBox;

	GFileChooserOptionsDialog() {
		super("File Chooser Options", true);

		addWorkPanel(buildComponent());

		addOKButton();
		addCancelButton();

		setPreferredSize(300, 100);
	}

	@Override
	protected void dialogShown() {
		initializeValues();
	}

	private JComponent buildComponent() {
		JPanel panel = new JPanel(new PairLayout());

		showDotFilesCheckBox = new GCheckBox();
		showDotFilesCheckBox.setSelected(true);

		JLabel label = new GLabel("Show '.' files");
		label.setToolTipText("When toggled on the file chooser will show files " +
			"with names that begin with a '.' character");

		panel.add(showDotFilesCheckBox);
		panel.add(label);

		return panel;
	}

	private void initializeValues() {
		boolean showDotFiles = getShowsDotFiles();
		showDotFilesCheckBox.setSelected(showDotFiles);
	}

	@Override
	protected void okCallback() {
		// apply the user changes
		Preferences.setProperty(SHOW_DOT_FILES_PROPERTY_NAME,
			Boolean.toString(showDotFilesCheckBox.isSelected()));
		Preferences.store();

		close();
	}

//==================================================================================================
// Options Getter Methods
//==================================================================================================

	boolean getShowsDotFiles() {
		String showDotFilesValue =
			Preferences.getProperty(SHOW_DOT_FILES_PROPERTY_NAME, SHOW_DOT_FILES_DEFAULT, true);
		return Boolean.parseBoolean(showDotFilesValue);
	}
}
