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
package ghidra.app.plugin.gui;

import java.io.File;
import java.io.IOException;
import java.util.List;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.DialogComponentProvider;
import docking.theme.gui.ThemeUtils;
import docking.widgets.combobox.GhidraComboBox;
import generic.theme.GTheme;
import generic.theme.ThemeManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.layout.PairLayout;

public class CreateThemeDialog extends DialogComponentProvider {

	private JTextField nameField;
	private ThemeManager themeManager;
	private GhidraComboBox<GTheme> combo;
	private GTheme newTheme;

	protected CreateThemeDialog(ThemeManager themeManager) {
		super("Create Theme");
		this.themeManager = themeManager;

		addWorkPanel(buildMainPanel());
		addOKButton();
		addCancelButton();
	}

	@Override
	protected void okCallback() {
		String themeName = nameField.getText().trim();
		File file = ThemeUtils.getSaveFile(themeName);
		GTheme baseTheme = (GTheme) combo.getSelectedItem();
		newTheme = new GTheme(file, themeName, baseTheme.getLookAndFeelType(),
			baseTheme.useDarkDefaults());
		newTheme.load(baseTheme);
		try {
			newTheme.save();
		}
		catch (IOException e) {
			Msg.showError(ThemeUtils.class, null, "I/O Error",
				"Error writing theme file: " + newTheme.getFile().getAbsolutePath(), e);
			newTheme = null;
		}
		close();
	}

	@Override
	protected void cancelCallback() {
		close();
	}

	private JComponent buildMainPanel() {
		JPanel panel = new JPanel(new PairLayout(10, 10));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		nameField = createNameField();
		combo = buildThemeCombo();

		panel.add(new JLabel("New Theme Name: "));
		panel.add(nameField);
		panel.add(new JLabel("Base Theme: "));
		panel.add(combo);

		return panel;
	}

	private JTextField createNameField() {
		JTextField jTextField = new JTextField(20);
		jTextField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void removeUpdate(DocumentEvent e) {
				updateOk();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				updateOk();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				updateOk();
			}

		});
		return jTextField;
	}

	private void updateOk() {
		String name = nameField.getText().trim();
		setOkEnabled(isValidThemeName(name));
	}

	private boolean isValidThemeName(String name) {
		if (name.isBlank()) {
			setStatusText("You must enter a theme name!");
			return false;
		}
		GTheme existing = themeManager.getTheme(name);
		// if no theme exists with that name, then we are safe to save it
		if (existing != null) {
			setStatusText("Theme already exists with that name!");
			return false;
		}
		clearStatusText();
		return true;
	}

	private GhidraComboBox<GTheme> buildThemeCombo() {
		List<GTheme> supportedThemes = themeManager.getSupportedThemes();

		GhidraComboBox<GTheme> ghidraComboBox = new GhidraComboBox<>(supportedThemes);
		ghidraComboBox.setSelectedItem(themeManager.getActiveTheme());
		return ghidraComboBox;
	}

	public GTheme getNewTheme(PluginTool tool, String suggestedName) {
		if (suggestedName != null) {
			nameField.setText(suggestedName);
			nameField.selectAll();
		}
		updateOk();
		tool.showDialog(this);
		return newTheme;
	}
}
