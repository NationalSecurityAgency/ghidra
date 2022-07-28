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
package docking.theme.gui;

import java.awt.BorderLayout;
import java.awt.Color;

import javax.swing.*;
import javax.swing.event.ChangeListener;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.options.editor.GhidraColorChooser;
import docking.theme.ColorValue;
import docking.theme.Gui;
import ghidra.util.Swing;

public class GThemeColorEditorDialog extends DialogComponentProvider {

	private ColorValue originalColorValue;
	private ColorValue currentColorValue;

	private GThemeDialog themeDialog;
	private GhidraColorChooser colorChooser;
	private ChangeListener colorChangeListener = e -> colorChanged();

	public GThemeColorEditorDialog(GThemeDialog themeDialog) {
		super("Theme Color Editor", false);
		this.themeDialog = themeDialog;
		addWorkPanel(buildColorPanel());
		addOKButton();
		addCancelButton();
	}

	public void editColor(ColorValue colorValue) {
		if (currentColorValue != null && !currentColorValue.equals(originalColorValue)) {
			themeDialog.colorChangeAccepted();
		}
		this.originalColorValue = colorValue;
		this.currentColorValue = colorValue;

		setTitle("Edit Color For: " + colorValue.getId());
		Color color = Gui.getRawColor(originalColorValue.getId());
		colorChooser.getSelectionModel().removeChangeListener(colorChangeListener);
		colorChooser.setColor(color);
		colorChooser.getSelectionModel().addChangeListener(colorChangeListener);

		if (!isShowing()) {
			DockingWindowManager.showDialog(themeDialog.getComponent(), this);
		}
	}

	private JComponent buildColorPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		colorChooser = new GhidraColorChooser();
		panel.add(colorChooser);

		return panel;
	}

	@Override
	protected void okCallback() {
		close();
		if (!currentColorValue.equals(originalColorValue)) {
			themeDialog.colorChangeAccepted();
		}
		currentColorValue = null;
		originalColorValue = null;
	}

	@Override
	protected void cancelCallback() {
		retoreOriginalColor();
		close();
		currentColorValue = null;
		originalColorValue = null;
	}

	private void retoreOriginalColor() {
		Gui.setColor(originalColorValue);
	}

	private void colorChanged() {
		Color newColor = colorChooser.getColor();
		currentColorValue = new ColorValue(originalColorValue.getId(), newColor);
		Swing.runLater(() -> Gui.setColor(currentColorValue));
	}

}
