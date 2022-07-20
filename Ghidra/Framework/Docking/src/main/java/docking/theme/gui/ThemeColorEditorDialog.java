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

public class ThemeColorEditorDialog extends DialogComponentProvider {

	private ColorValue startingColorValue;
	private ColorValue currentColorValue;

	private ThemeDialog themeDialog;
	private GhidraColorChooser colorChooser;
	private ChangeListener colorChangeListener = e -> colorChanged();

	public ThemeColorEditorDialog(ThemeDialog themeDialog) {
		super("Theme Color Editor", false);
		this.themeDialog = themeDialog;
		addWorkPanel(buildColorPanel());
		addOKButton();
		addCancelButton();
	}

	public void editColor(ColorValue colorValue) {
		this.startingColorValue = colorValue;
		this.currentColorValue = colorValue;

		setTitle("Edit Color For: " + colorValue.getId());
		Color color = Gui.getRawColor(startingColorValue.getId());
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
		currentColorValue = null;
		startingColorValue = null;
		close();
		themeDialog.colorEditorClosed();
	}

	@Override
	protected void cancelCallback() {
		restoreOriginalColor();
		currentColorValue = null;
		startingColorValue = null;
		close();
		themeDialog.colorEditorClosed();
	}

	private void restoreOriginalColor() {
		themeDialog.colorChanged(currentColorValue, startingColorValue);
		currentColorValue = startingColorValue;
	}

	private void colorChanged() {
		Color newColor = colorChooser.getColor();
		ColorValue newColorValue = new ColorValue(startingColorValue.getId(), newColor);
		themeDialog.colorChanged(currentColorValue, newColorValue);
		currentColorValue = newColorValue;
	}

}
