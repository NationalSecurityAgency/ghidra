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

import java.awt.*;
import java.beans.PropertyEditorSupport;
import java.util.Objects;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;

/**
 * Font property editor that is a bit unusual in that its custom component is a button that when 
 * pushed, pops up a dialog for editing the color. Use {@link FontPropertyEditor} for a more
 * traditional property editor that returns a direct color editing component.
 */

public class FontEditor extends PropertyEditorSupport {
	private JButton previewButton;
	private FontPropertyEditor fontPropertyEditor;

	public FontEditor() {
		previewButton = new JButton(FontPropertyEditor.SAMPLE_STRING);
		previewButton.addActionListener(e -> buttonPushed());
		fontPropertyEditor = new FontPropertyEditor();
		fontPropertyEditor.addPropertyChangeListener(ev -> fontChanged());
	}

	private void buttonPushed() {
		showDialog();
		previewButton.setFont((Font) getValue());
	}

	/**
	 * Convenience method for directly showing a dialog for editing fonts
	 */
	public void showDialog() {
		EditorDialogProvider provider = new EditorDialogProvider();
		DockingWindowManager.showDialog(previewButton, provider);
		previewButton.repaint();
	}

	@Override
	public void setValue(Object o) {
		if (Objects.equals(o, getValue())) {
			return;
		}
		Font font = (Font) o;
		previewButton.setFont(font);
		fontPropertyEditor.setValue(font);
		super.setValue(font);
	}

	@Override
	public boolean supportsCustomEditor() {
		return true;
	}

	@Override
	public Component getCustomEditor() {
		return previewButton;
	}

	private void fontChanged() {
		Font font = (Font) fontPropertyEditor.getValue();
		setValue(font);
	}

	class EditorDialogProvider extends DialogComponentProvider {
		private Font originalFont = (Font) getValue();

		EditorDialogProvider() {
			super("Font Editor", true);
			addWorkPanel(buildWorkPanel());
			addOKButton();
			addCancelButton();
		}

		private JComponent buildWorkPanel() {
			JPanel panel = new JPanel(new BorderLayout());
			panel.add(fontPropertyEditor.getCustomEditor());
			return panel;
		}

		@Override
		protected void okCallback() {
			close();
		}

		@Override
		protected void cancelCallback() {
			setValue(originalFont);
			close();
		}
	}
}
