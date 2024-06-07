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

import java.awt.BorderLayout;
import java.util.Objects;

import javax.swing.*;

import docking.widgets.checkbox.GCheckBox;
import gui.event.MouseBinding;

/**
 * A panel that displays inputs for key strokes and mouse bindings.
 */
public class ActionBindingPanel extends JPanel {

	private static final String DISABLED_HINT = "Select an action";

	private KeyEntryTextField keyEntryField;
	private JCheckBox useMouseBindingCheckBox;
	private MouseEntryTextField mouseEntryField;
	private JPanel textFieldPanel;

	private DockingActionInputBindingListener listener;

	public ActionBindingPanel(DockingActionInputBindingListener listener) {

		this.listener = Objects.requireNonNull(listener);
		build();
	}

	private void build() {

		setLayout(new BoxLayout(this, BoxLayout.LINE_AXIS));

		textFieldPanel = new JPanel(new BorderLayout());

		keyEntryField = new KeyEntryTextField(20, ks -> listener.keyStrokeChanged(ks));
		keyEntryField.setDisabledHint(DISABLED_HINT);
		keyEntryField.setEnabled(false); // enabled on action selection
		mouseEntryField = new MouseEntryTextField(20, mb -> listener.mouseBindingChanged(mb));
		mouseEntryField.setDisabledHint(DISABLED_HINT);
		mouseEntryField.setEnabled(false); // enabled on action selection

		textFieldPanel.add(keyEntryField, BorderLayout.NORTH);

		String checkBoxText = "Enter Mouse Binding";
		useMouseBindingCheckBox = new GCheckBox(checkBoxText);
		useMouseBindingCheckBox
				.setToolTipText("When checked, the text field accepts mouse buttons");
		useMouseBindingCheckBox.setName(checkBoxText);
		useMouseBindingCheckBox.addItemListener(e -> updateTextField());

		add(textFieldPanel);
		add(Box.createHorizontalStrut(5));
		add(useMouseBindingCheckBox);
	}

	private void updateTextField() {

		if (useMouseBindingCheckBox.isSelected()) {
			textFieldPanel.remove(keyEntryField);
			textFieldPanel.add(mouseEntryField, BorderLayout.NORTH);
		}
		else {
			textFieldPanel.remove(mouseEntryField);
			textFieldPanel.add(keyEntryField, BorderLayout.NORTH);
		}

		validate();
		repaint();
	}

	public void setKeyBindingData(KeyStroke ks, MouseBinding mb) {

		keyEntryField.setKeyStroke(ks);
		mouseEntryField.setMouseBinding(mb);
	}

	@Override
	public void setEnabled(boolean enabled) {
		keyEntryField.clearField();
		mouseEntryField.clearField();

		keyEntryField.setEnabled(enabled);
		mouseEntryField.setEnabled(enabled);
	}

	public void clearKeyStroke() {
		keyEntryField.clearField();
	}

	public KeyStroke getKeyStroke() {
		return keyEntryField.getKeyStroke();
	}

	public MouseBinding getMouseBinding() {
		return mouseEntryField.getMouseBinding();
	}

	public void clearMouseBinding() {
		mouseEntryField.clearField();
	}

	public boolean isMouseBinding() {
		return useMouseBindingCheckBox.isSelected();
	}

}
