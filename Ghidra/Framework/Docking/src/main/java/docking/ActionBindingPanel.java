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

import java.util.Objects;

import javax.swing.*;

import docking.widgets.EmptyBorderButton;
import docking.widgets.label.GLabel;
import generic.theme.GIcon;
import gui.event.MouseBinding;

/**
 * A panel that displays inputs for key strokes and mouse bindings.
 */
public class ActionBindingPanel extends JPanel {

	private static final String DISABLED_HINT = "Select an action";

	private KeyEntryPanel keyEntryPanel;
	private MouseEntryTextField mouseEntryField;

	private DockingActionInputBindingListener listener;

	public ActionBindingPanel(DockingActionInputBindingListener listener) {

		this.listener = Objects.requireNonNull(listener);
		build();
	}

	private void build() {

		setLayout(new BoxLayout(this, BoxLayout.LINE_AXIS));

		keyEntryPanel = new KeyEntryPanel(20, ks -> listener.keyStrokeChanged(ks));
		keyEntryPanel.setDisabledHint(DISABLED_HINT);
		keyEntryPanel.setEnabled(false); // enabled on action selection

		mouseEntryField = new MouseEntryTextField(20, mb -> listener.mouseBindingChanged(mb));
		mouseEntryField.setDisabledHint(DISABLED_HINT);

		JButton clearMouseButton = new EmptyBorderButton(new GIcon("icon.text.field.clear"));
		clearMouseButton.setName("Clear Mouse Binding");
		clearMouseButton.addActionListener(e -> mouseEntryField.clearMouseBinding());

		GLabel keyBindingLabel = new GLabel("Key Binding: ");
		JTextField tf = keyEntryPanel.getTextField();
		keyBindingLabel.setLabelFor(tf);

		GLabel mouseBindingLabel = new GLabel("Mouse Binding: ");
		mouseBindingLabel.setLabelFor(mouseBindingLabel);

		add(keyBindingLabel);
		add(keyEntryPanel);
		add(Box.createHorizontalStrut(30));
		add(mouseBindingLabel);
		add(mouseEntryField);
		add(Box.createHorizontalStrut(2));
		add(clearMouseButton);
	}

	public void setKeyBindingData(KeyStroke ks, MouseBinding mb) {

		keyEntryPanel.setKeyStroke(ks);
		mouseEntryField.setMouseBinding(mb);
	}

	@Override
	public void setEnabled(boolean enabled) {
		keyEntryPanel.clearField();
		mouseEntryField.clearField();

		keyEntryPanel.setEnabled(enabled);
		mouseEntryField.setEnabled(enabled);
	}

	public void clearKeyStroke() {
		keyEntryPanel.clearField();
	}

	public KeyStroke getKeyStroke() {
		return keyEntryPanel.getKeyStroke();
	}

	public MouseBinding getMouseBinding() {
		return mouseEntryField.getMouseBinding();
	}

	public void clearMouseBinding() {
		mouseEntryField.clearMouseBinding();
	}
}
