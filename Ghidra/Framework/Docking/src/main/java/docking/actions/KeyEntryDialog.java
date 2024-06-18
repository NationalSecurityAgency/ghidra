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
package docking.actions;

import java.awt.*;
import java.util.Objects;

import javax.swing.*;
import javax.swing.text.*;

import docking.*;
import docking.action.DockingActionIf;
import docking.action.KeyBindingData;
import docking.tool.ToolConstants;
import docking.widgets.label.GIconLabel;
import generic.theme.GAttributes;
import generic.theme.GThemeDefaults.Colors.Messages;
import generic.theme.Gui;
import ghidra.util.HelpLocation;
import resources.Icons;

/**
 * Dialog to set the key binding on an action. It is triggered by the F4 key.
 */
public class KeyEntryDialog extends DialogComponentProvider {

	private KeyBindings keyBindings;
	private ToolActions toolActions;
	private DockingActionIf action;

	private JPanel defaultPanel;
	private KeyEntryTextField keyEntryField;
	private JTextPane collisionPane;
	private StyledDocument doc;

	private SimpleAttributeSet textAttrs;
	private Color bgColor;

	public KeyEntryDialog(Tool tool, DockingActionIf action) {
		super("Set Key Binding for " + action.getName(), true);
		this.action = action;
		this.toolActions = (ToolActions) tool.getToolActions();

		this.keyBindings = new KeyBindings(tool);

		setUpAttributes();
		createPanel();
		KeyStroke keyBinding = action.getKeyBinding();
		updateCollisionPane(keyBinding);
		setHelpLocation(new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "KeyBindingPopup"));
	}

	private void createPanel() {
		addWorkPanel(buildMainPanel());
		addOKButton();
		addCancelButton();
	}

	private JPanel buildMainPanel() {

		defaultPanel = new JPanel(new BorderLayout());
		defaultPanel.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 5));

		JLabel imageLabel = new GIconLabel(Icons.INFO_ICON);
		bgColor = imageLabel.getBackground();
		JTextPane pane = new JTextPane();
		pane.setBorder(BorderFactory.createEmptyBorder(0, 5, 2, 5));
		pane.setBackground(bgColor);
		pane.setEditable(false);

		StyledDocument document = pane.getStyledDocument();
		try {
			document.insertString(0, "To add or change a key binding, type any key combination.\n" +
				"To remove a key binding, press <Enter> or <Backspace>.", null);
		}
		catch (BadLocationException e1) {
			// shouldn't be possible
		}

		JPanel labelPanel = new JPanel();
		labelPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		BoxLayout bl = new BoxLayout(labelPanel, BoxLayout.X_AXIS);
		labelPanel.setLayout(bl);
		labelPanel.add(Box.createHorizontalStrut(5));
		labelPanel.add(imageLabel);
		labelPanel.add(Box.createHorizontalStrut(10));
		labelPanel.add(pane);
		labelPanel.add(Box.createHorizontalStrut(5));

		keyEntryField = new KeyEntryTextField(20, keyStroke -> {
			okButton.setEnabled(true);
			updateCollisionPane(keyStroke);
		});

		defaultPanel.add(labelPanel, BorderLayout.NORTH);
		defaultPanel.setBorder(BorderFactory.createLoweredBevelBorder());
		JPanel p = new JPanel(new FlowLayout(FlowLayout.CENTER));
		p.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));
		p.add(keyEntryField);
		KeyStroke keyBinding = action.getKeyBinding();
		if (keyBinding != null) {
			keyEntryField.setText(KeyBindingUtils.parseKeyStroke(keyBinding));
		}
		setFocusComponent(keyEntryField);
		defaultPanel.add(p, BorderLayout.CENTER);

		JPanel mainPanel = new JPanel(new BorderLayout());
		mainPanel.add(defaultPanel, BorderLayout.NORTH);
		mainPanel.add(createCollisionPanel(), BorderLayout.CENTER);
		return mainPanel;
	}

	private JPanel createCollisionPanel() {
		JPanel parent = new JPanel(new BorderLayout());

		JPanel noWrapPanel = new JPanel(new BorderLayout());
		collisionPane = new JTextPane();
		collisionPane.setEditable(false);
		collisionPane.setBackground(bgColor);
		doc = collisionPane.getStyledDocument();
		noWrapPanel.add(collisionPane, BorderLayout.CENTER);
		JScrollPane sp = new JScrollPane(noWrapPanel);
		Dimension d = defaultPanel.getPreferredSize();
		sp.setPreferredSize(new Dimension(sp.getPreferredSize().width, d.height));
		parent.add(sp, BorderLayout.CENTER);
		return parent;
	}

	/**
	 * Sets the given keystroke value into the text field of this dialog
	 * @param ks the keystroke to set
	 */
	public void setKeyStroke(KeyStroke ks) {
		keyEntryField.setKeyStroke(ks);
		updateCollisionPane(ks);
	}

	@Override
	protected void cancelCallback() {
		close();
	}

	@Override
	protected void okCallback() {
		KeyStroke newKs = keyEntryField.getKeyStroke();
		String errorMessage = toolActions.validateActionKeyBinding(action, newKs);
		if (errorMessage != null) {
			setStatusText(errorMessage);
			return;
		}

		clearStatusText();

		KeyStroke existingKeyStroke = action.getKeyBinding();
		if (Objects.equals(existingKeyStroke, newKs)) {
			setStatusText("Key binding unchanged");
			return;
		}

		action.setUnvalidatedKeyBindingData(newKs == null ? null : new KeyBindingData(newKs));

		close();
	}

	private void setUpAttributes() {
		Font font = Gui.getFont("font.standard");
		textAttrs = new GAttributes(font, Messages.NORMAL);
	}

	private void updateCollisionPane(KeyStroke ks) {
		clearStatusText();
		collisionPane.setText("");
		if (ks == null) {
			return;
		}

		KeyStroke existingKeyStroke = action.getKeyBinding();
		if (Objects.equals(existingKeyStroke, ks)) {
			setStatusText("Key binding unchanged");
			return;
		}

		String text = keyBindings.getActionsForKeyStrokeText(ks);
		try {
			doc.insertString(0, text, textAttrs);
			collisionPane.setCaretPosition(0);
		}
		catch (BadLocationException e) {
			// shouldn't be possible
		}

	}
}
