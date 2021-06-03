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
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.text.*;

import docking.DialogComponentProvider;
import docking.KeyEntryTextField;
import docking.action.*;
import docking.tool.ToolConstants;
import docking.widgets.label.GIconLabel;
import ghidra.util.HelpLocation;
import ghidra.util.ReservedKeyBindings;
import resources.ResourceManager;

/**
 * Dialog to set the key binding on an action; it is popped up when the F4 key
 * is hit.
 */
public class KeyEntryDialog extends DialogComponentProvider {

	private ToolActions toolActions;
	private DockingActionIf action;
	private JPanel defaultPanel;
	private KeyEntryTextField keyEntryField;
	private JTextPane collisionPane;
	private StyledDocument doc;
	private SimpleAttributeSet tabAttrSet;
	private SimpleAttributeSet textAttrSet;
	private Color bgColor;

	public KeyEntryDialog(DockingActionIf action, ToolActions actions) {
		super("Set Key Binding for " + action.getName(), true);
		this.action = action;
		this.toolActions = actions;
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

		JLabel imageLabel = new GIconLabel(ResourceManager.loadImage("images/information.png"));
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
	}

	@Override
	protected void cancelCallback() {
		close();
	}

	@Override
	protected void okCallback() {
		KeyStroke newKeyStroke = keyEntryField.getKeyStroke();
		if (newKeyStroke != null && ReservedKeyBindings.isReservedKeystroke(newKeyStroke)) {
			setStatusText(keyEntryField.getText() + " is a reserved keystroke");
			return;
		}

		clearStatusText();

		KeyStroke existingKeyStroke = action.getKeyBinding();
		if (Objects.equals(existingKeyStroke, newKeyStroke)) {
			setStatusText("Key binding unchanged");
			return;
		}

		action.setUnvalidatedKeyBindingData(new KeyBindingData(newKeyStroke));

		close();
	}

	private void setUpAttributes() {
		textAttrSet = new SimpleAttributeSet();
		textAttrSet.addAttribute(StyleConstants.FontFamily, "Tahoma");
		textAttrSet.addAttribute(StyleConstants.FontSize, Integer.valueOf(11));
		textAttrSet.addAttribute(StyleConstants.Foreground, Color.BLUE);

		tabAttrSet = new SimpleAttributeSet();
		TabStop tabs = new TabStop(20, StyleConstants.ALIGN_LEFT, TabStop.LEAD_NONE);
		StyleConstants.setTabSet(tabAttrSet, new TabSet(new TabStop[] { tabs }));
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

		List<DockingActionIf> list = getManagedActionsForKeyStroke(ks);
		if (list.size() == 0) {
			return;
		}

		list.sort((a1, a2) -> {
			String s1 = a1.getName() + a1.getOwnerDescription();
			String s2 = a2.getName() + a2.getOwnerDescription();
			return s1.compareToIgnoreCase(s2);
		});

		String ksName = KeyBindingUtils.parseKeyStroke(ks);
		try {
			doc.insertString(0, "Actions mapped to " + ksName + "\n\n", textAttrSet);
			for (int i = 0; i < list.size(); i++) {
				DockingActionIf a = list.get(i);

				String collisionStr = "\t" + a.getName() + " (" + a.getOwnerDescription() + ")\n";
				int offset = doc.getLength();
				doc.insertString(offset, collisionStr, textAttrSet);
				doc.setParagraphAttributes(offset, 1, tabAttrSet, false);
			}
			collisionPane.setCaretPosition(0);
		}
		catch (BadLocationException e) {
			// shouldn't be possible
		}

	}

	private List<DockingActionIf> getManagedActionsForKeyStroke(KeyStroke keyStroke) {
		MultipleKeyAction multiAction = getMultipleKeyAction(keyStroke);
		if (multiAction == null) {
			return Collections.emptyList();
		}

		List<DockingActionIf> list = multiAction.getActions();
		Map<String, DockingActionIf> nameMap = new HashMap<>(list.size());

		// the list may have multiple matches for a single owner, which we do not want (see
		// SharedStubKeyBindingAction)
		for (DockingActionIf dockableAction : list) {
			if (shouldAddAction(dockableAction)) {
				// this overwrites same named actions
				nameMap.put(dockableAction.getName() + dockableAction.getOwner(), dockableAction);
			}
		}

		return new ArrayList<>(nameMap.values());
	}

	private MultipleKeyAction getMultipleKeyAction(KeyStroke ks) {
		Action keyAction = toolActions.getAction(ks);
		if (keyAction instanceof MultipleKeyAction) {
			return (MultipleKeyAction) keyAction;
		}
		return null;
	}

	private boolean shouldAddAction(DockingActionIf dockableAction) {
		return dockableAction.getKeyBindingType().isManaged();
	}
}
