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
package docking.action;

import java.awt.*;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.text.*;

import docking.*;
import ghidra.util.HelpLocation;
import ghidra.util.ReservedKeyBindings;
import resources.ResourceManager;

/**
 * Dialog to set the key binding on an action; it is popped up when the F4 key
 * is hit.
 */
public class KeyEntryDialog extends DialogComponentProvider {

	private DockingActionManager actionManager;
	private DockingActionIf action;
	private JPanel defaultPanel;
	private KeyEntryTextField keyEntryField;
	private JTextPane collisionPane;
	private StyledDocument doc;
	private SimpleAttributeSet tabAttrSet;
	private SimpleAttributeSet textAttrSet;
	private Color bgColor;

	public KeyEntryDialog(DockingActionIf action, DockingActionManager actionManager) {
		super("Set Key Binding for " + action.getName(), true);
		this.actionManager = actionManager;
		this.action = action;
		setUpAttributes();
		createPanel();
		KeyStroke keyBinding = action.getKeyBinding();
		updateCollisionPane(keyBinding);
		setHelpLocation(new HelpLocation("Tool", "KeyBindingPopup"));
	}

	private void createPanel() {
		addWorkPanel(buildMainPanel());
		addOKButton();
		addCancelButton();
	}

	private JPanel buildMainPanel() {

		defaultPanel = new JPanel(new BorderLayout());
		defaultPanel.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 5));

		Icon icon = ResourceManager.loadImage("images/information.png");
		JLabel imageLabel = new JLabel(icon);
		bgColor = imageLabel.getBackground();
		JTextPane pane = new JTextPane();
		pane.setBorder(BorderFactory.createEmptyBorder(0, 5, 2, 5));
		pane.setBackground(bgColor);
		pane.setEditable(false);

		StyledDocument document = pane.getStyledDocument();
		try {
			document.insertString(0, "To add or change a key binding, type any key combination.\n"
				+ "To remove a key binding, press <Enter> or <Backspace>.", null);
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

		keyEntryField = new KeyEntryTextField(20, new KeyEntryListener() {
			@Override
			public void processEntry(KeyStroke keyStroke) {
				okButton.setEnabled(true);
				updateCollisionPane(keyStroke);
			}
		});

		defaultPanel.add(labelPanel, BorderLayout.NORTH);
		defaultPanel.setBorder(BorderFactory.createLoweredBevelBorder());
		JPanel p = new JPanel(new FlowLayout(FlowLayout.CENTER));
		p.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));
		p.add(keyEntryField);
		KeyStroke keyBinding = action.getKeyBinding();
		if (keyBinding != null) {
			keyEntryField.setText(DockingKeyBindingAction.parseKeyStroke(keyBinding));
		}
		setFocusComponent(keyEntryField);
		defaultPanel.add(p, BorderLayout.CENTER);

		JPanel mainPanel = new JPanel(new BorderLayout());
		mainPanel.add(defaultPanel, BorderLayout.NORTH);
		mainPanel.add(createCollisionPanel(), BorderLayout.CENTER);
		return mainPanel;
	}

	private JPanel createCollisionPanel() {
		JPanel p = new JPanel(new BorderLayout());
		collisionPane = new JTextPane();
		collisionPane.setEditable(false);
		collisionPane.setBackground(bgColor);
		doc = collisionPane.getStyledDocument();
		JScrollPane sp = new JScrollPane(collisionPane);
		Dimension d = defaultPanel.getPreferredSize();
		sp.setPreferredSize(new Dimension(sp.getPreferredSize().width, d.height));
		p.add(sp, BorderLayout.CENTER);
		return p;
	}

	@Override
	protected void cancelCallback() {
		close();
	}

	@Override
	protected void okCallback() {
		KeyStroke keyStroke = keyEntryField.getCurrentKeyStroke();
		if (keyStroke != null && ReservedKeyBindings.isReservedKeystroke(keyStroke)) {
			setStatusText(keyEntryField.getText() + " is a reserved keystroke");
			return;
		}

		clearStatusText();

		List<DockingActionIf> actions =
			actionManager.getAllDockingActionsByFullActionName(action.getFullName());
		for (DockingActionIf element : actions) {
			if (element.isKeyBindingManaged()) {
				element.setUnvalidatedKeyBindingData(new KeyBindingData(keyStroke));
			}
		}

		close();
	}

	private void setUpAttributes() {
		textAttrSet = new SimpleAttributeSet();
		textAttrSet.addAttribute(StyleConstants.FontFamily, "Tahoma");
		textAttrSet.addAttribute(StyleConstants.FontSize, new Integer(11));
		textAttrSet.addAttribute(StyleConstants.Foreground, Color.BLUE);

		tabAttrSet = new SimpleAttributeSet();
		TabStop tabs = new TabStop(20, StyleConstants.ALIGN_LEFT, TabStop.LEAD_NONE);
		StyleConstants.setTabSet(tabAttrSet, new TabSet(new TabStop[] { tabs }));
	}

	private void updateCollisionPane(KeyStroke ks) {
		collisionPane.setText("");
		if (ks == null) {
			return;
		}

		List<DockingActionIf> list = getManagedActionsForKeyStroke(ks);
		if (list.size() == 0) {
			return;
		}

		String ksName = DockingKeyBindingAction.parseKeyStroke(ks);
		try {
			doc.insertString(0, "Actions mapped to " + ksName + "\n\n", textAttrSet);
			for (int i = 0; i < list.size(); i++) {
				DockingActionIf a = list.get(i);

				String collisionStr = "\t" + a.getName() + "  (" + a.getOwner() + ")\n";
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
		Map<String, DockingActionIf> nameMap = new HashMap<String, DockingActionIf>(list.size());

		// the list may have multiple matches for a single owner, which we do not want (see
		// DummyKeyBindingsOptionsAction)
		for (DockingActionIf dockableAction : list) {
			if (shouldAddAction(dockableAction)) {
				// this overwrites same named actions
				nameMap.put(dockableAction.getName() + dockableAction.getOwner(), dockableAction);
			}
		}

		return new ArrayList<DockingActionIf>(nameMap.values());
	}

	/**
	 * Get the multiple key action for the given keystroke.
	 */
	private MultipleKeyAction getMultipleKeyAction(KeyStroke ks) {
		Action keyAction = actionManager.getDockingKeyAction(ks);
		if (keyAction instanceof MultipleKeyAction) {
			return (MultipleKeyAction) keyAction;
		}
		return null;
	}

	private boolean shouldAddAction(DockingActionIf dockableAction) {
		return dockableAction.isKeyBindingManaged();
	}
}
