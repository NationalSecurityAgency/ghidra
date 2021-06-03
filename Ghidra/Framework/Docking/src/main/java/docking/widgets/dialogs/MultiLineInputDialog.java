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
package docking.widgets.dialogs;

import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingUtils;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;

public class MultiLineInputDialog extends DialogComponentProvider {

	private static final KeyStroke SUBMIT_KEYSTROKE =
		KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, DockingUtils.CONTROL_KEY_MODIFIER_MASK);

	private boolean isCanceled;
	private JTextArea inputTextArea;

	public MultiLineInputDialog(String title, String messageText, String initialValue, Icon icon) {
		super(title, true);

		addWorkPanel(build(messageText, icon, initialValue));

		setFocusComponent(inputTextArea);

		setTransient(true);
		addOKButton();
		addCancelButton();
	}

	private JPanel build(String messageText, Icon icon, String initialValue) {

		JPanel dataPanel = new JPanel(new BorderLayout());
		inputTextArea = new JTextArea(10, 50);

		DockingUtils.installUndoRedo(inputTextArea);

		inputTextArea.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				KeyStroke keyStrokeForEvent = KeyStroke.getKeyStrokeForEvent(e);
				if (SUBMIT_KEYSTROKE.equals(keyStrokeForEvent)) {
					okCallback();
				}
			}
		});

		inputTextArea.setLineWrap(true);
		inputTextArea.setWrapStyleWord(true);
		if (initialValue != null) {
			inputTextArea.setText(initialValue);
		}
		inputTextArea.selectAll();

		JLabel messageLabel = new GDLabel();
		messageLabel.setText(messageText);
		messageLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));

		String metaKeyText = "Control";
		OperatingSystem OS = Platform.CURRENT_PLATFORM.getOperatingSystem();
		if (OS == OperatingSystem.MAC_OS_X) {
			metaKeyText = "Command";
		}
		JLabel hintLabel = new GLabel("(" + metaKeyText + "-Enter to accept)");
		hintLabel.setHorizontalAlignment(SwingConstants.CENTER);
		Font font = hintLabel.getFont();
		Font smallerFont = font.deriveFont(12F);
		Font smallItalicFont = smallerFont.deriveFont(Font.ITALIC);
		hintLabel.setFont(smallItalicFont);
		hintLabel.setForeground(Color.LIGHT_GRAY);

		dataPanel.add(messageLabel, BorderLayout.NORTH);
		dataPanel.add(new JScrollPane(inputTextArea), BorderLayout.CENTER);
		dataPanel.add(hintLabel, BorderLayout.SOUTH);

		JLabel iconLabel = new GDLabel();
		iconLabel.setIcon(icon);
		iconLabel.setVerticalAlignment(SwingConstants.TOP);

		JPanel separatorPanel = new JPanel();
		separatorPanel.setPreferredSize(new Dimension(15, 1));

		JPanel iconPanel = new JPanel(new BorderLayout());
		iconPanel.add(iconLabel, BorderLayout.CENTER);
		iconPanel.add(separatorPanel, BorderLayout.EAST);

		JPanel workPanel = new JPanel(new BorderLayout());
		workPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		workPanel.add(iconPanel, BorderLayout.WEST);
		workPanel.add(dataPanel, BorderLayout.CENTER);

		return workPanel;
	}

	@Override
	protected void okCallback() {
		isCanceled = false;
		close();
	}

	@Override
	protected void cancelCallback() {
		isCanceled = true;
		close();
	}

	/**
	 * Returns if this dialog is canceled.
	 */
	public boolean isCanceled() {
		return isCanceled;
	}

	/**
	 * return the value of the first combo box
	 */
	public String getValue() {
		if (isCanceled) {
			return null;
		}
		return inputTextArea.getText();
	}
//
//	public static void main(String[] args) {
//
//		Icon icon = OptionDialog.getIconForMessageType(OptionDialog.QUESTION_MESSAGE);
//		MultiLineInputDialog dialog =
//			new MultiLineInputDialog("Test", "Enter Text", "Default Value", icon);
//		DockingDialog dockingDialog = new DockingDialog(dialog, null);
//		dockingDialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
//		dockingDialog.setVisible(true);
//	}
}
