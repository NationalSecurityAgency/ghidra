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
package ghidra.graph.support;

import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.beans.PropertyChangeListener;

import javax.swing.*;

import docking.GenericHeader;
import ghidra.graph.graphs.AbstractTestVertex;

/**
 * A test vertex that allows the user t enter text and has a header for dragging.
 */
public class TextAreaTestVertex extends AbstractTestVertex {

	private JPanel mainPanel = new JPanel(new BorderLayout());
	private JTextArea textArea = new JTextArea();
	private GenericHeader genericHeader;

	public TextAreaTestVertex(String name) {
		super(name);

		textArea.setText(name);
		textArea.setPreferredSize(new Dimension(200, 50));
		textArea.setBackground(Color.YELLOW.darker());
		textArea.setCaretColor(Color.PINK);
		textArea.setBorder(BorderFactory.createRaisedBevelBorder());
		textArea.setLineWrap(true);

		PropertyChangeListener[] listeners = textArea.getPropertyChangeListeners();
		for (PropertyChangeListener l : listeners) {

			// the AquaCaret does not remove itself as a listener
			if (l.getClass().getSimpleName().contains("AquaCaret")) {
				textArea.removePropertyChangeListener(l);
			}
		}

		textArea.setVisible(true);
		textArea.getCaret().setSelectionVisible(true);

		genericHeader = new GenericHeader() {
			// overridden to prevent excessive title bar width for long symbol names
			@Override
			public Dimension getPreferredSize() {
				Dimension preferredSize = super.getPreferredSize();
				int maxWidth = textArea.getPreferredSize().width;
				if (maxWidth <= 0) {
					return preferredSize;
				}

				int toolBarWidth = getToolBarWidth();
				int minimumGrabArea = 60;
				int minimumWidth = minimumGrabArea + toolBarWidth;

				maxWidth = Math.max(maxWidth, minimumWidth);
				preferredSize.width = Math.max(maxWidth, 170);
				return preferredSize;
			}
		};
		genericHeader.setComponent(textArea);
		genericHeader.setTitle(name);
		genericHeader.setNoWrapToolbar(true);

		mainPanel.addKeyListener(new KeyListener() {

			@Override
			public void keyTyped(KeyEvent e) {
				KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
				kfm.redispatchEvent(textArea, e);
			}

			@Override
			public void keyReleased(KeyEvent e) {
				KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
				kfm.redispatchEvent(textArea, e);
			}

			@Override
			public void keyPressed(KeyEvent e) {
				KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
				kfm.redispatchEvent(textArea, e);
			}
		});

		mainPanel.add(genericHeader, BorderLayout.NORTH);
		mainPanel.add(textArea, BorderLayout.CENTER);
	}

	@Override
	public boolean isGrabbable(Component c) {
		if (c == textArea) {
			return false;
		}
		return true;
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	public JTextArea getTextArea() {
		return textArea;
	}

	public String getText() {
		return textArea.getText();
	}

	@Override
	public void setFocused(boolean focused) {
		super.setFocused(focused);
		textArea.getCaret().setVisible(focused);
	}

	@Override
	public void setSelected(boolean selected) {
		super.setSelected(selected);
		genericHeader.setSelected(selected);
	}

	@Override
	public void dispose() {
		genericHeader.dispose();
	}
}
