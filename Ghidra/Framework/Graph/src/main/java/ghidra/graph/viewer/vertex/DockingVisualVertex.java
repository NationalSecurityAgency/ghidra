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
package ghidra.graph.viewer.vertex;

import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.beans.PropertyChangeListener;

import javax.swing.*;

import docking.GenericHeader;
import ghidra.graph.viewer.VisualVertex;
import ghidra.util.MathUtilities;

/**
 * A {@link VisualVertex} implementation that provides a component with a docking header that 
 * is clickable.
 */
public class DockingVisualVertex extends AbstractVisualVertex {

	private JPanel mainPanel = new JPanel(new BorderLayout());
	private JTextArea textArea;
	private GenericHeader genericHeader;
	private String name;

	private int maxWidth = 200; // something reasonable

	public DockingVisualVertex(String name) {
		this.name = name;

		textArea = new JTextArea() {
			// overridden to cap the width
			@Override
			public Dimension getPreferredSize() {
				Dimension preferredSize = super.getPreferredSize();
				int width = preferredSize.width;
				preferredSize.width = MathUtilities.clamp(width, width, maxWidth);
				return preferredSize;
			}
		};
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
			// overridden to prevent excessive title bar width for long names
			@Override
			public Dimension getPreferredSize() {
				Dimension preferredSize = super.getPreferredSize();
				int width = textArea.getPreferredSize().width;
				int preferredWidth = MathUtilities.clamp(width, width, maxWidth);
				if (preferredWidth <= 0) {
					return preferredSize;
				}

				int toolBarWidth = getToolBarWidth();
				int minimumGrabArea = 60;
				int minimumWidth = minimumGrabArea + toolBarWidth;
				preferredSize.width = MathUtilities.clamp(preferredWidth, minimumWidth, maxWidth);
				return preferredSize;
			}
		};
		genericHeader.setComponent(textArea);
		genericHeader.setTitle(name);
		genericHeader.setNoWrapToolbar(true);

		mainPanel.addKeyListener(new KeyListener() {

			@Override
			public void keyTyped(KeyEvent e) {
				if (!textArea.isEditable()) {
					return;
				}

				KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
				kfm.redispatchEvent(textArea, e);
				e.consume(); // consume all events; signal that our text area will handle them
			}

			@Override
			public void keyReleased(KeyEvent e) {

				if (!textArea.isEditable()) {
					return;
				}

				KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
				kfm.redispatchEvent(textArea, e);
				e.consume(); // consume all events; signal that our text area will handle them
			}

			@Override
			public void keyPressed(KeyEvent e) {

				if (!textArea.isEditable()) {
					return;
				}

				KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
				kfm.redispatchEvent(textArea, e);
				e.consume(); // consume all events; signal that our text area will handle them
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

	public String getName() {
		return name;
	}

	public void setMaxWidth(int width) {
		this.maxWidth = width;
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

	@Override
	public String toString() {
		return name;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		DockingVisualVertex other = (DockingVisualVertex) obj;
		if (name == null) {
			if (other.name != null) {
				return false;
			}
		}
		else if (!name.equals(other.name)) {
			return false;
		}
		return true;
	}

}
