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

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import generic.theme.GThemeDefaults.Colors;

/**
 * A re-usable floating text edit window.
 */
public class EditWindow extends JWindow {

	private DockingWindowManager mgr;
	private JTextField textField;
	private boolean active = false;
	private Component comp;
	private Rectangle rect;
	private EditListener listener;

	private AssociatedComponentListener compListener = new AssociatedComponentListener();

	EditWindow(DockingWindowManager mgr) {
		super(mgr.getRootFrame());
		this.mgr = mgr;
		create();
	}

	Component getAssociatedComponent() {
		return comp;
	}

	@Override
	public boolean isActive() {
		return active;
	}

	@Override
	public void setVisible(boolean state) {

		active = state;
		super.setVisible(state);

		if (!state) {
			if (comp != null) {
				comp.removeComponentListener(compListener);
				if (comp instanceof JTabbedPane) {
					((JTabbedPane) comp).removeChangeListener(compListener);
				}
				Frame frame = mgr.getRootFrame();
				frame.removeComponentListener(compListener);
				comp = null;
				listener = null;
			}
		}
	}

	void close() {
		setVisible(false);
		dispose();
	}

	void show(String defaultText, Component c, Rectangle r, EditListener editListener) {

		if (comp != null) {
			setVisible(false);
		}

		if (c == null || !c.isVisible()) {
			return;
		}

		this.comp = c;
		this.rect = r;
		this.listener = editListener;

		comp.addComponentListener(compListener);

		if (comp instanceof JTabbedPane) {
			((JTabbedPane) comp).addChangeListener(compListener);
		}

		Frame frame = mgr.getRootFrame();
		frame.addComponentListener(compListener);

		setLocation();

		textField.setText(defaultText != null ? defaultText : "");
		Dimension d = textField.getPreferredSize();
		textField.setPreferredSize(new Dimension(rect.width, d.height));
		pack();

		setVisible(true);

		toFront();
		textField.requestFocus();
		textField.selectAll();
	}

	private void setLocation() {
		Point p = comp.getLocationOnScreen();
		setLocation(p.x + rect.x + 3, p.y + rect.y);
	}

	private void create() {
		textField = new JTextField(" ");
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBackground(Colors.BACKGROUND);
		panel.add(textField, BorderLayout.CENTER);

		textField.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
					close();
				}
			}
		});
		textField.addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				if (!e.isTemporary()) {
					close();
				}
			}
		});
		textField.addActionListener(e -> {
			if (listener != null) {
				String text = textField.getText();
				EditListener l = listener;
				close();
				l.editCompleted(text);
			}
		});

		getContentPane().add(panel, BorderLayout.CENTER);
	}

	private class AssociatedComponentListener implements ComponentListener, ChangeListener {

		@Override
		public void componentHidden(ComponentEvent e) {
			close();
		}

		@Override
		public void componentResized(ComponentEvent e) {
			close();
		}

		@Override
		public void componentShown(ComponentEvent e) {
			// stub
		}

		@Override
		public void componentMoved(ComponentEvent e) {
			if (comp != null && comp.isVisible()) {
				setLocation();
			}
		}

		@Override
		public void stateChanged(ChangeEvent e) {
			close();
		}
	}

}
