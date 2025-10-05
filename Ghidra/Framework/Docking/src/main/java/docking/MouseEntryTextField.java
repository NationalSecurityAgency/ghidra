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

import java.awt.event.*;
import java.awt.event.FocusEvent.Cause;
import java.util.Objects;
import java.util.function.Consumer;

import docking.widgets.textfield.HintTextField;
import gui.event.MouseBinding;

public class MouseEntryTextField extends HintTextField {

	private static final String HINT = "Press a mouse button";
	private String disabledHint = HINT;

	private MouseBinding mouseBinding;
	private Consumer<MouseBinding> listener;

	public MouseEntryTextField(int columns, Consumer<MouseBinding> listener) {
		super(HINT);
		setColumns(columns);
		setName("Mouse Entry Text Field");
		getAccessibleContext().setAccessibleName(getName());
		this.listener = Objects.requireNonNull(listener);

		// remove the default mouse listeners to prevent pasting
		MouseListener[] oldListeners1 = getMouseListeners();
		for (MouseListener l : oldListeners1) {
			removeMouseListener(l);
		}

		addMouseListener(new MyMouseListener());
		addKeyListener(new MyKeyListener());
	}

	@Override
	public void setEnabled(boolean enabled) {
		setHint(enabled ? HINT : disabledHint);
		super.setEnabled(enabled);
	}

	/**
	 * Sets the hint text that will be displayed when this field is disabled
	 * @param disabledHint the hint text
	 */
	public void setDisabledHint(String disabledHint) {
		this.disabledHint = Objects.requireNonNull(disabledHint);
	}

	public MouseBinding getMouseBinding() {
		return mouseBinding;
	}

	public void setMouseBinding(MouseBinding mb) {
		processMouseBinding(mb, false);
	}

	/**
	 * Clears the state of this class, but does not notify listeners.  This allows clients to 
	 * control the state of the field without having a callback change the client state.
	 */
	public void clearField() {
		processMouseBinding(null, false);
	}

	/**
	 * Clears the state of this class and notifies this client.  This effectively allows for the
	 * programmatic setting of the mouse binding in use to be null, or in the 'no mouse binding set'
	 * state.
	 */
	public void clearMouseBinding() {
		processMouseBinding(null, true);
	}

	private void processMouseBinding(MouseBinding mb, boolean notify) {

		this.mouseBinding = mb;
		if (mouseBinding == null) {
			setText("");
		}
		else {
			setText(mouseBinding.getDisplayText());
		}

		if (notify) {
			listener.accept(mb);
		}
	}

	private class MyMouseListener extends MouseAdapter {

		@Override
		public void mousePressed(MouseEvent e) {
			if (!MouseEntryTextField.this.isEnabled()) {
				return;
			}

			requestFocusInWindow(Cause.MOUSE_EVENT);

			int modifiersEx = e.getModifiersEx();
			int button = e.getButton();

			int buttonDownMask = InputEvent.getMaskForButton(button);
			if (button == MouseEvent.BUTTON1 && buttonDownMask == modifiersEx) {
				// Don't allow the user to bind an unmodified left-click, as odd behavior can ensue.
				// We can revisit this if a valid use case is found.
				e.consume();
				return;
			}

			processMouseBinding(new MouseBinding(button, modifiersEx), true);

			e.consume();
		}

		@Override
		public void mouseReleased(MouseEvent e) {
			e.consume();
		}

		@Override
		public void mouseClicked(MouseEvent e) {
			e.consume();
		}
	}

	private class MyKeyListener implements KeyListener {

		@Override
		public void keyTyped(KeyEvent e) {
			e.consume();
		}

		@Override
		public void keyReleased(KeyEvent e) {
			e.consume();
		}

		@Override
		public void keyPressed(KeyEvent e) {
			int keyCode = e.getKeyCode();
			if (isClearKey(keyCode)) {
				processMouseBinding(null, true);
			}
			e.consume();
		}

		private boolean isClearKey(int keyCode) {
			return keyCode == KeyEvent.VK_BACK_SPACE || keyCode == KeyEvent.VK_ENTER;
		}

	}

}
