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

import org.apache.logging.log4j.message.ParameterizedMessage;

import ghidra.util.Msg;
import gui.event.MouseBinding;

/**
 * Allows Ghidra to give preference to its mouse event processing over the default Java mouse event
 * processing.  This class allows us to assign mouse bindings to actions.
 * <p>
 * {@link #install()} must be called in order to install this <code>Singleton</code> into Java's
 * mouse event processing system.
 *
 * @see KeyBindingOverrideKeyEventDispatcher
 */
public class MouseBindingMouseEventDispatcher {

	private static MouseBindingMouseEventDispatcher instance;

	static synchronized void install() {
		if (instance == null) {
			instance = new MouseBindingMouseEventDispatcher();
		}
	}

	/**
	 * Provides the current focus owner.  This allows for dependency injection.
	 */
	private FocusOwnerProvider focusProvider = new DefaultFocusOwnerProvider();

	/**
	 * We use this action as a signal that we intend to process a mouse binding and that no other
	 * Java component should try to handle it.
	 * <p>
	 * This action is one that is triggered by a mouse pressed, but will be processed on a
	 * mouse released.  We do this to ensure that we consume all related mouse events (press and
	 * release) and to be consistent with the {@link KeyBindingOverrideKeyEventDispatcher}.
	 */
	private PendingActionInfo inProgressAction;

	private MouseBindingMouseEventDispatcher() {
		// Note: see the documentation on addAWTEventListener() for limitations of using this
		// listener mechanism
		Toolkit toolkit = Toolkit.getDefaultToolkit();
		AWTEventListener listener = new AWTEventListener() {
			@Override
			public void eventDispatched(AWTEvent event) {
				process((MouseEvent) event);
			}
		};
		toolkit.addAWTEventListener(listener, AWTEvent.MOUSE_EVENT_MASK);
	}

	private void process(MouseEvent e) {

		int id = e.getID();
		if (id == MouseEvent.MOUSE_ENTERED || id == MouseEvent.MOUSE_EXITED) {
			return;
		}

		// always let the application finish processing key events that it started
		if (actionInProgress(e)) {
			return;
		}

		MouseBinding mouseBinding = MouseBinding.getMouseBinding(e);
		DockingMouseBindingAction action = getDockingKeyBindingActionForEvent(mouseBinding);
		Msg.trace(this,
			new ParameterizedMessage("Mouse binding to action: {} to {}", mouseBinding, action));
		if (action == null) {
			return;
		}

		inProgressAction = new PendingActionInfo(action, mouseBinding);
		e.consume();
	}

	/**
	 * Used to clear the flag that signals we are in the middle of processing a Ghidra action.
	 */
	private boolean actionInProgress(MouseEvent e) {

		if (inProgressAction == null) {
			Msg.trace(this, "No mouse binding action in progress");
			return false;
		}

		// Note: mouse buttons can be simultaneously clicked.  This means that the order of pressed
		// and released events may arrive intermixed.  To handle this correctly, we allow the
		// MouseBinding to check for the matching release event.
		MouseBinding mouseBinding = inProgressAction.mouseBinding();
		boolean isMatching = mouseBinding.isMatchingRelease(e);
		Msg.trace(this,
			new ParameterizedMessage(
				"Is release event for in-progress mouse binding action? {} for {}", isMatching,
				inProgressAction.action()));
		if (isMatching) {
			DockingMouseBindingAction action = inProgressAction.action();
			inProgressAction = null;

			String command = null;
			Object source = e.getSource();
			long when = e.getWhen();
			int modifiers = e.getModifiersEx();

			action.actionPerformed(
				new ActionEvent(source, ActionEvent.ACTION_PERFORMED, command, when, modifiers));
		}

		e.consume();
		return true;
	}

	private DockingMouseBindingAction getDockingKeyBindingActionForEvent(
			MouseBinding mouseBinding) {
		DockingWindowManager activeManager = getActiveDockingWindowManager();
		if (activeManager == null) {
			return null;
		}

		DockingMouseBindingAction bindingAction =
			(DockingMouseBindingAction) activeManager.getActionForMouseBinding(mouseBinding);
		return bindingAction;
	}

	private DockingWindowManager getActiveDockingWindowManager() {
		// we need an active window to process events
		Window activeWindow = focusProvider.getActiveWindow();
		if (activeWindow == null) {
			return null;
		}

		DockingWindowManager activeManager = DockingWindowManager.getActiveInstance();
		if (activeManager == null) {
			// this can happen if clients use DockingWindows Look and Feel settings or
			// DockingWindows widgets without using the DockingWindows system (like in tests or
			// in stand-alone, non-Ghidra apps).
			return null;
		}

		DockingWindowManager managingInstance = getDockingWindowManagerForWindow(activeWindow);
		if (managingInstance != null) {
			return managingInstance;
		}

		// this is a case where the current window is unaffiliated with a DockingWindowManager,
		// like a JavaHelp window
		return activeManager;
	}

	private static DockingWindowManager getDockingWindowManagerForWindow(Window activeWindow) {
		DockingWindowManager manager = DockingWindowManager.getInstance(activeWindow);
		if (manager != null) {
			return manager;
		}
		if (activeWindow instanceof DockingDialog) {
			DockingDialog dockingDialog = (DockingDialog) activeWindow;
			return dockingDialog.getOwningWindowManager();
		}
		return null;
	}

	private record PendingActionInfo(DockingMouseBindingAction action, MouseBinding mouseBinding) {
		//
	}
}
