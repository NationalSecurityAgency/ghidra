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

import static docking.KeyBindingPrecedence.*;

import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;

import javax.swing.*;
import javax.swing.text.JTextComponent;

import docking.action.MultipleKeyAction;
import docking.actions.KeyBindingUtils;
import docking.menu.keys.MenuKeyProcessor;
import ghidra.util.bean.GGlassPane;
import ghidra.util.exception.AssertException;

/**
 * Allows Ghidra to give preference to its key event processing over the default Java key event
 * processing.  See {@link #dispatchKeyEvent(KeyEvent)} for a more detailed explanation of how
 * Ghidra processes key events.
 * <p>
 * {@link #install()} must be called in order to install this <code>Singleton</code> into Java's
 * key event processing system.
 */
public class KeyBindingOverrideKeyEventDispatcher implements KeyEventDispatcher {

	private static KeyBindingOverrideKeyEventDispatcher instance = null;

	/**
	 * We use this action as a signal that we intend to process a key
	 * binding and that no other Java component should try to handle it (sometimes Java processes
	 * bindings on key typed, after we have processed a binding on key pressed, which is not
	 * what we want).
	 * <p>
	 * This action is one that is triggered by a key pressed, but will be processed on a
	 * key released.  We need to do this for because on some systems, when we perform the
	 * action on a key pressed, we do not get the follow-on key events, which we need to reset
	 * our state (SCR 7040).
	 * <p>
	 * <b>Posterity Note:</b> While debugging we will not get a KeyEvent.KEY_RELEASED event if
	 * the focus changes from the application to the debugger tool.
	 */
	private DockingKeyBindingAction inProgressAction;

	/**
	 * Provides the current focus owner.  This allows for dependency injection.
	 */
	private FocusOwnerProvider focusProvider = new DefaultFocusOwnerProvider();

	/**
	 * Installs this key event dispatcher into Java's key event processing system.  Calling this
	 * method more than once has no effect.
	 */
	static void install() {
		if (instance == null) {
			instance = new KeyBindingOverrideKeyEventDispatcher();
			KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
			kfm.addKeyEventDispatcher(instance);
		}
	}

	/**
	 * Overridden to change the Java's key event processing to insert Ghidra's top level tool
	 * key bindings into the event processing.  Java's normal key event processing is:
	 * <ol>
	 *     <li>KeyListeners on the focused Component</li>
	 *     <li>InputMap and ActionMap actions for the Component</li>
	 *     <li>InputMap and ActionMap actions for the Component's parent, and so on up the
	 *         Swing hierarchy</li>
	 * </ol>
	 * Ghidra has altered this flow to be:
	 * <ol>
	 *     <li><b>Reserved keybinding actions</b>
	 *     <li>KeyListeners on the focused Component</li>
	 *     <li>InputMap and ActionMap actions for the Component</li>
	 *     <li><b>Ghidra tool-level actions</b></li>
	 *     <li>InputMap and ActionMap actions for the Component's parent, and so on up the
	 *         Swing hierarchy</li>
	 * </ol>
	 * This updated key event processing allows individual components to handle key events first,
	 * but then allows global Ghidra key bindings to be processed, allowing normal Java processing
	 * after Ghidra has had its chance to process the event.
	 * <P>
	 * There are some exceptions to this processing chain:
	 * <ol>
	 *      <li>We don't do any processing when the focused component is an instance of
	 *          <code>JTextComponent</code>.</li>
	 *      <li>We don't do any processing if the active window is an instance of
	 *          <code>DockingDialog</code>.</li>
	 * </ol>
	 * 
	 * @see java.awt.KeyEventDispatcher#dispatchKeyEvent(java.awt.event.KeyEvent)
	 */
	@Override
	public boolean dispatchKeyEvent(KeyEvent event) {
		if (blockKeyInput(event)) {
			return true; // let NO events through!
		}

		// always let Ghidra finish processing key events that it started
		if (actionInProgress(event)) {
			return true;
		}

		if (MenuKeyProcessor.processMenuKeyEvent(event)) {
			return true;
		}

		DockingKeyBindingAction action = getDockingKeyBindingActionForEvent(event);
		if (action == null) {
			return false; // let the normal event flow continue
		}

		// *Special*, reserved key bindings--these can always be processed
		if (processReservedKeyActionsPrecedence(action, event)) {
			return true;
		}

		// some known special cases that we don't wish to process
		KeyStroke ks = KeyStroke.getKeyStrokeForEvent(event);
		if (!isValidContextForKeyStroke(ks)) {
			return false;
		}

		if (willBeHandledByTextComponent(event)) {
			return false;
		}

		KeyBindingPrecedence keyBindingPrecedence = getValidKeyBindingPrecedence(action);
		if (keyBindingPrecedence == null) {
			// Odd Code: we use the precedence as a signal to say that, when it is null, there
			//           are no valid bindings to be processed.  We used to have a isValidContext()
			//           method on the action, but it repeated the involved work that is done
			//           in getKeyBindingPrecedence(), which is needed below.  So, just use the
			//           one call for both purposes.
			return false;
		}

		// Process the key event in precedence order.
		// If it processes the event at any given level, the short-circuit operator will kick out.
		// Finally, if the exception statement is reached, then someone has added a new level
		// of precedence that this algorithm has not taken into account!
		// @formatter:off
		return processKeyListenerPrecedence(action, keyBindingPrecedence, event) ||
			   processComponentActionMapPrecedence(action, keyBindingPrecedence, event) ||
			   processActionAtPrecedence(DefaultLevel, keyBindingPrecedence, action, event) ||
			   throwAssertException();
		// @formatter:on
	}

	private KeyBindingPrecedence getValidKeyBindingPrecedence(DockingKeyBindingAction action) {

		if (action instanceof MultipleKeyAction) {
			MultipleKeyAction multiAction = (MultipleKeyAction) action;
			return multiAction.geValidKeyBindingPrecedence(focusProvider.getFocusOwner());
		}
		return action.getKeyBindingPrecedence();
	}

	/**
	 * Returns true if the given key event should be blocked (i.e., not processed by us or Java).
	 */
	private boolean blockKeyInput(KeyEvent event) {
		Component component = event.getComponent();
		if (component == null) {
			// We are for managing GUI keyboard input--don't care about the event if this happens
			return false;
		}

		JRootPane rootPane = SwingUtilities.getRootPane(component);
		if (rootPane == null) {
			// This can happen when the source component of the key event has been hidden as a
			// result of processing the key event earlier, like on a key pressed event; for
			// example, when the user presses the ESC key to close a dialog.
			return true; // don't let Java process the remaining event chain
		}

		Component glassPane = rootPane.getGlassPane();
		if (glassPane instanceof GGlassPane) {
			if (((GGlassPane) glassPane).isBusy()) {
				return true; // out parent's glass pane is blocking..don't let events through
			}
		}
//        else {
//            Msg.debug( KeyBindingOverrideKeyEventDispatcher.this,
//                "Found a window with a non-standard glass pane--this should be fixed to " +
//                "use the Docking windowing system" );
//        }
		return false;
	}

	/**
	 * Used to clear the flag that signals we are in the middle of processing a Ghidra action.
	 */
	private boolean actionInProgress(KeyEvent event) {
		boolean wasInProgress = inProgressAction != null;
		if (event.getID() == KeyEvent.KEY_RELEASED) {
			DockingKeyBindingAction action = inProgressAction;
			inProgressAction = null;
			KeyStroke keyStroke = KeyStroke.getKeyStrokeForEvent(event);

			// note: this call has no effect if 'action' is null
			SwingUtilities.notifyAction(action, keyStroke, event, event.getSource(),
				event.getModifiersEx());

		}
		return wasInProgress;
	}

	/**
	 * A check to see if a given keystroke is something that should not be processed, depending
	 * upon the current state of the system.
	 * 
	 * @param keyStroke The keystroke to check.
	 * @return true if the caller of this method should handle the keystroke; false if the
	 *         keystroke should be ignored.
	 */
	private boolean isValidContextForKeyStroke(KeyStroke keyStroke) {
		Window activeWindow = focusProvider.getActiveWindow();
		if (activeWindow instanceof DockingDialog) {

			// The choice to ignore modal dialogs was made long ago.  We cannot remember why the
			// choice was made, but speculate that odd things can happen when keybindings are
			// processed with modal dialogs open.  For now, do not let key bindings get processed
			// for modal dialogs.  This can be changed in the future if needed.
			DockingDialog dialog = (DockingDialog) activeWindow;
			return !dialog.isModal();
		}
		return true; // default case; allow it through
	}

	private boolean willBeHandledByTextComponent(KeyEvent event) {

		Component destination = event.getComponent();
		if (destination == null) {
			Component focusOwner = focusProvider.getFocusOwner();
			destination = focusOwner;
		}

		if (!(destination instanceof JTextComponent)) {
			return false; // we only handle text components
		}

		// Note: don't do this--it breaks key event handling for text components, as they do
		//       not get to handle key events when they are not editable (they still should
		//       though, so things like built-in copy/paste still work).
		// JTextComponent textComponent = (JTextComponent) focusOwner;
		// if (!textComponent.isEditable()) {
		//	return false;
		// }

		// We've made the executive decision to allow all keys to go through to the text component
		// unless they are modified with the 'Alt'/'Ctrl'/etc keys, unless they directly used
		// by the text component
		if (!isModified(event)) {
			return true; // unmodified keys will be given to the text component
		}

		// the key is modified; let it through if the component has a mapping for the key
		return hasRegisteredKeyBinding((JTextComponent) destination, event);
	}

	/**
	 * A test to see if the given event is modified in such a way as a text component would not
	 * handle the event
	 * @param e the event
	 * @return true if modified
	 */
	private boolean isModified(KeyEvent e) {
		return e.isAltDown() || e.isAltGraphDown() || e.isMetaDown() || e.isControlDown();
	}

	private boolean hasRegisteredKeyBinding(JComponent c, KeyEvent event) {
		KeyStroke keyStroke = KeyStroke.getKeyStrokeForEvent(event);
		Action action = getJavaActionForComponent(c, keyStroke);
		return action != null;
	}

	/**
	 * This method should only be called if a programmer adds a new precedence to
	 * {@link KeyBindingPrecedence} and does not update the algorithm of
	 * {@link #dispatchKeyEvent(KeyEvent)} to take into account the new precedence.
	 */
	private boolean throwAssertException() {
		throw new AssertException("New precedence added to KeyBindingPrecedence?");
	}

	private boolean processReservedKeyActionsPrecedence(DockingKeyBindingAction action,
			KeyEvent event) {

		if (!action.isReservedKeybindingPrecedence()) {
			return false;
		}

		if (inProgressAction != null) {
			return true;
		}

		inProgressAction = action; // this will be handled on the release
		return true;
	}

	private boolean processKeyListenerPrecedence(DockingKeyBindingAction action,
			KeyBindingPrecedence keyBindingPrecedence, KeyEvent e) {
		if (processActionAtPrecedence(KeyBindingPrecedence.KeyListenerLevel, keyBindingPrecedence,
			action, e)) {
			return true;
		}

		// O.K., there is an action for the KeyStroke, but before we process it, we have to
		// check the proper ordering of key events (see method JavaDoc)
		if (processComponentKeyListeners(e)) {
			return true;
		}

		return false;
	}

	private boolean processComponentActionMapPrecedence(DockingKeyBindingAction action,
			KeyBindingPrecedence keyBindingPrecedence, KeyEvent event) {

		if (processActionAtPrecedence(ActionMapLevel, keyBindingPrecedence, action, event)) {
			return true;
		}

		KeyStroke keyStroke = KeyStroke.getKeyStrokeForEvent(event);
		if (processInputAndActionMaps(event, keyStroke)) {
			return true;
		}

		return false;
	}

	private boolean processActionAtPrecedence(KeyBindingPrecedence precedence,
			KeyBindingPrecedence keyBindingPrecedence, DockingKeyBindingAction action,
			KeyEvent event) {

		if (keyBindingPrecedence != precedence) {
			return false;
		}

		if (inProgressAction != null) {
			return true;
		}

		inProgressAction = action; // this will be handled on the release
		event.consume(); // don't let this event be used later
		return true;
	}

	private boolean processComponentKeyListeners(KeyEvent keyEvent) {

		Component focusOwner = focusProvider.getFocusOwner();
		if (focusOwner == null) {
			return false;
		}

		KeyListener[] keyListeners = focusOwner.getKeyListeners();
		for (KeyListener listener : keyListeners) {
			int id = keyEvent.getID();
			switch (id) {
				case KeyEvent.KEY_TYPED:
					listener.keyTyped(keyEvent);
					break;
				case KeyEvent.KEY_PRESSED:
					listener.keyPressed(keyEvent);
					break;
				case KeyEvent.KEY_RELEASED:
					listener.keyReleased(keyEvent);
					break;
			}
		}

		return keyEvent.isConsumed();
	}

	// note: this code is taken from the JComponent method:
	// protected boolean processKeyBinding(KeyStroke, KeyEvent, int, boolean )
	//
	// returns true if there is a focused component that has an action for the given keystroke
	// and it processes that action.
	private boolean processInputAndActionMaps(KeyEvent keyEvent, KeyStroke keyStroke) {
		Component focusOwner = focusProvider.getFocusOwner();
		if (focusOwner == null || !focusOwner.isEnabled() || !(focusOwner instanceof JComponent)) {
			return false;
		}

		JComponent jComponent = (JComponent) focusOwner;
		Action action = getJavaActionForComponent(jComponent, keyStroke);
		if (action != null) {
			return SwingUtilities.notifyAction(action, keyStroke, keyEvent, keyEvent.getSource(),
				keyEvent.getModifiersEx());
		}
		return false;
	}

	private Action getJavaActionForComponent(JComponent jComponent, KeyStroke keyStroke) {
		// first see if there is a Java key binding for when the component is in the focused
		// window...
		Action action = KeyBindingUtils.getAction(jComponent, keyStroke, JComponent.WHEN_FOCUSED);
		if (action != null) {
			return action;
		}

		// ...next see if there is a key binding for when the component is the child of the focus
		// owner
		action = KeyBindingUtils.getAction(jComponent, keyStroke,
			JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
		return action;
	}

	/**
	 * Gets a {@link DockingKeyBindingAction} that is registered for the given key event.  This
	 * method is aware of context for things like {@link DockingWindowManager} and active windows.
	 * @param event The key event to check.
	 * @return An action, if one is available for the given key event, in the current context.
	 */
	private DockingKeyBindingAction getDockingKeyBindingActionForEvent(KeyEvent event) {
		DockingWindowManager activeManager = getActiveDockingWindowManager();
		if (activeManager == null) {
			return null;
		}

		KeyStroke keyStroke = KeyStroke.getKeyStrokeForEvent(event);
		DockingKeyBindingAction bindingAction =
			(DockingKeyBindingAction) activeManager.getActionForKeyStroke(keyStroke);
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

	void setFocusOwnerProvider(FocusOwnerProvider focusProvider) {
		this.focusProvider = focusProvider;
	}
}
