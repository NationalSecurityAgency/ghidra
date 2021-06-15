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

import java.awt.event.InputEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.*;

import javax.swing.Action;
import javax.swing.KeyStroke;

import docking.*;
import ghidra.util.ReservedKeyBindings;
import ghidra.util.exception.AssertException;

/**
 * A class that organizes system key bindings by mapping them to assigned {@link DockingActionIf}s.
 * 
 * <p>This class understands reserved system key bindings.  For non-reserved key bindings, this 
 * class knows how to map a single key binding to multiple actions.
 */
public class KeyBindingsManager implements PropertyChangeListener {

	// this map exists to update the MultiKeyBindingAction when the key binding changes
	private Map<DockingActionIf, ComponentProvider> actionToProviderMap;
	private Map<KeyStroke, DockingKeyBindingAction> dockingKeyMap;
	private Tool tool;

	public KeyBindingsManager(Tool tool) {
		this.tool = tool;
		dockingKeyMap = new HashMap<>();
		actionToProviderMap = new HashMap<>();
	}

	public void addAction(ComponentProvider optionalProvider, DockingActionIf action) {
		action.addPropertyChangeListener(this);
		if (optionalProvider != null) {
			actionToProviderMap.put(action, optionalProvider);
		}

		KeyStroke keyBinding = action.getKeyBinding();

		if (keyBinding != null) {
			addKeyBinding(optionalProvider, action, keyBinding);
		}
	}

	public void addReservedAction(DockingActionIf action) {
		KeyStroke keyBinding = action.getKeyBinding();
		Objects.requireNonNull(keyBinding);
		addReservedKeyBinding(action, keyBinding);
	}

	public void addReservedAction(DockingActionIf action, KeyStroke ks) {
		addReservedKeyBinding(action, ks);
	}

	public void removeAction(DockingActionIf action) {
		action.removePropertyChangeListener(this);
		actionToProviderMap.remove(action);
		removeKeyBinding(action.getKeyBinding(), action);
	}

	private void addKeyBinding(ComponentProvider provider, DockingActionIf action,
			KeyStroke keyStroke) {

		if (ReservedKeyBindings.isReservedKeystroke(keyStroke)) {
			throw new AssertException("Cannot assign action to a reserved keystroke.  " +
				"Action: " + action.getName() + " - Keystroke: " + keyStroke);
		}

		// map standard keybinding to action 
		doAddKeyBinding(provider, action, keyStroke);

		fixupAltGraphKeyStrokeMapping(provider, action, keyStroke);
	}

	private void fixupAltGraphKeyStrokeMapping(ComponentProvider provider, DockingActionIf action,
			KeyStroke keyStroke) {

		// special case 
		int modifiers = keyStroke.getModifiers();
		if ((modifiers & InputEvent.ALT_DOWN_MASK) == InputEvent.ALT_DOWN_MASK) {
			//
			// Also register the 'Alt' binding with the 'Alt Graph' mask.  This fixes the but
			// on Windows (https://bugs.openjdk.java.net/browse/JDK-8194873) 
			// that have different key codes for the left and right Alt keys.
			//
			modifiers |= InputEvent.ALT_GRAPH_DOWN_MASK;
			KeyStroke updateKeyStroke =
				KeyStroke.getKeyStroke(keyStroke.getKeyCode(), modifiers, false);
			doAddKeyBinding(provider, action, updateKeyStroke, keyStroke);
		}
	}

	private void doAddKeyBinding(ComponentProvider provider, DockingActionIf action,
			KeyStroke keyStroke) {
		doAddKeyBinding(provider, action, keyStroke, keyStroke);
	}

	private void doAddKeyBinding(ComponentProvider provider, DockingActionIf action,
			KeyStroke mappingKeyStroke, KeyStroke actionKeyStroke) {

		DockingKeyBindingAction existingAction = dockingKeyMap.get(mappingKeyStroke);
		if (existingAction == null) {
			dockingKeyMap.put(mappingKeyStroke,
				new MultipleKeyAction(tool, provider, action, actionKeyStroke));
			return;
		}

		if (!(existingAction instanceof MultipleKeyAction)) {
			return; // reserved binding; nothing to do
		}

		MultipleKeyAction multipleKeyction = (MultipleKeyAction) existingAction;
		multipleKeyction.addAction(provider, action);
	}

	private void addReservedKeyBinding(DockingActionIf action, KeyStroke keyStroke) {
		DockingKeyBindingAction existingAction = dockingKeyMap.get(keyStroke);
		if (existingAction != null) {
			throw new AssertException("Attempting to add more than one reserved " +
				"action to a given keystroke: " + keyStroke);
		}

		KeyBindingData binding = KeyBindingData.createReservedKeyBindingData(keyStroke);
		action.setKeyBindingData(binding);
		dockingKeyMap.put(keyStroke, new ReservedKeyBindingAction(tool, action, keyStroke));
	}

	/**
	 * Remove the keystroke binding from the root pane's input map
	 * using keystroke specified instead of that specified by the action
	 */
	private void removeKeyBinding(KeyStroke keyStroke, DockingActionIf action) {
		if (keyStroke == null) {
			return;
		}

		if (ReservedKeyBindings.isReservedKeystroke(keyStroke)) {
			return;
		}

		DockingKeyBindingAction existingAction = dockingKeyMap.get(keyStroke);
		if (existingAction == null) {
			return;
		}

		MultipleKeyAction mkAction = (MultipleKeyAction) existingAction;
		mkAction.removeAction(action);
		if (mkAction.isEmpty()) {
			dockingKeyMap.remove(keyStroke);
		}
	}

	@Override
	public void propertyChange(PropertyChangeEvent evt) {
		String name = evt.getPropertyName();
		DockingActionIf action = (DockingActionIf) evt.getSource();
		if (!name.equals(DockingActionIf.KEYBINDING_DATA_PROPERTY)) {
			return;
		}

		KeyBindingData keyData = (KeyBindingData) evt.getOldValue();
		if (keyData != null) {
			KeyStroke ks = keyData.getKeyBinding();
			if (ks != null) {
				removeKeyBinding(ks, action);
			}
		}

		KeyBindingData newKeyData = (KeyBindingData) evt.getNewValue();
		if (newKeyData != null) {
			KeyStroke ks = newKeyData.getKeyBinding();
			if (ks != null) {
				addKeyBinding(actionToProviderMap.get(action), action, ks);
			}
		}
	}

	public Action getDockingKeyAction(KeyStroke keyStroke) {
		return dockingKeyMap.get(keyStroke);
	}

	public void dispose() {
		dockingKeyMap.clear();
		actionToProviderMap.clear();
	}
}
