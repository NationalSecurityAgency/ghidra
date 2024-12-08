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
import docking.actions.KeyBindingUtils;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import gui.event.MouseBinding;

/**
 * A class that organizes system key bindings by mapping them to assigned {@link DockingActionIf}s.
 *
 * <p>This class understands reserved system key bindings.  For non-reserved key bindings, this
 * class knows how to map a single key binding to multiple actions.
 */
public class KeyBindingsManager implements PropertyChangeListener {

	// this map exists to update the MultiKeyBindingAction when the key binding changes
	private Map<DockingActionIf, ComponentProvider> actionToProviderMap = new HashMap<>();
	private Map<KeyStroke, DockingKeyBindingAction> dockingKeyMap = new HashMap<>();
	private Map<MouseBinding, DockingMouseBindingAction> dockingMouseMap = new HashMap<>();
	private Map<String, DockingActionIf> systemActionsByFullName = new HashMap<>();

	private Tool tool;

	public KeyBindingsManager(Tool tool) {
		this.tool = tool;
	}

	public void addAction(ComponentProvider optionalProvider, DockingActionIf action) {
		action.addPropertyChangeListener(this);
		if (optionalProvider != null) {
			actionToProviderMap.put(action, optionalProvider);
		}

		KeyBindingData kbData = action.getKeyBindingData();
		if (kbData == null) {
			return;
		}

		KeyStroke keyBinding = kbData.getKeyBinding();
		if (keyBinding != null) {
			addKeyBinding(optionalProvider, action, keyBinding);
		}

		MouseBinding mouseBinding = kbData.getMouseBinding();
		if (mouseBinding != null) {
			doAddMouseBinding(action, mouseBinding);
		}
	}

	public void addSystemAction(DockingActionIf action) {
		KeyStroke keyStroke = action.getKeyBinding();
		Objects.requireNonNull(keyStroke);
		DockingKeyBindingAction existingAction = dockingKeyMap.get(keyStroke);
		if (existingAction != null) {
			throw new AssertException("Attempting to add more than one reserved " +
				"action to a given keystroke: " + keyStroke);
		}

		addSystemKeyBinding(action, keyStroke);
		action.addPropertyChangeListener(this);
	}

	public void removeAction(DockingActionIf action) {
		action.removePropertyChangeListener(this);
		actionToProviderMap.remove(action);
		removeKeyBinding(action.getKeyBinding(), action);
	}

	private void addKeyBinding(ComponentProvider provider, DockingActionIf action,
			KeyStroke keyStroke) {

		String errorMessage = validateActionKeyBinding(action, keyStroke);
		if (errorMessage != null) {
			// Getting here should not be possible from the UI, but may happen if a developer sets
			// an incorrect keybinding
			Msg.error(this, errorMessage);
			return;
		}

		// map standard keystroke to action
		doAddKeyBinding(provider, action, keyStroke);

		// map workaround keystroke to action
		fixupAltGraphKeyStrokeMapping(provider, action, keyStroke);
	}

	public String validateActionKeyBinding(DockingActionIf dockingAction, KeyStroke ks) {

		if (ks == null) {
			return null; // clearing the key stroke
		}

		//
		// 1) Handle case with given key stroke already in use by a system action
		//
		Action existingAction = dockingKeyMap.get(ks);
		if (existingAction instanceof SystemKeyBindingAction systemAction) {

			DockingActionIf systemDockingAction = systemAction.getAction();
			if (dockingAction == systemDockingAction) {
				return null; // same key stroke; not sure if this can happen
			}

			String ksString = KeyBindingUtils.parseKeyStroke(ks);
			return ksString + " in use by System action '" + systemDockingAction.getName() + "'";
		}

		if (dockingAction == null) {
			return null; // the client is only checking the keystroke and not any associated action
		}

		//
		// 2) Handle the case where a system action key stroke is being set to something that is
		// already in-use by some other action
		//
		boolean hasSystemAction = systemActionsByFullName.containsKey(dockingAction.getFullName());
		if (hasSystemAction && existingAction != null) {
			return "System action cannot be set to in-use key stroke";
		}

		return null;
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
		if (existingAction instanceof MultipleKeyAction) {
			MultipleKeyAction multipleKeyction = (MultipleKeyAction) existingAction;
			multipleKeyction.addAction(provider, action);
			return;
		}

		if (existingAction instanceof SystemKeyBindingAction) {
			// This should not happen due to protections in the UI
			Msg.error(this, "Attempted to use the same keybinding for an existing System action: " +
				existingAction + ".  Keystroke: " + mappingKeyStroke);
			return;
		}

		if (systemActionsByFullName.containsKey(action.getFullName())) {
			// the user has updated the binding for a System action; re-install it
			registerSystemKeyBinding(action, mappingKeyStroke);
			return;
		}

		// assume existingAction == null
		dockingKeyMap.put(mappingKeyStroke,
			new MultipleKeyAction(tool, provider, action, actionKeyStroke));
	}

	private void doAddMouseBinding(DockingActionIf action, MouseBinding mouseBinding) {

		DockingMouseBindingAction mouseBindingAction = dockingMouseMap.get(mouseBinding);
		if (mouseBindingAction != null) {
			String existingName = mouseBindingAction.getFullActionName();
			String message = """
					Attempted to use the same mouse binding for multiple actions. \
					Multiple mouse bindings are not supported. Binding: %s \
					New action: %s; existing action: %s
					""".formatted(mouseBinding, action.getFullName(), existingName);
			Msg.error(this, message);
			return;
		}

		dockingMouseMap.put(mouseBinding, new DockingMouseBindingAction(action, mouseBinding));
	}

	private void addSystemKeyBinding(DockingActionIf action, KeyStroke keyStroke) {
		KeyBindingData binding = KeyBindingData.createSystemKeyBindingData(keyStroke);
		action.setKeyBindingData(binding);
		registerSystemKeyBinding(action, keyStroke);
	}

	private void registerSystemKeyBinding(DockingActionIf action, KeyStroke keyStroke) {
		SystemKeyBindingAction systemAction = new SystemKeyBindingAction(tool, action, keyStroke);
		dockingKeyMap.put(keyStroke, systemAction);
		systemActionsByFullName.put(action.getFullName(), action);
	}

	private void removeKeyBinding(KeyStroke keyStroke, DockingActionIf action) {
		if (keyStroke == null) {
			return;
		}

		DockingKeyBindingAction existingAction = dockingKeyMap.get(keyStroke);
		if (existingAction == null) {
			return;
		}

		if (existingAction instanceof SystemKeyBindingAction) {
			dockingKeyMap.remove(keyStroke);
		}
		else if (existingAction instanceof MultipleKeyAction) {

			MultipleKeyAction mkAction = (MultipleKeyAction) existingAction;
			mkAction.removeAction(action);
			if (mkAction.isEmpty()) {
				dockingKeyMap.remove(keyStroke);
			}
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

	public Action getDockingAction(KeyStroke keyStroke) {
		return dockingKeyMap.get(keyStroke);
	}

	public Action getDockingAction(MouseBinding mouseBinding) {
		return dockingMouseMap.get(mouseBinding);
	}

	public boolean isSystemAction(DockingActionIf action) {
		return systemActionsByFullName.containsKey(action.getFullName());
	}

	public DockingActionIf getSystemAction(String fullName) {
		return systemActionsByFullName.get(fullName);
	}

	public Set<DockingActionIf> getSystemActions() {
		return new HashSet<>(systemActionsByFullName.values());
	}

	public void dispose() {
		dockingKeyMap.clear();
		dockingMouseMap.clear();
		actionToProviderMap.clear();
		systemActionsByFullName.clear();
	}
}
