/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.util.ReservedKeyBindings;
import ghidra.util.exception.AssertException;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.*;

import javax.swing.Action;
import javax.swing.KeyStroke;

import docking.action.*;

public class KeyBindingsManager implements PropertyChangeListener {

	protected Map<KeyStroke, DockingKeyBindingAction> dockingKeyMap;
	protected Map<DockingActionIf, ComponentProvider> actionToProviderMap;

	private DockingWindowManager winMgr;

	public KeyBindingsManager(DockingWindowManager winMgr) {
		this.winMgr = winMgr;
		dockingKeyMap = new HashMap<KeyStroke, DockingKeyBindingAction>();
		actionToProviderMap = new HashMap<DockingActionIf, ComponentProvider>();
	}

	public void addAction(DockingActionIf action, ComponentProvider optionalProvider) {
		action.addPropertyChangeListener(this);
		if (optionalProvider != null) {
			actionToProviderMap.put(action, optionalProvider);
		}

		KeyStroke keyBinding = action.getKeyBinding();

		if (keyBinding != null) {
			addKeyBinding(action, optionalProvider, keyBinding);
		}
	}

	public void addReservedAction(DockingActionIf action) {
		KeyStroke keyBinding = action.getKeyBinding();
		addReservedKeyBinding(action, keyBinding);
	}

	public void removeAction(DockingActionIf action) {
		action.removePropertyChangeListener(this);
		actionToProviderMap.remove(action);
		removeKeyBinding(action.getKeyBinding(), action);
	}

	private void addKeyBinding(DockingActionIf action, ComponentProvider provider,
			KeyStroke keyStroke) {
		if (ReservedKeyBindings.isReservedKeystroke(keyStroke)) {
			throw new AssertException("Cannot assign action to a reserved keystroke.  " +
				"Action: " + action.getName() + " - Keystroke: " + keyStroke);
		}

		DockingKeyBindingAction existingAction = dockingKeyMap.get(keyStroke);
		if (existingAction == null) {
			dockingKeyMap.put(keyStroke, new MultipleKeyAction(winMgr, provider, action, keyStroke));
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

		dockingKeyMap.put(keyStroke, new ReservedKeyBindingAction(winMgr, action, keyStroke));
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
				addKeyBinding(action, actionToProviderMap.get(action), ks);
			}
		}
	}

	public List<DockingActionIf> getLocalActions() {
		return new ArrayList<DockingActionIf>(actionToProviderMap.keySet());
	}

	public Action getDockingKeyAction(KeyStroke keyStroke) {
		return dockingKeyMap.get(keyStroke);
	}

	public void dispose() {
		winMgr = null;
		dockingKeyMap.clear();
		actionToProviderMap.clear();
	}

}
