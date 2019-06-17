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
package docking.actions;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.*;

import javax.swing.KeyStroke;

import org.apache.commons.collections4.map.LazyMap;

import docking.*;
import docking.action.*;
import docking.tool.util.DockingToolConstants;
import ghidra.framework.options.*;
import ghidra.util.exception.AssertException;
import util.CollectionUtils;

/**
 * An class to manage actions registered with the tool
 */
public class ToolActions implements PropertyChangeListener {

	private DockingWindowManager winMgr;
	private ActionToGuiHelper actionGuiHelper;

	/*
	 	Map of Maps of Sets
	 	
	 	Owner Name -> 
	 		Action Name -> Set of Actions
	 */
	private Map<String, Map<String, Set<DockingActionIf>>> actionsByNameByOwner = LazyMap.lazyMap(
		new HashMap<>(), () -> LazyMap.lazyMap(new HashMap<>(), () -> new HashSet<>()));

	private Map<String, SharedStubKeyBindingAction> sharedActionMap = new HashMap<>();

	private ToolOptions keyBindingOptions;
	private DockingTool dockingTool;

	/**
	 * Construct an ActionManager
	 * 
	 * @param tool tool using this ActionManager
	 * @param windowManager manager of the "Docking" arrangement of a set of components 
	 *        and actions in the tool
	 */
	public ToolActions(DockingTool tool, DockingWindowManager windowManager) {
		this.dockingTool = tool;
		this.winMgr = windowManager;
		this.actionGuiHelper = new ActionToGuiHelper(winMgr);
		keyBindingOptions = tool.getOptions(DockingToolConstants.KEY_BINDINGS);
	}

	public void dispose() {
		actionsByNameByOwner.clear();
		sharedActionMap.clear();
	}

	private void addActionToMap(DockingActionIf action) {

		Set<DockingActionIf> actions = getActionStorage(action);
		KeyBindingUtils.assertSameDefaultKeyBindings(action, actions);
		actions.add(action);
	}

	/**
	 * Add an action that works specifically with a component provider. 
	 * @param provider provider associated with the action
	 * @param action local action to the provider
	 */
	public synchronized void addLocalAction(ComponentProvider provider, DockingActionIf action) {
		checkForAlreadyAddedAction(provider, action);

		action.addPropertyChangeListener(this);
		addActionToMap(action);
		setKeyBindingOption(action);
		actionGuiHelper.addLocalAction(provider, action);
	}

	/**
	 * Adds the action to the tool.
	 * @param action the action to be added.
	 */
	public synchronized void addToolAction(DockingActionIf action) {
		action.addPropertyChangeListener(this);
		addActionToMap(action);
		setKeyBindingOption(action);
		actionGuiHelper.addToolAction(action);
	}

	private void setKeyBindingOption(DockingActionIf action) {

		if (action.usesSharedKeyBinding()) {
			installSharedKeyBinding(action);
			return;
		}

		if (!action.isKeyBindingManaged()) {
			return;
		}

		KeyStroke ks = action.getKeyBinding();
		keyBindingOptions.registerOption(action.getFullName(), OptionType.KEYSTROKE_TYPE, ks, null,
			null);
		KeyStroke newKs = keyBindingOptions.getKeyStroke(action.getFullName(), ks);
		if (!Objects.equals(ks, newKs)) {
			action.setUnvalidatedKeyBindingData(new KeyBindingData(newKs));
		}
	}

	private void installSharedKeyBinding(DockingActionIf action) {
		String name = action.getName();
		KeyStroke defaultKeyStroke = action.getKeyBinding();

		// get or create the stub to which we will add the action
		SharedStubKeyBindingAction stub = sharedActionMap.computeIfAbsent(name, key -> {

			SharedStubKeyBindingAction newStub =
				new SharedStubKeyBindingAction(name, keyBindingOptions);
			keyBindingOptions.registerOption(newStub.getFullName(), OptionType.KEYSTROKE_TYPE,
				defaultKeyStroke, null, null);
			return newStub;
		});

		stub.addClientAction(action);
	}

	/**
	 * Removes the given action from the tool
	 * @param action the action to be removed.
	 */
	public synchronized void removeToolAction(DockingActionIf action) {
		action.removePropertyChangeListener(this);
		removeAction(action);
		actionGuiHelper.removeToolAction(action);
	}

	/**
	 * Remove all actions that have the given owner.
	 * @param owner owner of the actions to remove
	 */
	public synchronized void removeToolActions(String owner) {

		// remove from the outer map first, to prevent concurrent modification exceptions
		Map<String, Set<DockingActionIf>> toCleanup = actionsByNameByOwner.remove(owner);
		if (toCleanup == null) {
			return; // no actions registered for this owner
		}

		//@formatter:off
		toCleanup.values()
			.stream()
			.flatMap(set -> set.stream())
			.forEach(action -> removeToolAction(action))
			;
		//@formatter:on
	}

	private void checkForAlreadyAddedAction(ComponentProvider provider, DockingActionIf action) {
		if (getActionStorage(action).contains(action)) {
			throw new AssertException("Cannot add the same action more than once. Provider " +
				provider.getName() + " - action: " + action.getFullName());
		}
	}

	/**
	 * Get all actions for the given owner
	 * @param owner owner of the actions
	 * @return array of actions; zero length array is returned if no
	 * action exists with the given name
	 */
	public synchronized Set<DockingActionIf> getActions(String owner) {

		Set<DockingActionIf> result = new HashSet<>();
		Map<String, Set<DockingActionIf>> actionsByName = actionsByNameByOwner.get(owner);
		for (Set<DockingActionIf> actions : actionsByName.values()) {
			result.addAll(actions);
		}

		if (SharedStubKeyBindingAction.SHARED_OWNER.equals(owner)) {
			result.addAll(sharedActionMap.values());
		}

		return result;
	}

	/**
	 * Get a set of all actions in the tool
	 * @return the actions
	 */
	public synchronized Set<DockingActionIf> getAllActions() {

		Set<DockingActionIf> result = new HashSet<>();
		Collection<Map<String, Set<DockingActionIf>>> maps = actionsByNameByOwner.values();
		for (Map<String, Set<DockingActionIf>> actionsByName : maps) {
			for (Set<DockingActionIf> actions : actionsByName.values()) {
				result.addAll(actions);
			}
		}

		result.addAll(sharedActionMap.values());

		return result;
	}

	/**
	 * Get the keybindings for each action so that they are still registered as being used; 
	 * otherwise the options will be removed because they are noted as not being used.
	 */
	public synchronized void restoreKeyBindings() {
		keyBindingOptions = dockingTool.getOptions(DockingToolConstants.KEY_BINDINGS);
		Set<DockingActionIf> actions = getAllActions();
		for (DockingActionIf action : actions) {
			if (!action.isKeyBindingManaged()) {
				continue;
			}
			KeyStroke ks = action.getKeyBinding();
			KeyStroke newKs = keyBindingOptions.getKeyStroke(action.getFullName(), ks);
			if (ks != newKs) {
				action.setUnvalidatedKeyBindingData(new KeyBindingData(newKs));
			}
		}
	}

	/**
	 * Remove an action that works specifically with a component provider. 
	 * @param provider provider associated with the action
	 * @param action local action to the provider
	 */
	public synchronized void removeProviderAction(ComponentProvider provider,
			DockingActionIf action) {
		action.removePropertyChangeListener(this);
		removeAction(action);
		actionGuiHelper.removeProviderAction(provider, action);
	}

	/**
	 * Get the actions for the given provider and remove them from the action map
	 * @param provider provider whose actions are to be removed
	 */
	public synchronized void removeComponentActions(ComponentProvider provider) {
		Iterator<DockingActionIf> it = actionGuiHelper.getComponentActions(provider);
		Set<DockingActionIf> set = CollectionUtils.asSet(it);
		for (DockingActionIf action : set) {
			removeProviderAction(provider, action);
		}
	}

	private void removeAction(DockingActionIf action) {
		getActionStorage(action).remove(action);
		if (action.usesSharedKeyBinding()) {
			SharedStubKeyBindingAction stub = sharedActionMap.get(action.getName());
			if (stub != null) {
				stub.removeClientAction(action);
			}
		}
	}

	private Set<DockingActionIf> getActionStorage(DockingActionIf action) {
		String owner = action.getOwner();
		String name = action.getName();
		return actionsByNameByOwner.get(owner).get(name);
	}

	@Override
	public void propertyChange(PropertyChangeEvent evt) {
		if (evt.getPropertyName().equals(DockingActionIf.KEYBINDING_DATA_PROPERTY)) {
			DockingAction action = (DockingAction) evt.getSource();
			if (!action.isKeyBindingManaged()) {
				dockingTool.setConfigChanged(true);
				return;
			}
			KeyBindingData keyBindingData = (KeyBindingData) evt.getNewValue();
			KeyStroke newKeyStroke = keyBindingData.getKeyBinding();
			Options opt = dockingTool.getOptions(DockingToolConstants.KEY_BINDINGS);
			KeyStroke optKeyStroke = opt.getKeyStroke(action.getFullName(), null);
			if (newKeyStroke == null) {
				opt.removeOption(action.getFullName());
			}
			else if (!newKeyStroke.equals(optKeyStroke)) {
				opt.setKeyStroke(action.getFullName(), newKeyStroke);
				dockingTool.setConfigChanged(true);
			}
		}
	}

	DockingActionIf getSharedStubKeyBindingAction(String name) {
		return sharedActionMap.get(name);
	}
}
