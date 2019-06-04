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
import java.util.function.Predicate;

import javax.swing.KeyStroke;

import org.apache.commons.collections4.map.LazyMap;

import docking.*;
import docking.action.*;
import docking.tool.util.DockingToolConstants;
import ghidra.framework.options.*;
import ghidra.util.exception.AssertException;

/**
 * An class to manage actions registered with the tool
 */
public class DockingToolActionManager implements PropertyChangeListener {

	private DockingWindowManager winMgr;
	private DockingWindowManagerActionUpdater winMgrActionUpdater;

	private Map<String, List<DockingActionIf>> actionMap =
		LazyMap.lazyMap(new HashMap<>(), () -> new ArrayList<>());
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
	public DockingToolActionManager(DockingTool tool, DockingWindowManager windowManager) {
		this.dockingTool = tool;
		this.winMgr = windowManager;
		this.winMgrActionUpdater = new DockingWindowManagerActionUpdater(winMgr);
		keyBindingOptions = tool.getOptions(DockingToolConstants.KEY_BINDINGS);
	}

	public void dispose() {
		actionMap.clear();
	}

	private void addActionToMap(DockingActionIf action) {
		String name = action.getFullName();
		List<DockingActionIf> actionList = actionMap.get(name);

		List<DockingActionIf> list = actionMap.get(name);
		if (!list.isEmpty()) {
			KeyBindingUtils.assertSameDefaultKeyBindings(action, actionList);
		}

		actionList.add(action);
	}

	private void removeActionFromMap(DockingActionIf action) {
		String name = action.getFullName();
		actionMap.get(name).remove(action);
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
		winMgrActionUpdater.addLocalAction(provider, action);
	}

	/**
	 * Adds the action to the tool.
	 * @param action the action to be added.
	 */
	public synchronized void addToolAction(DockingActionIf action) {
		action.addPropertyChangeListener(this);
		addActionToMap(action);
		setKeyBindingOption(action);
		winMgrActionUpdater.addToolAction(action);
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
		removeActionFromMap(action);
		winMgrActionUpdater.removeToolAction(action);
	}

	/**
	 * Remove all actions that have the given owner.
	 * @param owner owner of the actions to remove
	 */
	public synchronized void removeToolActions(String owner) {
		Predicate<String> ownerMatches = actionOwner -> actionOwner.equals(owner);
		Set<DockingActionIf> actions = getActions(ownerMatches);
		for (DockingActionIf action : actions) {
			removeToolAction(action);
		}
	}

	private void checkForAlreadyAddedAction(ComponentProvider provider, DockingActionIf action) {
		String name = action.getFullName();
		List<DockingActionIf> actionList = actionMap.get(name);
		if (actionList.contains(action)) {
			throw new AssertException("Cannot add the same action more than once. Provider " +
				provider.getName() + " - action: " + name);
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
		removeActionFromMap(action);
		winMgr.removeProviderAction(provider, action);
	}

	/**
	 * Get all actions that have the action name which includes the action owner's name.
	 * 
	 * @param fullName full name for the action, e.g., "My Action (My Plugin)"
	 * @return list of actions; empty if no action exists with the given name
	 */
	public Set<DockingActionIf> getDockingActionsByFullActionName(String fullName) {
		List<DockingActionIf> list = actionMap.get(fullName);
		return new HashSet<>(list);
	}

	/**
	 * Returns a list of actions whose owner matches the given predicate.
	 * 
	 * Note: Actions with the same name are assumed to be different instances of the same action.
	 * 
	 * @param ownerFilter the predicate that is used to test if the owners are the same; to get
	 *        all actions, return an 'always true' predicate 
	 * @return a list of deduped actions.
	 */
	private Set<DockingActionIf> getActions(Predicate<String> ownerFilter) {

		Set<DockingActionIf> result = new HashSet<>();
		for (List<DockingActionIf> list : actionMap.values()) {
			for (DockingActionIf action : list) {
				if (ownerFilter.test(action.getOwner())) {
					result.addAll(list);
				}
			}
		}

		for (DockingActionIf action : sharedActionMap.values()) {
			if (ownerFilter.test(action.getOwner())) {
				result.add(action);
			}
		}

		return result;
	}

	/**
	 * Get all actions for the given owner.
	 * @param owner owner of the actions
	 * @return array of actions; zero length array is returned if no
	 * action exists with the given name
	 */
	public synchronized Set<DockingActionIf> getActions(String owner) {
		Predicate<String> ownerMatches = actionOwner -> actionOwner.equals(owner);
		return getActions(ownerMatches);
	}

	/**
	 * Get a list of all actions in the tool
	 * @return list of PluginAction objects
	 */
	public synchronized Set<DockingActionIf> getAllActions() {
		Predicate<String> allOwnersMatch = name -> true;
		return getActions(allOwnersMatch);
	}

	/**
	 * Get the keybindings for each action so that they are still registered
	 * as being used; otherwise the options will be removed because they
	 * are noted as not being used.
	 *
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
	 * Get the actions for the given provider and remove them from the action map
	 * @param provider provider whose actions are to be removed
	 */
	public void removeComponentActions(ComponentProvider provider) {
		Iterator<DockingActionIf> iterator = winMgr.getComponentActions(provider);
		while (iterator.hasNext()) {
			DockingActionIf action = iterator.next();
			String name = action.getFullName();
			actionMap.get(name).remove(action);
		}
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
