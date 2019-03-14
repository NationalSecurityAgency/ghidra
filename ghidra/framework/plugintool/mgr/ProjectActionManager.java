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
package ghidra.framework.plugintool.mgr;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.*;

import javax.swing.KeyStroke;

import docking.ComponentProvider;
import docking.DockingWindowManager;
import docking.action.*;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.ToolConstants;
import ghidra.util.exception.AssertException;

/**
 * Helper class to manage plugin actions for the tool. 
 */
public class ProjectActionManager implements PropertyChangeListener {
	private DockingWindowManager winMgr;
	private Map<String, List<DockingActionIf>> actionMap;
	private Options keyBindingOptions;
	private PluginTool tool;

	/**
	 * Construct an ActionManager.
	 * @param tool plugin tool using this ActionManager
	 * @param winMgr manager of the "Docking" arrangement 
	 * of a set of components and actions in the tool
	 */
	public ProjectActionManager(PluginTool tool, DockingWindowManager winMgr) {
		this.tool = tool;
		this.winMgr = winMgr;
		actionMap = new HashMap<>();
		keyBindingOptions = tool.getOptions(ToolConstants.KEY_BINDINGS);
	}

	public void dispose() {
		actionMap.clear();
	}

	private void addActionToMap(DockingActionIf action) {
		String name = action.getFullName();
		List<DockingActionIf> actionList = actionMap.get(name);
		if (actionList == null) {
			List<DockingActionIf> newList = new ArrayList<>();
			newList.add(action);
			actionMap.put(name, newList);
		}
		else {
			actionList.add(action);
		}
	}

	private void removeActionFromMap(DockingActionIf action) {
		String name = action.getFullName();
		List<DockingActionIf> actionList = actionMap.get(name);
		if (actionList == null) {
			return;
		}

		if (actionList.remove(action) && actionList.isEmpty()) {
			actionMap.remove(name);
		}
	}

	/**
	 * Adds the action to the tool.
	 * @param action the action to be added.
	 */
	public synchronized void addToolAction(DockingActionIf action) {
		action.addPropertyChangeListener(this);
		addActionToMap(action);
		if (action.isKeyBindingManaged()) {
			KeyStroke ks = action.getKeyBinding();
			keyBindingOptions.registerOption(action.getFullName(), OptionType.KEYSTROKE_TYPE, ks,
				null, null);
			KeyStroke newKs = keyBindingOptions.getKeyStroke(action.getFullName(), ks);
			if (ks != newKs) {
				action.setUnvalidatedKeyBindingData(new KeyBindingData(newKs));
			}
		}
		winMgr.addToolAction(action);
	}

	/**
	 * Removes the given action from the tool
	 * @param action the action to be removed.
	 */
	public synchronized void removeToolAction(DockingActionIf action) {
		action.removePropertyChangeListener(this);
		removeActionFromMap(action);
		winMgr.removeToolAction(action);
	}

	/**
	 * Remove all actions that have the given owner.
	 * @param owner owner of the actions to remove
	 */
	public synchronized void removeToolActions(String owner) {
		List<DockingActionIf> actions = getActions(owner);
		for (DockingActionIf action : actions) {
			removeToolAction(action);
		}
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
		if (action.isKeyBindingManaged()) {
			KeyStroke ks = action.getKeyBinding();
			keyBindingOptions.registerOption(action.getFullName(), OptionType.KEYSTROKE_TYPE, ks,
				null, null);
			KeyStroke newKs = keyBindingOptions.getKeyStroke(action.getFullName(), ks);
			if (ks != newKs) {
				action.setUnvalidatedKeyBindingData(new KeyBindingData(newKs));
			}
		}
		winMgr.addLocalAction(provider, action);
	}

	private void checkForAlreadyAddedAction(ComponentProvider provider, DockingActionIf action) {
		String name = action.getFullName();
		List<DockingActionIf> actionList = actionMap.get(name);
		if (actionList == null) {
			return;
		}
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
	public List<DockingActionIf> getDockingActionsByFullActionName(String fullActionName) {
		List<DockingActionIf> list = actionMap.get(fullActionName);
		if (list == null) {
			return new ArrayList<>();
		}
		return new ArrayList<>(list);
	}

	/**
	 * Returns a list of actions whose owner matches the given owner or all actions if the given
	 * owner is null.
	 * <p>
	 * This method will only return a single instance of any named action, even if multiple 
	 * actions have been registered with the same name.
	 * <p>
	 * Note: Actions with the same name are assumed to be different instances of the same action.
	 * 
	 * @param owner The of the action, or null to get all actions
	 * @return a list of deduped actions.
	 */
	private List<DockingActionIf> getUniqueActionList(String owner) {
		List<DockingActionIf> matchingActionList = new ArrayList<>();

		for (List<DockingActionIf> actionList : actionMap.values()) {
			// we only want *one* instance of duplicate actions
			DockingActionIf action = actionList.get(0);
			if (owner == null || action.getOwner().equals(owner)) {
				matchingActionList.add(action);
			}
		}

		return matchingActionList;
	}

	/**
	 * Get all actions for the given owner.
	 * @param owner owner of the actions
	 * @return array of actions; zero length array is returned if no
	 * action exists with the given name
	 */
	public synchronized List<DockingActionIf> getActions(String owner) {
		List<DockingActionIf> list = getUniqueActionList(owner);
		return list;
	}

	/**
	 * Get a list of all actions in the tool.
	 * @return list of PluginAction objects
	 */
	public List<DockingActionIf> getAllActions() {
		return getUniqueActionList(null);
	}

	/**
	 * Get the keybindings for each action so that they are still registered
	 * as being used; otherwise the options will be removed because they
	 * are noted as not being used.
	 *
	 */
	public synchronized void restoreKeyBindings() {
		keyBindingOptions = tool.getOptions(ToolConstants.KEY_BINDINGS);
		List<DockingActionIf> actions = getAllActions();
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
	 * Get the actions for the given provider and remove them from the
	 * actionMap; call the window manager to remove the provider.
	 * @param provider provider to be removed
	 */
	public void removeComponent(ComponentProvider provider) {
		Iterator<DockingActionIf> iterator = winMgr.getComponentActions(provider);
		while (iterator.hasNext()) {
			DockingActionIf action = iterator.next();
			String name = action.getFullName();
			List<DockingActionIf> actionList = actionMap.get(name);
			if (actionList != null && actionList.remove(action) && actionList.isEmpty()) {
				actionMap.remove(name);
			}
		}
		winMgr.removeComponent(provider);
	}

	@Override
	public void propertyChange(PropertyChangeEvent evt) {
		if (evt.getPropertyName().equals(DockingActionIf.KEYBINDING_DATA_PROPERTY)) {
			DockingAction action = (DockingAction) evt.getSource();
			if (!action.isKeyBindingManaged()) {
				tool.setConfigChanged(true);
				return;
			}
			KeyBindingData keyBindingData = (KeyBindingData) evt.getNewValue();
			KeyStroke newKeyStroke = keyBindingData.getKeyBinding();
			Options opt = tool.getOptions(ToolConstants.KEY_BINDINGS);
			KeyStroke optKeyStroke = opt.getKeyStroke(action.getFullName(), null);
			if (newKeyStroke == null) {
				opt.removeOption(action.getFullName());
			}
			else if (!newKeyStroke.equals(optKeyStroke)) {
				opt.setKeyStroke(action.getFullName(), newKeyStroke);
				tool.setConfigChanged(true);
			}
		}
	}
}
