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

import static generic.util.action.SystemKeyBindings.*;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import javax.swing.Action;
import javax.swing.KeyStroke;

import org.apache.commons.collections4.IteratorUtils;
import org.apache.commons.collections4.Predicate;
import org.apache.commons.collections4.map.LazyMap;

import docking.*;
import docking.action.*;
import docking.tool.util.DockingToolConstants;
import ghidra.framework.options.*;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import gui.event.MouseBinding;
import util.CollectionUtils;
import utilities.util.reflection.ReflectionUtilities;

/**
 * An class to manage actions registered with the tool
 */
public class ToolActions implements DockingToolActions, PropertyChangeListener {

	// matches the full action name (e.g., "Action Name (Owner Name)"
	private Pattern ACTION_NAME_PATTERN = Pattern.compile("(.+) \\((.+)\\)");

	private ActionToGuiHelper actionGuiHelper;

	/*
	 	Map of Maps of Sets
	
	 	Owner Name ->
	 		Action Name -> Set of Actions
	 */
	private Map<String, Map<String, Set<DockingActionIf>>> actionsByNameByOwner = LazyMap.lazyMap(
		new HashMap<>(), () -> LazyMap.lazyMap(new HashMap<>(), () -> new HashSet<>()));

	private Map<String, SharedStubKeyBindingAction> sharedActionMap = new HashMap<>();

	private ToolOptions options;
	private Tool tool;
	private KeyBindingsManager keyBindingsManager;
	private OptionsChangeListener optionChangeListener = (toolOptions, optionName, oldValue,
			newValue) -> updateKeyBindingsFromOptions(optionName, (ActionTrigger) newValue);

	/**
	 * Construct an ActionManager
	 *
	 * @param tool tool using this ActionManager
	 * @param actionToGuiHelper the class that takes actions and maps them to GUI widgets
	 */
	public ToolActions(Tool tool, ActionToGuiHelper actionToGuiHelper) {
		this.tool = tool;
		this.actionGuiHelper = actionToGuiHelper;
		this.keyBindingsManager = new KeyBindingsManager(tool);
		this.options = tool.getOptions(DockingToolConstants.KEY_BINDINGS);
		this.options.addOptionsChangeListener(optionChangeListener);

		createSystemActions();
		SharedActionRegistry.installSharedActions(tool, this);
	}

	private void createSystemActions() {

		addSystemAction(new SetKeyBindingAction(tool, UPDATE_KEY_BINDINGS_KEY));

		addSystemAction(new HelpAction(HELP_KEY1, false));
		addSystemAction(new HelpAction(HELP_KEY2, true));
		addSystemAction(new HelpInfoAction(HELP_INFO_KEY));
		addSystemAction(new ShowContextMenuAction(CONTEXT_MENU_KEY1, true));
		addSystemAction(new ShowContextMenuAction(CONTEXT_MENU_KEY2, false));

		addSystemAction(new NextPreviousWindowAction(FOCUS_NEXT_WINDOW_KEY, true));
		addSystemAction(new NextPreviousWindowAction(FOCUS_PREVIOUS_WINDOW_KEY, false));

		addSystemAction(new GlobalFocusTraversalAction(FOCUS_NEXT_COMPONENT_KEY, true));
		addSystemAction(new GlobalFocusTraversalAction(FOCUS_PREVIOUS_COMPONENT_KEY, false));

		addSystemAction(new ShowActionChooserDialogAction());

		// helpful debugging actions
		addSystemAction(new ShowFocusInfoAction());
		addSystemAction(new ShowFocusCycleAction());
		addSystemAction(new ComponentThemeInspectorAction());
	}

	private void addSystemAction(DockingAction action) {

		// Some System actions support changing the keybinding.  In the future, all System actions
		// may support this.
		if (action.getKeyBindingType().isManaged()) {
			ActionTrigger actionTrigger = getActionTrigger(action);
			loadKeyBindingFromOptions(action, actionTrigger);
		}

		keyBindingsManager.addSystemAction(action);
		addActionToMap(action);
	}

	public void dispose() {
		actionsByNameByOwner.clear();
		sharedActionMap.clear();
		keyBindingsManager.dispose();
	}

	private void addActionToMap(DockingActionIf action) {
		Set<DockingActionIf> actions = getActionStorage(action);
		assertSameDefaultActionTrigger(action, actions);
		actions.add(action);
	}

	private static void assertSameDefaultActionTrigger(DockingActionIf newAction,
			Collection<DockingActionIf> existingActions) {

		if (!newAction.getKeyBindingType().supportsKeyBindings()) {
			return;
		}

		KeyBindingData newDefaultBinding = newAction.getDefaultKeyBindingData();
		ActionTrigger defaultTrigger = getActionTrigger(newDefaultBinding);
		for (DockingActionIf action : existingActions) {
			if (!action.getKeyBindingType().supportsKeyBindings()) {
				continue;
			}

			KeyBindingData existingDefaultBinding = action.getDefaultKeyBindingData();
			ActionTrigger existingTrigger = getActionTrigger(existingDefaultBinding);
			if (!Objects.equals(defaultTrigger, existingTrigger)) {
				logDifferentKeyBindingsWarnigMessage(newAction, action, existingTrigger);
				break; // one warning seems like enough
			}
		}
	}

	/*
	 * Verifies that two equivalent actions (same name and owner) share the same default action 
	 * trigger.  It is considered a programming mistake for two equivalent actions to have different
	 * triggers.
	 */
	private static void logDifferentKeyBindingsWarnigMessage(DockingActionIf newAction,
			DockingActionIf existingAction, ActionTrigger existingDefaultTrigger) {

		//@formatter:off
		String s = "Shared Key Binding Actions have different default values.  These " +
				"must be the same." +
				"\n\tAction name: '"+existingAction.getName()+ "'" +
				"\n\tAction 1: " + existingAction.getInceptionInformation() +
				"\n\t\tAction Trigger: " + existingDefaultTrigger +
				"\n\tAction 2: " + newAction.getInceptionInformation() +
				"\n\t\tAction Trigger: " + newAction.getKeyBinding() +
				"\nUsing the " +
				"first value set - " + existingDefaultTrigger;
		//@formatter:on

		Msg.warn(ToolActions.class, s, ReflectionUtilities.createJavaFilteredThrowable());
	}

	private static ActionTrigger getActionTrigger(KeyBindingData data) {
		if (data == null) {
			return null;
		}
		return data.getActionTrigger();
	}

	/**
	 * Add an action that works specifically with a component provider.
	 * @param provider provider associated with the action
	 * @param action local action to the provider
	 */
	@Override
	public synchronized void addLocalAction(ComponentProvider provider, DockingActionIf action) {
		checkForAlreadyAddedAction(provider, action);

		action.addPropertyChangeListener(this);
		addActionToMap(action);
		initializeKeyBinding(provider, action);
		actionGuiHelper.addLocalAction(provider, action);
	}

	@Override
	public synchronized void addGlobalAction(DockingActionIf action) {
		checkForAlreadyAddedAction(null, action);

		action.addPropertyChangeListener(this);
		addActionToMap(action);
		initializeKeyBinding(null, action);
		actionGuiHelper.addToolAction(action);
	}

	private void initializeKeyBinding(ComponentProvider provider, DockingActionIf action) {

		KeyBindingType type = action.getKeyBindingType();
		if (!type.supportsKeyBindings()) {
			return;
		}

		if (type.isShared()) {
			installSharedKeyBinding(provider, action);
			return;
		}

		ActionTrigger actionTrigger = getActionTrigger(action);
		loadKeyBindingFromOptions(action, actionTrigger);

		keyBindingsManager.addAction(provider, action);
	}

	private ActionTrigger getActionTrigger(DockingActionIf action) {
		KeyBindingData kbData = action.getKeyBindingData();
		if (kbData != null) {
			return kbData.getActionTrigger();
		}
		return null;
	}

	private void loadKeyBindingFromOptions(DockingActionIf action, ActionTrigger actionTrigger) {

		String fullName = action.getFullName();
		String description = "Keybinding for " + fullName;
		options.registerOption(fullName, OptionType.ACTION_TRIGGER, actionTrigger, null,
			description);

		KeyBindingData existingKbData = action.getKeyBindingData();

		ActionTrigger newTrigger = options.getActionTrigger(fullName, actionTrigger);
		KeyBindingData newKbData = KeyBindingData.update(existingKbData, newTrigger);
		action.setUnvalidatedKeyBindingData(newKbData);
	}

	private void installSharedKeyBinding(ComponentProvider provider, DockingActionIf action) {

		String name = action.getName();

		// get or create the stub to which we will add the action
		SharedStubKeyBindingAction stub = sharedActionMap.computeIfAbsent(name, key -> {

			ActionTrigger actionTrigger = getActionTrigger(action);
			SharedStubKeyBindingAction newStub =
				new SharedStubKeyBindingAction(name, actionTrigger, options);
			registerStub(newStub, actionTrigger);
			return newStub;
		});

		String owner = action.getOwner();
		stub.addActionOwner(owner);
		stub.addClientAction(action);

		if (!(action instanceof AutoGeneratedDockingAction)) {
			// Auto-generated actions are temporary and should not receive key events
			keyBindingsManager.addAction(provider, action);
		}
	}

	private void registerStub(SharedStubKeyBindingAction stub, ActionTrigger defaultActionTrigger) {
		stub.addPropertyChangeListener(this);

		loadKeyBindingFromOptions(stub, defaultActionTrigger);

		keyBindingsManager.addAction(null, stub);
	}

	@Override
	public synchronized void removeGlobalAction(DockingActionIf action) {
		action.removePropertyChangeListener(this);
		removeAction(action);
		actionGuiHelper.removeToolAction(action);
		dispose(action);
	}

	private void dispose(DockingActionIf action) {
		try {
			action.dispose();
		}
		catch (Throwable t) {
			Msg.error(this, "Exception disposing action '" + action.getFullName() + "'", t);
		}
	}

	@Override
	public synchronized void removeActions(String owner) {

		// remove from the outer map first, to prevent concurrent modification exceptions
		Map<String, Set<DockingActionIf>> toCleanup = actionsByNameByOwner.remove(owner);
		if (toCleanup == null) {
			return; // no actions registered for this owner
		}

		// Note: this method is called when plugins are removed.  'owner' is the name of the plugin.
		// This method will also get called while passing the system owner.  In that case, we do 
		// not want to remove system actions in this method.   We check below for system actions.

		//@formatter:off
		toCleanup.values()
			.stream()
			.flatMap(set -> set.stream())
			.filter(action -> !keyBindingsManager.isSystemAction(action)) // (see note above) 
			.forEach(action -> removeGlobalAction(action))
			;
		//@formatter:on
	}

	private void checkForAlreadyAddedAction(ComponentProvider provider, DockingActionIf action) {
		if (getActionStorage(action).contains(action)) {
			String providerString =
				provider == null ? "Action: " : "Provider " + provider.getName() + " - action: ";
			throw new AssertException("Cannot add the same action more than once. " +
				providerString + action.getFullName());
		}
	}

	@Override
	public Set<DockingActionIf> getLocalActions(ComponentProvider provider) {
		return actionGuiHelper.getLocalActions(provider);
	}

	@Override
	public synchronized Set<DockingActionIf> getActions(String owner) {

		Set<DockingActionIf> result = new HashSet<>();
		Map<String, Set<DockingActionIf>> actionsByName = actionsByNameByOwner.get(owner);
		for (Set<DockingActionIf> actions : actionsByName.values()) {
			result.addAll(actions);
		}

		Collection<SharedStubKeyBindingAction> values = sharedActionMap.values();
		for (SharedStubKeyBindingAction stub : values) {
			String stubOwner = stub.getOwner();
			if (stubOwner.equals(owner)) {
				result.add(stub);
			}
		}

		return result;
	}

	@Override
	public synchronized Set<DockingActionIf> getGlobalActions() {
		return actionGuiHelper.getGlobalActions();
	}

	@Override
	public synchronized Set<DockingActionIf> getAllActions() {

		Set<DockingActionIf> result = new HashSet<>();
		Collection<Map<String, Set<DockingActionIf>>> maps = actionsByNameByOwner.values();
		for (Map<String, Set<DockingActionIf>> actionsByName : maps) {
			for (Set<DockingActionIf> actions : actionsByName.values()) {
				result.addAll(actions);
			}
		}

		result.addAll(sharedActionMap.values());

		result.addAll(keyBindingsManager.getSystemActions());

		return result;
	}

	private Iterator<DockingActionIf> getAllActionsIterator() {
		// chain all items together, rather than copy the data
		// Note: do not use Apache's IteratorUtils.chainedIterator. It degrades exponentially
		//@formatter:off
		return Stream.concat(
			actionsByNameByOwner.values().stream()
				.flatMap(actionsByName -> actionsByName.values().stream()) 
				.flatMap(actions -> actions.stream()),
			sharedActionMap.values().stream()).iterator();
		//@formatter:on
	}

	/*
	 * An odd method that really shoulnd't be on the interface.  This is a call that allows the 
	 * framework to signal that the ToolOptions have been rebuilt, such as when restoring from xml.
	 * During a rebuild, ToolOptions does not send out events, so this class does not get any of the
	 * values from the new options.  This method tells us to get the new version of the options from
	 * the tool.
	 */
	public synchronized void optionsRebuilt() {

		// grab the new, rebuilt options
		options = tool.getOptions(DockingToolConstants.KEY_BINDINGS);

		Iterator<DockingActionIf> it = getKeyBindingActionsIterator();
		for (DockingActionIf action : CollectionUtils.asIterable(it)) {
			KeyBindingData currentKbData = action.getKeyBindingData();
			ActionTrigger optionsTrigger = options.getActionTrigger(action.getFullName(), null);
			KeyBindingData newKbData = KeyBindingData.update(currentKbData, optionsTrigger);
			action.setUnvalidatedKeyBindingData(newKbData);
		}
	}

	// return only actions that allow key bindings
	private Iterator<DockingActionIf> getKeyBindingActionsIterator() {
		Predicate<DockingActionIf> filter = a -> a.getKeyBindingType() == KeyBindingType.INDIVIDUAL;
		return IteratorUtils.filteredIterator(getAllActionsIterator(), filter);
	}

	/**
	 * Remove an action that works specifically with a component provider.
	 * @param provider provider associated with the action
	 * @param action local action to the provider
	 */
	@Override
	public synchronized void removeLocalAction(ComponentProvider provider, DockingActionIf action) {
		action.removePropertyChangeListener(this);
		removeAction(action);
		keyBindingsManager.removeAction(action);
		actionGuiHelper.removeProviderAction(provider, action);
		dispose(action);
	}

	@Override
	public synchronized void removeActions(ComponentProvider provider) {
		Iterator<DockingActionIf> it = actionGuiHelper.getComponentActions(provider);

		// copy the data to avoid concurrent modification exceptions
		Set<DockingActionIf> set = CollectionUtils.asSet(it);
		for (DockingActionIf action : set) {
			removeLocalAction(provider, action);
		}
	}

	private void removeAction(DockingActionIf action) {

		keyBindingsManager.removeAction(action);

		getActionStorage(action).remove(action);
		if (!action.getKeyBindingType().isShared()) {
			return;
		}

		SharedStubKeyBindingAction stub = sharedActionMap.get(action.getName());
		if (stub != null) {
			stub.removeClientAction(action);
		}
	}

	private Set<DockingActionIf> getActionStorage(DockingActionIf action) {
		String owner = action.getOwner();
		String name = action.getName();
		return actionsByNameByOwner.get(owner).get(name);
	}

	private void updateKeyBindingsFromOptions(String optionName, ActionTrigger newTrigger) {

		// note: the 'shared actions' update themselves, so we only need to handle standard actions

		Matcher matcher = ACTION_NAME_PATTERN.matcher(optionName);
		matcher.find();
		String name = matcher.group(1);
		String owner = matcher.group(2);

		Set<DockingActionIf> actions = actionsByNameByOwner.get(owner).get(name);
		if (actions.isEmpty()) {
			// An empty actions list implies that the action changed in the options is a shared 
			// action or a system action.  Shared actions will update themselves.  Here we will 
			// handle system actions.
			DockingActionIf systemAction = keyBindingsManager.getSystemAction(optionName);
			if (systemAction != null) {
				KeyBindingData oldKbData = systemAction.getKeyBindingData();
				KeyBindingData newKbData = KeyBindingData.update(oldKbData, newTrigger);
				systemAction.setUnvalidatedKeyBindingData(newKbData);
			}
			return;
		}

		for (DockingActionIf action : actions) {
			KeyBindingData oldKbData = action.getKeyBindingData();
			KeyBindingData newKbData = KeyBindingData.update(oldKbData, newTrigger);
			action.setUnvalidatedKeyBindingData(newKbData);
		}
	}

	@Override
	public void propertyChange(PropertyChangeEvent evt) {
		if (!evt.getPropertyName().equals(DockingActionIf.KEYBINDING_DATA_PROPERTY)) {
			return;
		}

		DockingActionIf action = (DockingActionIf) evt.getSource();
		if (!action.getKeyBindingType().isManaged()) {
			// this reads unusually, but we need to notify the tool to rebuild its 'Window' menu
			// in the case that this action is one of the tool's special actions
			keyBindingsChanged();
			return;
		}

		//
		// Check to see if we need to update the options to reflect the change to the action's key 
		// binding data.
		//
		KeyBindingData newKeyBindingData = (KeyBindingData) evt.getNewValue();
		ActionTrigger newTrigger = null;
		if (newKeyBindingData != null) {
			newTrigger = newKeyBindingData.getActionTrigger();
		}

		ActionTrigger currentTrigger = options.getActionTrigger(action.getFullName(), null);
		if (!Objects.equals(currentTrigger, newTrigger)) {
			options.setActionTrigger(action.getFullName(), newTrigger);
			keyBindingsChanged();
		}
	}

	// triggered by a user-initiated action; called by propertyChange()
	private void keyBindingsChanged() {
		tool.setConfigChanged(true);
		actionGuiHelper.keyBindingsChanged();
	}

	@Override
	public DockingActionIf getLocalAction(ComponentProvider provider, String actionName) {

		Iterator<DockingActionIf> it = actionGuiHelper.getComponentActions(provider);
		while (it.hasNext()) {
			DockingActionIf action = it.next();
			if (action.getName().equals(actionName)) {
				return action;
			}
		}
		return null;
	}

	/**
	 * Checks whether the given key stroke can be used for the given action for restrictions such as
	 * those for System level actions.
	 * @param action the action; may be null
	 * @param ks the key stroke
	 * @return A null value if valid; a non-null error message if invalid
	 */
	public String validateActionKeyBinding(DockingActionIf action, KeyStroke ks) {
		return keyBindingsManager.validateActionKeyBinding(action, ks);
	}

	public Action getAction(KeyStroke ks) {
		return keyBindingsManager.getDockingAction(ks);
	}

	public Action getAction(MouseBinding mb) {
		return keyBindingsManager.getDockingAction(mb);
	}

	DockingActionIf getSharedStubKeyBindingAction(String name) {
		return sharedActionMap.get(name);
	}

	/**
	 * Allows clients to register an action by using a placeholder.  This is useful when
	 * an API wishes to have a central object (like a plugin) register actions for transient
	 * providers, that may not be loaded until needed.
	 *
	 * <p>This method may be called multiple times with the same conceptual placeholder--the
	 * placeholder will only be added once.
	 *
	 * @param placeholder the placeholder containing information related to the action it represents
	 */
	@Override
	public void registerSharedActionPlaceholder(SharedDockingActionPlaceholder placeholder) {

		String name = placeholder.getName();
		SharedStubKeyBindingAction stub = sharedActionMap.computeIfAbsent(name, key -> {

			ActionTrigger actionTrigger = getActionTrigger(placeholder);
			SharedStubKeyBindingAction newStub =
				new SharedStubKeyBindingAction(name, actionTrigger, options);
			registerStub(newStub, actionTrigger);
			return newStub;
		});

		String owner = placeholder.getOwner();
		stub.addActionOwner(owner);
	}

	private ActionTrigger getActionTrigger(SharedDockingActionPlaceholder placeholder) {
		KeyStroke defaultKs = placeholder.getKeyBinding();
		if (defaultKs != null) {
			return new ActionTrigger(defaultKs);
		}
		return null;
	}
}
