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

import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.collections4.Bag;
import org.apache.commons.collections4.bag.HashBag;
import org.apache.commons.lang3.StringUtils;

import docking.ActionContext;
import docking.DockingWindowManager;
import docking.action.*;
import docking.tool.ToolConstants;
import ghidra.framework.options.*;
import ghidra.util.Msg;
import utilities.util.reflection.ReflectionUtilities;

/**
 * A stub action that allows key bindings to be edited through the key bindings options.  This 
 * allows plugins to create actions that share keybindings without having to manage those 
 * keybindings themselves.
 * 
 * <p>Some ways this class is used:
 * <ol>
 * 	<li>As a central action to manage key bindings for multiple actions from different clients 
 *      (plugins) that are conceptually the same.  When the plugins are loaded 
 *      these actions get registered and are wired to listen to key binding changes to this stub. 
 * 	</li>
 *  <li>As a placeholder action to manage key bindings for actions that have not yet been 
 *      registered and may not get registered during the lifetime of a single tool session.
 *      This can happen when a plugin has transient component providers that only get shown
 *      upon a user request.  This stub allows the key binding for those actions to be managed,
 *      even if they do not get registered when the tool is shown.
 *  </li>
 * </ol>
 * 
 * <p>Clients should not be using this class directly.
 */
public class SharedStubKeyBindingAction extends DockingAction implements OptionsChangeListener {

	static final String SHARED_OWNER = ToolConstants.SHARED_OWNER;

	/**
	 * We save the client actions for later validate and options updating.  We also need the
	 * default key binding data, which is stored in the value of this map.
	 * 
	 * Note: This collection is weak; the actions will stay as long as they are 
	 * 		 registered in the tool.
	 */
	private WeakHashMap<DockingActionIf, ActionTrigger> clientActions = new WeakHashMap<>();

	private ToolOptions keyBindingOptions;
	private Bag<String> actionOwners = new HashBag<>();

	/**
	 * Creates a new dummy action by the given name and default keystroke value
	 * 
	 * @param name The name of the action--this will be displayed in the options as the name of
	 *             key binding's action
	 * @param defaultActionTrigger the default action trigger for this stub.  The action trigger 
	 *        will be validated each time an action is added to this stub to ensure that the 
	 *        defaults are in sync.
	 * @param options the tool's key binding options
	 */
	SharedStubKeyBindingAction(String name, ActionTrigger defaultActionTrigger,
			ToolOptions options) {
		// Note: we need to have this stub registered to use key bindings so that the options will
		//       restore the saved key binding to this class, which will then notify any of the
		//       shared actions using this stub.
		super(name, SHARED_OWNER, KeyBindingType.INDIVIDUAL);
		this.keyBindingOptions = options;

		// Dummy keybinding actions don't have help--the real action does
		DockingWindowManager.getHelpService().excludeFromHelp(this);

		setKeyBindingData(this, defaultActionTrigger);

		// A listener to keep the shared, stub keybindings in sync with their clients 
		options.addOptionsChangeListener(this);
	}

	/**
	 * Adds the given owner name to this stub.  This is used to display all known clients of
	 * the action represented by this stub.  Normally, when this class has actions, the names
	 * of each action's owner would be used directly.  However, this class can also be used as 
	 * a placeholder, when no actions have yet been registered.  In that case, the owner has 
	 * to be set directly on this stub.
	 *  
	 * @param owner the name of the client that owns the actions that may get registered with
	 *        this stub
	 */
	void addActionOwner(String owner) {
		if (DockingWindowManager.DOCKING_WINDOWS_OWNER.equals(owner)) {
			// Special case: special system-level action owner; the user does not need to see
			return;
		}
		actionOwners.add(owner);
	}

	void removeClientAction(DockingActionIf action) {
		clientActions.remove(action);
		actionOwners.remove(action.getOwner());
	}

	void addClientAction(DockingActionIf action) {

		// 1) Validate new action keystroke against existing actions
		ActionTrigger defaultKs = validateActionsHaveTheSameDefaultKeyStroke(action);

		// 2) Add the action and the validated keystroke, as this is the default keystroke
		clientActions.put(action, defaultKs);

		// 3) Update the given action with the current option value.  This allows clients to 
		//    add and remove actions after the tool has been initialized.
		updateActionKeyStrokeFromOptions(action, defaultKs);
	}

	@Override
	public String getOwnerDescription() {
		List<String> owners = new LinkedList<>(actionOwners.uniqueSet());
		if (owners.size() == 1) {
			return owners.get(0);
		}

		boolean hasTool = owners.remove(SHARED_OWNER);
		Collections.sort(owners);
		if (hasTool) {
			owners.add(0, SHARED_OWNER);
		}

		return StringUtils.join(owners, ", ");
	}

	@Override
	public String getDescription() {

		Set<DockingActionIf> actions = clientActions.keySet();
		for (DockingActionIf action : actions) {
			String description = action.getDescription();
			if (!StringUtils.isBlank(description)) {
				return description;
			}
		}

		return super.getDescription();
	}

	private ActionTrigger validateActionsHaveTheSameDefaultKeyStroke(DockingActionIf newAction) {

		// this value may be null
		KeyBindingData defaultBinding = newAction.getDefaultKeyBindingData();
		ActionTrigger newDefaulTrigger = getActionTrigger(defaultBinding);

		Set<Entry<DockingActionIf, ActionTrigger>> entries = clientActions.entrySet();
		for (Entry<DockingActionIf, ActionTrigger> entry : entries) {
			DockingActionIf existingAction = entry.getKey();
			ActionTrigger existingDefaultTrigger = entry.getValue();
			if (Objects.equals(existingDefaultTrigger, newDefaulTrigger)) {
				continue;
			}

			logDifferentKeyBindingsWarnigMessage(newAction, existingAction, existingDefaultTrigger);

			//
			// Not sure which keystroke to prefer here--keep the first one that was set
			//

			// set the existing action's keystroke to be the winner
			newAction.setKeyBindingData(existingAction.getKeyBindingData());

			// one message is probably enough; 
			return existingDefaultTrigger;
		}

		return newDefaulTrigger;
	}

	private void updateActionKeyStrokeFromOptions(DockingActionIf action,
			ActionTrigger defaultTrigger) {

		ActionTrigger stubTrigger = defaultTrigger;
		ActionTrigger optionsTrigger = getActionTriggerFromOptions(defaultTrigger);
		if (!Objects.equals(defaultTrigger, optionsTrigger)) {
			setKeyBindingData(action, optionsTrigger);
			stubTrigger = optionsTrigger;
		}

		setKeyBindingData(this, stubTrigger);
	}

	private void setKeyBindingData(DockingActionIf action, ActionTrigger actionTrigger) {
		KeyBindingData kbData = null;
		if (actionTrigger != null) {
			kbData = new KeyBindingData(actionTrigger);
		}

		// we use the 'unvalidated' call since this value is provided by the user--we assume
		// that user input is correct; we only validate programmer input
		action.setUnvalidatedKeyBindingData(kbData);
	}

	private ActionTrigger getActionTriggerFromOptions(ActionTrigger validatedTrigger) {
		return keyBindingOptions.getActionTrigger(getFullName(), validatedTrigger);
	}

	private ActionTrigger getActionTrigger(KeyBindingData data) {
		if (data == null) {
			return null;
		}
		return data.getActionTrigger();
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {

		if (!optionName.equals(getFullName())) {
			return; // not my binding
		}

		ActionTrigger newTrigger = (ActionTrigger) newValue;
		setKeyBindingData(this, newTrigger);

		for (DockingActionIf action : clientActions.keySet()) {
			setKeyBindingData(action, newTrigger);
		}
	}

	@Override
	public void actionPerformed(ActionContext context) {
		// no-op; this is a dummy!
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return false;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return false;
	}

	@Override
	public void dispose() {
		super.dispose();
		clientActions.clear();
		keyBindingOptions.removeOptionsChangeListener(this);
	}

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

		Msg.warn(SharedStubKeyBindingAction.class, s,
			ReflectionUtilities.createJavaFilteredThrowable());
	}
}
