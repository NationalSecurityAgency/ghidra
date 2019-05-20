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

import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.DockingWindowManager;
import docking.action.*;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.util.Msg;
import utilities.util.reflection.ReflectionUtilities;

/**
 * A stub action that allows key bindings to be edited through the key bindings options.  This 
 * allows plugins to create actions that share keybindings without having to manage those 
 * keybindings themselves.
 * 
 * <p>Clients should not be using this class directly.
 */
class SharedStubKeyBindingAction extends DockingAction implements OptionsChangeListener {

	static final String SHARED_OWNER = "Tool";

	/*
	 * We save the client actions for later validate and options updating.  We also need the
	 * default key binding data, which is stored in the value of this map.
	 * 
	 * Note: This collection is weak; the actions will stay as long as they are 
	 * 		 registered in the tool.
	 */
	private WeakHashMap<DockingActionIf, KeyStroke> clientActions = new WeakHashMap<>();

	private ToolOptions keyBindingOptions;

	/**
	 * Creates a new dummy action by the given name and default keystroke value
	 * 
	 * @param name The name of the action--this will be displayed in the options as the name of
	 *             key binding's action
	 * @param options the tool's key binding options
	 */
	public SharedStubKeyBindingAction(String name, ToolOptions options) {
		super(name, SHARED_OWNER);
		this.keyBindingOptions = options;

		// Dummy keybinding actions don't have help--the real action does
		DockingWindowManager.getHelpService().excludeFromHelp(this);

		// A listener to keep the shared, stub keybindings in sync with their clients 
		options.addOptionsChangeListener(this);
	}

	void addClientAction(DockingActionIf action) {

		// 1) Validate new action keystroke against existing actions
		KeyStroke validatedKeyStroke = validateActionsHaveTheSameDefaultKeyStroke(action);

		// 2) Update the given action with the current option value.  This allows clients to 
		//    add and remove actions after the tool has been initialized.
		validatedKeyStroke = updateKeyStrokeFromOptions(validatedKeyStroke);

		clientActions.put(action, validatedKeyStroke);
	}

	private KeyStroke validateActionsHaveTheSameDefaultKeyStroke(DockingActionIf newAction) {

		// this value may be null
		KeyBindingData defaultBinding = newAction.getKeyBindingData();
		KeyStroke newDefaultKs = getKeyStroke(defaultBinding);

		Set<Entry<DockingActionIf, KeyStroke>> entries = clientActions.entrySet();
		for (Entry<DockingActionIf, KeyStroke> entry : entries) {
			DockingActionIf existingAction = entry.getKey();
			KeyStroke existingDefaultKs = entry.getValue();
			if (Objects.equals(existingDefaultKs, newDefaultKs)) {
				continue;
			}

			logDifferentKeyBindingsWarnigMessage(newAction, existingAction, existingDefaultKs);

			//
			// Not sure which keystroke to prefer here--keep the first one that was set
			//

			// set the new action's keystroke to be the winner
			newAction.setKeyBindingData(new KeyBindingData(existingDefaultKs));

			// one message is probably enough; 
			return existingDefaultKs;
		}

		return newDefaultKs;
	}

	private void logDifferentKeyBindingsWarnigMessage(DockingActionIf newAction,
			DockingActionIf existingAction, KeyStroke existingDefaultKs) {

		//@formatter:off
		String s = "Shared Key Binding Actions have different deafult values.  These " +
				"must be the same." +
				"\n\tAction 1: " + existingAction.getInceptionInformation() +
				"\n\t\tKey Binding: " + existingDefaultKs +
				"\n\tAction 2: " + newAction.getInceptionInformation() + 
				"\n\t\tKey Binding: " + newAction.getKeyBinding() +
				"\nUsing the " +
				"first value set - " + existingDefaultKs				
			;
		//@formatter:on

		Msg.warn(this, s, ReflectionUtilities.createJavaFilteredThrowable());
	}

	private KeyStroke updateKeyStrokeFromOptions(KeyStroke validatedKeyStroke) {
		return keyBindingOptions.getKeyStroke(getFullName(), validatedKeyStroke);
	}

	private KeyStroke getKeyStroke(KeyBindingData data) {
		if (data == null) {
			return null;
		}
		return data.getKeyBinding();
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {

		if (!optionName.startsWith(getName())) {
			return; // not my binding
		}

		KeyStroke newKs = (KeyStroke) newValue;
		for (DockingActionIf action : clientActions.keySet()) {

			// Note: update this to say why we are using the 'unvalidated' call instead of the
			//       setKeyBindingData() call
			action.setUnvalidatedKeyBindingData(new KeyBindingData(newKs));
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
}
