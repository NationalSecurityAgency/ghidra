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

import java.awt.event.ActionEvent;
import java.util.*;

import javax.swing.*;

import docking.*;
import docking.actions.KeyBindingUtils;
import ghidra.util.Swing;

/**
 * Action that manages multiple PluginActions mapped to this action's key binding.
 */
public class MultipleKeyAction extends DockingKeyBindingAction {
	private List<ActionData> actions = new ArrayList<>();

	private MultiActionDialog dialog;

	/**
	 * Creates new MultipleKeyAction
	 *
	 * @param tool used to determine context
	 * @param provider the provider, if any, associated with the action
	 * @param action action that will be added to the list of actions bound to a keystroke
	 * @param keyStroke the keystroke, if any, associated with the action
	 */
	public MultipleKeyAction(Tool tool, ComponentProvider provider, DockingActionIf action,
			KeyStroke keyStroke) {
		super(tool, action, keyStroke);
		addAction(provider, action);
	}

	public boolean isEmpty() {
		return actions.isEmpty();
	}

	public void addAction(ComponentProvider provider, DockingActionIf action) {

		for (ActionData actionData : actions) {
			if (actionData.action.equals(action)) {
				return;
			}
		}

		KeyStroke keyBinding = action.getKeyBinding();
		if (!keyStroke.equals(keyBinding)) {
			throw new IllegalArgumentException(
				"KeyStrokes don't match - was: " + keyStroke + " new: " + keyBinding);
		}

		actions.add(new ActionData(action, provider));
	}

	public void removeAction(DockingActionIf action) {
		Iterator<ActionData> iterator = actions.iterator();
		while (iterator.hasNext()) {
			ActionData actionData = iterator.next();
			if (actionData.action == action) {
				iterator.remove();
				return;
			}
		}
	}

	/**
	 * Returns the enabled state of the <code>Action</code>. When enabled,
	 * any component associated with this object is active and
	 * able to fire this object's <code>actionPerformed</code> method.
	 *
	 * @return true if this <code>Action</code> is enabled
	 */
	@Override
	public boolean isEnabled() {
		// always return true so we can report the status message
		// when none of the actions is enabled...
		return true;
	}

	/**
	 * Enables or disables the action.  This affects all uses
	 * of the action.  Note that for popups, this affects whether or
	 * not the option is "grayed out", not whether the action is added
	 * to the popup.
	 *
	 * @param newValue  true to enable the action, false to
	 *                  disable it
	 * @see Action#setEnabled
	 */
	@Override
	public synchronized void setEnabled(boolean newValue) {
		if (newValue != enabled) {
			boolean oldValue = this.enabled;
			this.enabled = newValue;
			firePropertyChange("enabled", Boolean.valueOf(oldValue), Boolean.valueOf(newValue));
		}
	}

	/**
	 * Invoked when an action occurs.
	 */
	@Override
	public void actionPerformed(final ActionEvent event) {
		// Build list of actions which are valid in current context
		ComponentProvider localProvider = tool.getActiveComponentProvider();
		ActionContext localContext = getLocalContext(localProvider);
		localContext.setSourceObject(event.getSource());

		List<ExecutableKeyActionAdapter> list = getValidContextActions(localContext);

		// If menu active, disable all key bindings
		if (ignoreActionWhileMenuShowing()) {
			return;
		}

		// If more than one action, prompt user for selection
		if (list.size() > 1) {
			// popup dialog to show multiple actions
			if (dialog == null) {
				dialog = new MultiActionDialog(KeyBindingUtils.parseKeyStroke(keyStroke), list);
			}
			else {
				dialog.setActionList(list);
			}

			// doing the show in an invoke later seems to fix a strange swing bug that lock up 
			// the program if you tried to invoke a new action too quickly after invoking
			// it the first time
			Swing.runLater(() -> DockingWindowManager.showDialog(dialog));
		}
		else if (list.size() == 1) {
			final ExecutableKeyActionAdapter actionProxy = list.get(0);
			tool.setStatusInfo("");
			actionProxy.execute();
		}
		else {
			String name = (String) getValue(Action.NAME);
			tool.setStatusInfo("Action (" + name + ") not valid in this context!", true);
		}
	}

	private boolean ignoreActionWhileMenuShowing() {
		if (getKeyBindingPrecedence() == KeyBindingPrecedence.ReservedActionsLevel) {
			return false; // allow reserved bindings through "no matter what!"
		}

		MenuSelectionManager menuManager = MenuSelectionManager.defaultManager();
		return menuManager.getSelectedPath().length != 0;
	}

	private List<ExecutableKeyActionAdapter> getValidContextActions(ActionContext localContext) {
		List<ExecutableKeyActionAdapter> list = new ArrayList<>();
		boolean hasLocalActionsForKeyBinding = false;

		// 
		// 1) Prefer local actions for the active provider
		// 
		for (ActionData actionData : actions) {
			if (actionData.isMyProvider(localContext)) {
				hasLocalActionsForKeyBinding = true;
				if (isValidAndEnabled(actionData, localContext)) {
					list.add(new ExecutableKeyActionAdapter(actionData.action, localContext));
				}
			}
		}

		if (hasLocalActionsForKeyBinding) {
			// We have locals, ignore the globals.  This prevents global actions from processing
			// the given keybinding when a local action exits, regardless of enablement.
			return list;
		}

		//
		// 2) Check for actions local to the source component 
		// 
		for (ActionData actionData : actions) {
			if (!(actionData.action instanceof ComponentBasedDockingAction)) {
				continue;
			}

			ComponentBasedDockingAction componentAction =
				(ComponentBasedDockingAction) actionData.action;
			if (componentAction.isValidComponentContext(localContext)) {
				hasLocalActionsForKeyBinding = true;
				if (isValidAndEnabled(actionData, localContext)) {
					list.add(new ExecutableKeyActionAdapter(actionData.action, localContext));
				}
			}
		}

		if (hasLocalActionsForKeyBinding) {
			// We have locals, ignore the globals.  This prevents global actions from processing
			// the given keybinding when a local action exits, regardless of enablement.
			return list;
		}

		// 
		// 3) Check for global actions
		// 
		for (ActionData actionData : actions) {
			if (actionData.isGlobalAction()) {
				// When looking for context matches, we prefer local context, even though this
				// is a 'global' action.  This allows more specific context to be used when
				// available
				if (isValidAndEnabled(actionData, localContext)) {
					list.add(new ExecutableKeyActionAdapter(actionData.action, localContext));
				}
			}
		}
		return list;
	}

	private boolean isValidAndEnabled(ActionData actionData, ActionContext localContext) {
		DockingActionIf a = actionData.action;
		return a.isValidContext(localContext) && a.isEnabledForContext(localContext);
	}

	@Override
	public boolean isReservedKeybindingPrecedence() {
		return false; // MultipleKeyActions can never be reserved 
	}

	@Override
	public KeyBindingPrecedence getKeyBindingPrecedence() {
		ComponentProvider localProvider = tool.getActiveComponentProvider();
		ActionContext localContext = getLocalContext(localProvider);
		List<ExecutableKeyActionAdapter> validActions = getValidContextActions(localContext);

		if (validActions.isEmpty()) {
			return null; // a signal that no actions are valid for the current context
		}

		if (validActions.size() != 1) {
			return KeyBindingPrecedence.DefaultLevel;
		}

		ExecutableKeyActionAdapter actionProxy = validActions.get(0);
		DockingActionIf action = actionProxy.getAction();
		return action.getKeyBindingData().getKeyBindingPrecedence();
	}

	public List<DockingActionIf> getActions() {
		List<DockingActionIf> list = new ArrayList<>(actions.size());
		for (ActionData actionData : actions) {
			list.add(actionData.action);
		}
		return list;
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + " [\n\t" + getKeyBindingsAsString() + "\n]";
	}

	private String getKeyBindingsAsString() {
		StringBuilder buildy = new StringBuilder();
		for (ActionData data : actions) {
			buildy.append(data.action.toString()).append("\n\t");
		}

		if (actions.size() > 0) {
			buildy.delete(buildy.length() - 2, buildy.length()); // trim off newline and tab
		}

		return buildy.toString();
	}

	private class ActionData {
		DockingActionIf action;
		ComponentProvider provider;

		ActionData(DockingActionIf action, ComponentProvider provider) {
			this.action = action;
			this.provider = provider;
		}

		boolean isGlobalAction() {
			return provider == null;
		}

		boolean isMyProvider(ActionContext localContext) {
			ComponentProvider otherProvider = localContext.getComponentProvider();
			return provider == otherProvider;
		}

		@Override
		public String toString() {
			String providerString = provider == null ? "" : provider.toString() + " - ";
			return providerString + action;
		}
	}
}
