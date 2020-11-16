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

import java.awt.Component;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.util.*;

import javax.swing.*;

import docking.*;
import docking.actions.KeyBindingUtils;
import generic.util.WindowUtilities;
import ghidra.util.Swing;

/**
 * Action that manages multiple {@link DockingAction}s mapped to a given key binding
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
		// always return true so we can report the status message when all actions are disabled
		return true;
	}

	/**
	 * Enables or disables the action.  This affects all uses of the action.  Note that for popups, 
	 * this affects whether or not the option is "grayed out", not whether the action is added
	 * to the popup.
	 *
	 * @param newValue  true to enable the action, false to disable it
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

	@Override
	public void actionPerformed(final ActionEvent event) {
		// Build list of actions which are valid in current context
		List<ExecutableAction> list = getActionsForCurrentOrDefaultContext(event.getSource());

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
			ExecutableAction actionProxy = list.get(0);
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

	private List<ExecutableAction> getValidContextActions(ActionContext localContext,
			ActionContext globalContext) {
		List<ExecutableAction> list = new ArrayList<>();
		boolean hasLocalActionsForKeyBinding = false;

		// 
		// 1) Prefer local actions for the active provider
		// 
		for (ActionData actionData : actions) {
			if (actionData.isMyProvider(localContext)) {
				hasLocalActionsForKeyBinding = true;
				if (isValidAndEnabled(actionData, localContext)) {
					list.add(new ExecutableAction(actionData.action, localContext));
				}
			}
		}

		if (hasLocalActionsForKeyBinding) {
			// At this point, we have local actions that may or may not be enabled. Return here
			// so that any component specific actions found below will not interfere with the 
			// provider's local actions
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
					list.add(new ExecutableAction(actionData.action, localContext));
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
					list.add(new ExecutableAction(actionData.action, localContext));
				}
				else if (isValidAndEnabledGlobally(actionData, globalContext)) {
					list.add(new ExecutableAction(actionData.action, globalContext));
				}
			}
		}
		return list;
	}

	private boolean isValidAndEnabled(ActionData actionData, ActionContext context) {
		DockingActionIf a = actionData.action;
		return a.isValidContext(context) && a.isEnabledForContext(context);
	}

	private boolean isValidAndEnabledGlobally(ActionData actionData, ActionContext context) {
		// the context may be null when we don't want global action such as when getting actions
		// for a dialog
		if (context == null) {
			return false;
		}
		return actionData.supportsDefaultToolContext() && isValidAndEnabled(actionData, context);
	}

	@Override
	public boolean isReservedKeybindingPrecedence() {
		return false; // MultipleKeyActions can never be reserved 
	}

	@Override
	public KeyBindingPrecedence getKeyBindingPrecedence() {
		return geValidKeyBindingPrecedence(null);
	}

	/**
	 * This is a special version of {@link #getKeyBindingPrecedence()} that allows the internal
	 * key event processing to specify the source component when determining how precedence should
	 * be established for the actions contained herein.
	 * @param source the component; may be null
	 * @return the precedence; may be null
	 */
	public KeyBindingPrecedence geValidKeyBindingPrecedence(Component source) {

		List<ExecutableAction> validActions = getActionsForCurrentOrDefaultContext(source);
		if (validActions.isEmpty()) {
			return null; // a signal that no actions are valid for the current context
		}

		if (validActions.size() != 1) {
			return KeyBindingPrecedence.DefaultLevel;
		}

		ExecutableAction actionProxy = validActions.get(0);
		DockingActionIf action = actionProxy.getAction();
		return action.getKeyBindingData().getKeyBindingPrecedence();
	}

	private List<ExecutableAction> getActionsForCurrentOrDefaultContext(Object eventSource) {

		DockingWindowManager dwm = tool.getWindowManager();
		Window window = getWindow(dwm, eventSource);
		if (window instanceof DockingDialog) {
			return getDialogActions(window);
		}

		ComponentProvider localProvider = getProvider(dwm, eventSource);
		ActionContext localContext = getLocalContext(localProvider);
		localContext.setSourceObject(eventSource);
		ActionContext globalContext = tool.getDefaultToolContext();
		List<ExecutableAction> validActions = getValidContextActions(localContext, globalContext);
		return validActions;
	}

	private List<ExecutableAction> getDialogActions(Window window) {
		DockingDialog dockingDialog = (DockingDialog) window;
		DialogComponentProvider provider = dockingDialog.getDialogComponent();
		if (provider == null) {
			// this can happen if the dialog is closed during key event processing
			return Collections.emptyList();
		}
		ActionContext context = provider.getActionContext(null);
		List<ExecutableAction> validActions = getValidContextActions(context, null);
		return validActions;
	}

	private ComponentProvider getProvider(DockingWindowManager dwm, Object eventSource) {
		if (eventSource instanceof Component) {
			return dwm.getProvider((Component) eventSource);
		}
		return dwm.getActiveComponentProvider();
	}

	private Window getWindow(DockingWindowManager dwm, Object eventSource) {
		if (eventSource instanceof Component) {
			return WindowUtilities.windowForComponent((Component) eventSource);
		}
		return dwm.getActiveWindow();
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

		boolean supportsDefaultToolContext() {
			return action.supportsDefaultToolContext();
		}

		@Override
		public String toString() {
			String providerString = provider == null ? "" : provider.toString() + " - ";
			return providerString + action;
		}

	}
}
