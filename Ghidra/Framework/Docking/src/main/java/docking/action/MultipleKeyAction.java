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

import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.*;
import java.util.List;

import javax.help.UnsupportedOperationException;
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
	public void actionPerformed(ActionEvent event) {
		// A vestige from when we used to send this class through the Swing API.  Execution is now
		// done on the ExecutableAction this class creates.
		throw new UnsupportedOperationException();
	}

	private boolean ignoreActionWhileMenuShowing(ExecutableAction action) {

		KeyBindingPrecedence precedence = action.getKeyBindingPrecedence();
		if (precedence == KeyBindingPrecedence.SystemActionsLevel) {
			// Allow system bindings through.  This allows actions like Help to work for menus.
			return false;
		}

		MenuSelectionManager menuManager = MenuSelectionManager.defaultManager();
		return menuManager.getSelectedPath().length != 0;
	}

	private ExecutableAction createNonDialogExecutableAction(ActionContext localContext,
			Map<Class<? extends ActionContext>, ActionContext> contextMap) {

		MultiExecutableAction multiAction = new MultiExecutableAction();

		//
		// 1) Prefer local actions for the active provider
		//
		getLocalContextActions(localContext, multiAction);
		if (multiAction.isValid()) {
			// At this point, we have local docking actions that may or may not be enabled. Exit 
			// so that any component specific actions or global found below will not interfere with 
			// the provider's local actions
			return multiAction;
		}

		//
		// 2) Check for actions local to the source component (e.g., GTable and GTree)
		//
		getLocalComponentActions(localContext, multiAction);
		if (multiAction.isValid()) {
			// At this point, we have local component actions that may or may not be enabled. Exit
			// so that any global actions found below will not interfere with these component 
			// actions.
			return multiAction;
		}

		//
		// 3) Check for global actions using the current context 
		//
		getGlobalActions(localContext, multiAction);
		if (multiAction.isValid()) {
			// We have found global actions that are valid for the current local context.  Do not
			// also look for global actions that work for the default context.
			return multiAction;
		}

		//
		// 4) Check for global actions using the default context.  This is a final fallback to allow
		//    global actions to work that are unrelated to the current active component's context.
		// 
		getGlobalDefaultContextActions(contextMap, multiAction);
		return multiAction;
	}

	private void getLocalContextActions(ActionContext localContext,
			MultiExecutableAction multiAction) {

		for (ActionData actionData : actions) {
			if (!actionData.isMyProvider(localContext)) {
				continue;
			}

			if (!isValid(actionData, localContext)) {
				continue;
			}

			multiAction.setLocal(true);
			multiAction.setContext(localContext);
			multiAction.addValidAction(actionData.action);

			if (isEnabled(actionData, localContext)) {
				multiAction.addEnabledAction(actionData.action);
			}
		}
	}

	private void getLocalComponentActions(ActionContext localContext,
			MultiExecutableAction multiAction) {

		for (ActionData actionData : actions) {
			if (!(actionData.action instanceof ComponentBasedDockingAction componentAction)) {
				continue;
			}

			if (!componentAction.isValidComponentContext(localContext)) {
				continue;
			}

			multiAction.setContext(localContext);
			multiAction.addValidAction(actionData.action);

			if (isEnabled(actionData, localContext)) {
				multiAction.addEnabledAction(actionData.action);
			}
		}
	}

	private void getGlobalActions(ActionContext localContext,
			MultiExecutableAction multiAction) {

		for (ActionData actionData : actions) {
			if (!actionData.isGlobalAction()) {
				continue;
			}

			// When looking for context matches, we prefer local context, even though this
			// is a 'global' action.  This allows more specific context to be used when available
			if (!isValid(actionData, localContext)) {
				continue;
			}

			multiAction.setContext(localContext);
			multiAction.addValidAction(actionData.action);

			if (isEnabled(actionData, localContext)) {
				multiAction.addEnabledAction(actionData.action);
			}
		}
	}

	private void getGlobalDefaultContextActions(
			Map<Class<? extends ActionContext>, ActionContext> contextMap,
			MultiExecutableAction multiAction) {

		for (ActionData actionData : actions) {
			if (!actionData.isGlobalAction()) {
				continue;
			}

			if (!actionData.supportsDefaultContext()) {
				continue;
			}

			ActionContext defaultContext = contextMap.get(actionData.getContextType());
			if (!isValid(actionData, defaultContext)) {
				continue;
			}

			multiAction.setContext(defaultContext);
			multiAction.addValidAction(actionData.action);

			if (isEnabled(actionData, defaultContext)) {
				multiAction.addEnabledAction(actionData.action);
			}
		}
	}

	private boolean isValid(ActionData actionData, ActionContext context) {
		if (context == null) {
			return false;
		}
		DockingActionIf a = actionData.action;
		return a.isValidContext(context);
	}

	private boolean isEnabled(ActionData actionData, ActionContext context) {
		if (context == null) {
			return false;
		}
		DockingActionIf a = actionData.action;
		return a.isEnabledForContext(context);
	}

	@Override
	public boolean isSystemKeybindingPrecedence() {
		return false; // MultipleKeyActions can never be 'system' 
	}

	@Override
	public ExecutableAction getExecutableAction(Component source) {
		ExecutableAction action = createExecutableAction(source);

		// If menu active, disable all default key bindings
		if (ignoreActionWhileMenuShowing(action)) {
			return new MultiExecutableAction();
		}

		return action;
	}

	private ExecutableAction createExecutableAction(Object eventSource) {

		DockingWindowManager dwm = tool.getWindowManager();
		Window window = getWindow(dwm, eventSource);
		if (window instanceof DockingDialog) {
			return createDialogActions(eventSource, window);
		}

		ComponentProvider localProvider = getProvider(dwm, eventSource);
		ActionContext localContext = getLocalContext(localProvider);
		localContext.setSourceObject(eventSource);
		Map<Class<? extends ActionContext>, ActionContext> contextMap =
			dwm.getDefaultActionContextMap();
		return createNonDialogExecutableAction(localContext, contextMap);
	}

	private ExecutableAction createDialogActions(Object eventSource, Window window) {

		MultiExecutableAction multiAction = new MultiExecutableAction();

		DockingDialog dockingDialog = (DockingDialog) window;
		DialogComponentProvider provider = dockingDialog.getDialogComponent();
		if (provider == null) {
			// this can happen if the dialog is closed during key event processing
			return multiAction;
		}

		ActionContext context = provider.getActionContext(null);
		if (context == null) {
			return multiAction;
		}

		//
		// 1) Check for local actions
		//
		// Note: dialog key binding actions are proxy actions that get added to the tool as global
		// actions.  Thus, there are no 'local' actions for the dialog.

		//
		// 2) Check for actions local to the source component (e.g., GTable and GTree)
		//
		getLocalComponentActions(context, multiAction);
		if (multiAction.isValid()) {
			// At this point, we have local component actions that may or may not be enabled. Exit
			// so that any global actions found below will not interfere with these component 
			// actions.
			return multiAction;
		}

		//
		// 3) Check for global actions using the current context.  As noted above, at the time of 
		//    writing, dialog actions are all registered at the global level.
		//
		getGlobalActions(context, multiAction);

		// The choice to ignore global actions for modal dialogs was made long ago.  We cannot 
		// remember why the choice was made, but speculate that odd things can happen when 
		// keybindings are processed with modal dialogs open.  For now, do not let non-dialog 
		// actions get processed for modal dialogs.  This can be changed in the future if needed.
		if (provider.isModal()) {
			multiAction.filterAndKeepOnlyDialogActions(provider);
		}

		// Note: we currently do not use *default* global actions in dialogs.  It is not clear if 
		// this decision was intentional.		
		// if (!provider.isModal()) {
		//	  getGlobalDefaultContextActions(...);
		// }

		return multiAction;
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

	@Override
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

		public Class<? extends ActionContext> getContextType() {
			return action.getContextClass();
		}

		public boolean supportsDefaultContext() {
			return action.supportsDefaultContext();
		}

		boolean isGlobalAction() {
			return provider == null;
		}

		boolean isMyProvider(ActionContext localContext) {
			if (provider == null) {
				return false;
			}
			ComponentProvider otherProvider = localContext.getComponentProvider();
			return provider == otherProvider;
		}

		@Override
		public String toString() {
			String providerString = provider == null ? "" : provider.toString() + " - ";
			return providerString + action;
		}
	}

	/**
	 * An extension of {@link ExecutableAction} that itself contains 0 or more 
	 * {@link ExecutableAction}s.  This class is used to create a snapshot of all actions valid and
	 * enabled for a given keystroke.
	 */
	private class MultiExecutableAction implements ExecutableAction {

		private List<DockingActionIf> validActions = new ArrayList<>();
		private List<DockingActionIf> enabledActions = new ArrayList<>();

		private ActionContext context;
		private boolean isLocalAction;

		@Override
		public void execute() {

			if (enabledActions.size() == 1) {
				DockingActionIf action = enabledActions.get(0);
				tool.setStatusInfo("");

				// Toggle actions do not toggle its state directly therefor we have to do it for 
				// them before we execute the action.
				if (action instanceof ToggleDockingActionIf) {
					ToggleDockingActionIf toggleAction = (ToggleDockingActionIf) action;
					toggleAction.setSelected(!toggleAction.isSelected());
				}

				action.actionPerformed(context);

				return;
			}

			// If more than one action, prompt user to choose from multiple actions
			MultiActionDialog dialog =
				new MultiActionDialog(KeyBindingUtils.parseKeyStroke(keyStroke), enabledActions,
					context);

			// doing the show in an invoke later seems to fix a strange swing bug that lock up
			// the program if you tried to invoke a new action too quickly after invoking
			// it the first time
			Swing.runLater(() -> DockingWindowManager.showDialog(dialog));
		}

		@Override
		public KeyBindingPrecedence getKeyBindingPrecedence() {
			KeyBindingPrecedence precedence = KeyBindingPrecedence.DefaultLevel;
			if (enabledActions.size() == 1) {
				DockingActionIf action = enabledActions.get(0);
				precedence = action.getKeyBindingData().getKeyBindingPrecedence();
			}
			return precedence;
		}

		@Override
		public boolean isValid() {
			return !validActions.isEmpty();
		}

		@Override
		public boolean isEnabled() {
			return !enabledActions.isEmpty();
		}

		void setLocal(boolean isLocal) {
			this.isLocalAction = isLocal;
		}

		void setContext(ActionContext context) {
			if (this.context != null && this.context != context) {
				throw new IllegalArgumentException("Context cannot be changed once set");
			}
			this.context = context;
		}

		void addValidAction(DockingActionIf a) {
			validActions.add(a);
		}

		void addEnabledAction(DockingActionIf a) {
			enabledActions.add(a);
		}

		/**
		 * Keeps only those actions in the list that are owned by the given dialog provider
		 * @param provider the provider
		 */
		void filterAndKeepOnlyDialogActions(DialogComponentProvider provider) {

			Iterator<DockingActionIf> it = validActions.iterator();
			while (it.hasNext()) {
				DockingActionIf action = it.next();
				if (!provider.isDialogKeyBindingAction(action)) {
					it.remove();
					enabledActions.remove(action);
				}
			}
		}

		private String getContextText(Component focusOwner) {
			DockingWindowManager dwm = tool.getWindowManager();
			Window window = getWindow(dwm, focusOwner);
			if (window instanceof DockingDialog) {
				return "in this dialog";
			}

			if (!isLocalAction) {
				// no need to warn about global/default actions, as that may be annoying when the 
				// keystrokes bubble up to the global level
				return null;
			}

			ComponentProvider provider = context.getComponentProvider();
			if (provider != null) {
				return "in " + provider.getName();
			}

			return "for context";
		}

		@Override
		public void reportNotEnabled(Component focusOwner) {

			String contextText = getContextText(focusOwner);
			if (contextText == null) {
				return;
			}

			DockingActionIf action = validActions.get(0);
			String actionName = action.getName();
			String ksText = KeyBindingUtils.parseKeyStroke(keyStroke);
			String message =
				"'%s' (%s) not currently enabled %s".formatted(actionName, ksText, contextText);
			tool.setStatusInfo(message, true);
			Toolkit.getDefaultToolkit().beep();
		}

		@Override
		public String toString() {
			return getClass().getSimpleName() + ": " + validActions;
		}
	}
}
