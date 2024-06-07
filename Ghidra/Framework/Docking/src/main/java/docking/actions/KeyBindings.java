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

import docking.Tool;
import docking.action.DockingActionIf;
import docking.action.KeyBindingData;
import docking.tool.util.DockingToolConstants;
import ghidra.framework.options.ActionTrigger;
import ghidra.framework.options.ToolOptions;
import gui.event.MouseBinding;
import util.CollectionUtils;

/**
 * An object that maps actions to key strokes and mouse bindings.
 * <p>
 * This class knows how to load all system actions and how to load any key and mouse bindings for
 * those actions from the tool's options.   Clients can make changes to the state of this class that
 * can then be applied to the system by calling {@link #applyChanges()}.
 */
public class KeyBindings {

	private Tool tool;
	private ToolOptions keyBindingOptions;

	// allows clients to populate a table of all actions
	private List<DockingActionIf> uniqueActions = new ArrayList<>();

	// allows clients to know if a given key stroke or mouse binding is in use
	private Map<KeyStroke, List<String>> actionNamesByKeyStroke = new HashMap<>();
	private Map<MouseBinding, String> actionNameByMouseBinding = new HashMap<>();

	// tracks all changes to an action's key stroke and mouse bindings, which allows us to apply
	// and restore options values
	private Map<String, ActionKeyBindingState> actionInfoByFullName = new HashMap<>();

	private String longestActionName = "";

	public KeyBindings(Tool tool) {
		this.tool = tool;

		keyBindingOptions = tool.getOptions(DockingToolConstants.KEY_BINDINGS);

		init();
	}

	public List<DockingActionIf> getUniqueActions() {
		return Collections.unmodifiableList(uniqueActions);
	}

	/* used for testing */
	public Map<String, KeyStroke> getKeyStrokesByFullActionName() {
		Map<String, KeyStroke> result = new HashMap<>();
		Set<Entry<String, ActionKeyBindingState>> entries = actionInfoByFullName.entrySet();
		for (Entry<String, ActionKeyBindingState> entry : entries) {
			String key = entry.getKey();
			KeyStroke value = entry.getValue().getCurrentKeyStroke();
			result.put(key, value);
		}
		return result;
	}

	public boolean containsAction(String fullName) {
		return actionInfoByFullName.containsKey(fullName);
	}

	public KeyStroke getKeyStroke(String fullName) {
		ActionKeyBindingState info = actionInfoByFullName.get(fullName);
		return info.getCurrentKeyStroke();
	}

	public MouseBinding getMouseBinding(String fullName) {
		ActionKeyBindingState info = actionInfoByFullName.get(fullName);
		return info.getCurrentMouseBinding();
	}

	public String getActionForMouseBinding(MouseBinding mouseBinding) {
		return actionNameByMouseBinding.get(mouseBinding);
	}

	public String getActionsForKeyStrokeText(KeyStroke keyStroke) {

		StringBuffer sb = new StringBuffer();
		List<String> names = actionNamesByKeyStroke.get(keyStroke);
		if (CollectionUtils.isBlank(names)) {
			return sb.toString();
		}

		names.sort((n1, n2) -> {
			return n1.compareToIgnoreCase(n2);
		});

		String ksName = KeyBindingUtils.parseKeyStroke(keyStroke);
		sb.append("Actions mapped to key " + ksName + ":\n");
		for (int i = 0; i < names.size(); i++) {
			sb.append("  ");

			String name = names.get(i);
			ActionKeyBindingState info = actionInfoByFullName.get(name);
			DockingActionIf action = info.getRepresentativeAction();
			String shortName = action.getName();
			sb.append(shortName);
			sb.append(" (").append(action.getOwnerDescription()).append(')');
			if (i < names.size() - 1) {
				sb.append("\n");
			}
		}
		return sb.toString();
	}

	public String getLongestActionName() {
		return longestActionName;
	}

	public boolean isMouseBindingInUse(String fullName, MouseBinding newBinding) {

		String existingName = actionNameByMouseBinding.get(newBinding);
		if (existingName == null || newBinding == null) {
			return false; // no new binding, or not in use
		}

		return !Objects.equals(existingName, fullName);
	}

	public boolean setActionMouseBinding(String fullName, MouseBinding newBinding) {

		MouseBinding currentBinding = getMouseBinding(fullName);
		if (currentBinding != null) {
			if (currentBinding.equals(newBinding)) {
				return false;
			}

			actionNameByMouseBinding.remove(currentBinding);
		}

		if (newBinding != null) {
			actionNameByMouseBinding.put(newBinding, fullName);
		}

		ActionKeyBindingState info = actionInfoByFullName.get(fullName);
		info.setCurrentMouseBinding(newBinding);
		return true;
	}

	public boolean setActionKeyStroke(String fullName, KeyStroke newKs) {
		String newKsName = KeyBindingUtils.parseKeyStroke(newKs);

		// remove old keystroke for action name
		KeyStroke currentKs = getKeyStroke(fullName);
		if (currentKs != null) {
			String currentName = KeyBindingUtils.parseKeyStroke(currentKs);
			if (currentName.equals(newKsName)) {
				return false;
			}
			removeFromKeyMap(fullName, currentKs);
		}
		addActionKeyStroke(fullName, newKs);

		ActionKeyBindingState info = actionInfoByFullName.get(fullName);
		info.setCurrentKeyStroke(newKs);
		return true;
	}

	public boolean removeKeyStroke(String fullName) {

		ActionKeyBindingState info = actionInfoByFullName.get(fullName);
		if (info == null) {
			return false; // not sure if this can happen
		}

		KeyStroke currentKeyStroke = info.getCurrentKeyStroke();
		if (currentKeyStroke == null) {
			return false; // nothing to remove; nothing has changed
		}

		removeFromKeyMap(fullName, currentKeyStroke);
		info.setCurrentKeyStroke(null);
		return true;
	}

	/**
	 * Restores the tool options key bindings to the default values originally loaded when the
	 * system started.
	 */
	public void restoreOptions() {
		for (ActionKeyBindingState info : actionInfoByFullName.values()) {
			info.restore(keyBindingOptions);
		}
	}

	/**
	 * Cancels any pending changes that have not yet been applied.
	 */
	public void cancelChanges() {
		for (ActionKeyBindingState info : actionInfoByFullName.values()) {
			info.cancelChanges();
		}
	}

	/**
	 * Applies any pending changes.
	 */
	public void applyChanges() {
		for (ActionKeyBindingState info : actionInfoByFullName.values()) {
			info.apply(keyBindingOptions);
		}
	}

	private void removeFromKeyMap(String actionName, KeyStroke ks) {
		if (ks == null) {
			return;
		}

		List<String> list = actionNamesByKeyStroke.get(ks);
		if (list != null) {
			list.remove(actionName);
			if (list.isEmpty()) {
				actionNamesByKeyStroke.remove(ks);
			}
		}
	}

	private void init() {

		actionInfoByFullName = new HashMap<>();

		Map<String, List<DockingActionIf>> actionsByFullName =
			KeyBindingUtils.getAllActionsByFullName(tool);
		Set<Entry<String, List<DockingActionIf>>> entries = actionsByFullName.entrySet();
		for (Entry<String, List<DockingActionIf>> entry : entries) {

			List<DockingActionIf> actions = entry.getValue();

			String fullName = entry.getKey();
			ActionTrigger trigger = keyBindingOptions.getActionTrigger(fullName, null);

			KeyStroke ks = null;
			MouseBinding mb = null;

			if (trigger != null) {
				ks = trigger.getKeyStroke();
				mb = trigger.getMouseBinding();
			}

			ActionKeyBindingState info = new ActionKeyBindingState(actions, ks, mb);
			actionInfoByFullName.put(fullName, info);

			uniqueActions.add(info.getRepresentativeAction());

			addActionKeyStroke(fullName, ks);

			String shortName = info.getShortName();
			if (shortName.length() > longestActionName.length()) {
				longestActionName = shortName;
			}
		}
	}

	private void addActionKeyStroke(String actionName, KeyStroke ks) {
		if (ks == null) {
			return;
		}

		List<String> list = actionNamesByKeyStroke.get(ks);
		if (list == null) {
			list = new ArrayList<>();
			actionNamesByKeyStroke.put(ks, list);
		}
		if (!list.contains(actionName)) {
			list.add(actionName);
		}
	}

	/**
	 * A class to store current and original values for key strokes and mouse bindings.  This is 
	 * used to apply changes and restore default values.
	 */
	private class ActionKeyBindingState {

		private List<DockingActionIf> actions = new ArrayList<>();
		private KeyStroke originalKeyStroke;
		private KeyStroke currentKeyStroke;
		private MouseBinding originalMouseBinding;
		private MouseBinding currentMouseBinding;

		ActionKeyBindingState(List<DockingActionIf> actions, KeyStroke ks, MouseBinding mb) {
			this.actions.addAll(actions);
			this.originalKeyStroke = ks;
			this.currentKeyStroke = ks;
			this.originalMouseBinding = mb;
			this.currentMouseBinding = mb;
		}

		public DockingActionIf getRepresentativeAction() {
			// pick one action, they are all conceptually the same
			return actions.get(0);
		}

		String getShortName() {
			// pick one action, they are all conceptually the same
			return actions.get(0).getName();
		}

		String getFullName() {
			return getRepresentativeAction().getFullName();
		}

		public MouseBinding getCurrentMouseBinding() {
			return currentMouseBinding;
		}

		public void setCurrentMouseBinding(MouseBinding newMouseBinding) {
			this.currentMouseBinding = newMouseBinding;
		}

		public KeyStroke getCurrentKeyStroke() {
			return currentKeyStroke;
		}

		public void setCurrentKeyStroke(KeyStroke newKeyStroke) {
			this.currentKeyStroke = newKeyStroke;
		}

		public void cancelChanges() {
			currentKeyStroke = originalKeyStroke;
			currentMouseBinding = originalMouseBinding;
		}

		public void apply(ToolOptions keyStrokeOptions) {
			if (!hasChanged()) {
				return;
			}

			KeyBindingData kbd = getCurrentKeyBindingData();
			apply(keyStrokeOptions, kbd);
		}

		private void apply(ToolOptions keyStrokeOptions, KeyBindingData keyBinding) {

			if (keyBinding == null) {
				// no bindings; bindings have been cleared
				for (DockingActionIf action : actions) {
					action.setUnvalidatedKeyBindingData(null);
				}
				return;
			}

			ActionTrigger newTrigger = keyBinding.getActionTrigger();
			String fullName = getFullName();
			keyStrokeOptions.setActionTrigger(fullName, newTrigger);
		}

		private boolean hasChanged() {
			return !Objects.equals(originalKeyStroke, currentKeyStroke) ||
				!Objects.equals(originalMouseBinding, currentMouseBinding);
		}

		private boolean matches(KeyBindingData kbData) {

			if (CollectionUtils.isAllNull(kbData, currentKeyStroke, currentMouseBinding)) {
				return true;
			}

			if (kbData == null) {
				return false;
			}

			KeyStroke otherKs = kbData.getKeyBinding();
			if (!Objects.equals(otherKs, currentKeyStroke)) {
				return false;
			}

			MouseBinding otherMb = kbData.getMouseBinding();
			return Objects.equals(otherMb, currentMouseBinding);
		}

		private KeyBindingData getCurrentKeyBindingData() {

			if (currentKeyStroke == null && currentMouseBinding == null) {
				return null; // the key binding data does not exist or has been cleared
			}

			DockingActionIf action = getRepresentativeAction();
			KeyBindingData kbData = action.getKeyBindingData();
			ActionTrigger trigger = new ActionTrigger(currentKeyStroke, currentMouseBinding);
			return KeyBindingData.update(kbData, trigger);
		}

		// restores the options to their default values
		public void restore(ToolOptions options) {
			DockingActionIf action = getRepresentativeAction();
			KeyBindingData defaultBinding = action.getDefaultKeyBindingData();

			if (!matches(defaultBinding)) {
				apply(options, defaultBinding);
			}

			cancelChanges();
		}

	}

}
