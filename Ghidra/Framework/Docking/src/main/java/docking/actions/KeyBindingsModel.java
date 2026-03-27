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
import java.util.stream.Collectors;

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
 * An object that maps actions to key strokes and mouse bindings.  This class loads key bindings 
 * from tool options.  Clients can use this model to manage the values of each binding until the 
 * user is done editing the bindings.  When the client is finished, the bindings changes can be:
 * applied, ignored or restored to default settings.
 * <p>
 * This class knows how to load all system actions and how to load any key and mouse bindings for
 * those actions from the tool's options.   Clients can make changes to the state of this class that
 * can then be applied to the system by calling {@link #applyChanges()}.
 */
public class KeyBindingsModel {

	private Tool tool;
	private ToolOptions keyBindingOptions;

	// allows clients to know if a given key stroke or mouse binding is in use
	private Map<KeyStroke, List<String>> actionNamesByKeyStroke = new HashMap<>();
	private Map<MouseBinding, String> actionNameByMouseBinding = new HashMap<>();

	// tracks all changes to an action's key stroke and mouse bindings, which allows us to apply
	// and restore options values
	private Map<String, KeyBindingState> actionInfoByFullName = new HashMap<>();

	private String longestActionName = "";

	public KeyBindingsModel(Tool tool) {
		this.tool = tool;

		keyBindingOptions = tool.getOptions(DockingToolConstants.KEY_BINDINGS);

		init();
	}

	public List<ActionBindingsDescriptor> getActionBindings() {

		return actionInfoByFullName.values()
				.stream()
				.map(state -> (ActionBindingsDescriptor) state)
				.collect(Collectors.toList());
	}

	/* used for testing */
	public Map<String, KeyStroke> getKeyStrokesByFullActionName() {
		Map<String, KeyStroke> result = new HashMap<>();
		Set<Entry<String, KeyBindingState>> entries = actionInfoByFullName.entrySet();
		for (Entry<String, KeyBindingState> entry : entries) {
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
		KeyBindingState info = actionInfoByFullName.get(fullName);
		return info.getCurrentKeyStroke();
	}

	public MouseBinding getMouseBinding(String fullName) {
		KeyBindingState info = actionInfoByFullName.get(fullName);
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
			KeyBindingState state = actionInfoByFullName.get(name);
			String fullName = state.getFullName();
			sb.append(fullName);
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

		KeyBindingState info = actionInfoByFullName.get(fullName);
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

		KeyBindingState info = actionInfoByFullName.get(fullName);
		info.setCurrentKeyStroke(newKs);
		return true;
	}

	public boolean removeKeyStroke(String fullName) {

		KeyBindingState info = actionInfoByFullName.get(fullName);
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
		for (KeyBindingState info : actionInfoByFullName.values()) {
			info.restore(keyBindingOptions);
		}
	}

	/**
	 * Cancels any pending changes that have not yet been applied.
	 */
	public void cancelChanges() {
		for (KeyBindingState info : actionInfoByFullName.values()) {
			info.clearChanges();
		}
	}

	/**
	 * Applies any pending changes.
	 */
	public void applyChanges() {
		for (KeyBindingState info : actionInfoByFullName.values()) {
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

		Set<String> registeredNames = new HashSet<>();
		Map<String, List<DockingActionIf>> actionsByFullName =
			KeyBindingUtils.getAllActionsByFullName(tool);
		Set<Entry<String, List<DockingActionIf>>> entries = actionsByFullName.entrySet();
		for (Entry<String, List<DockingActionIf>> entry : entries) {

			List<DockingActionIf> actions = entry.getValue();

			String fullName = entry.getKey();
			ActionTrigger trigger = keyBindingOptions.getActionTrigger(fullName, null);

			registeredNames.add(fullName);

			KeyStroke ks = null;
			MouseBinding mb = null;

			if (trigger != null) {
				ks = trigger.getKeyStroke();
				mb = trigger.getMouseBinding();
			}

			ActionKeyBindingState state = new ActionKeyBindingState(actions, ks, mb);
			actionInfoByFullName.put(fullName, state);

			addActionKeyStroke(fullName, ks);

			String shortName = state.getName();
			if (shortName.length() > longestActionName.length()) {
				longestActionName = shortName;
			}
		}

		// ask options for unregistered key binding options
		List<String> allNamesList = keyBindingOptions.getOptionNames();
		Set<String> unregisteredNames = new HashSet<>(allNamesList);
		unregisteredNames.removeAll(registeredNames);

		for (String fullName : unregisteredNames) {
			KeyStroke ks = null;
			MouseBinding mb = null;

			ActionTrigger trigger = keyBindingOptions.getActionTrigger(fullName, null);
			if (trigger != null) {
				ks = trigger.getKeyStroke();
				mb = trigger.getMouseBinding();
			}

			UnregisteredActionKeyBindingState state =
				new UnregisteredActionKeyBindingState(fullName, ks, mb);
			actionInfoByFullName.put(fullName, state);

			addActionKeyStroke(fullName, ks);

			int description = fullName.indexOf("(");
			String shortName = fullName.substring(0, description).trim();
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

	private abstract class KeyBindingState implements ActionBindingsDescriptor {

		KeyStroke originalKeyStroke;
		KeyStroke currentKeyStroke;
		MouseBinding originalMouseBinding;
		MouseBinding currentMouseBinding;

		KeyBindingState(KeyStroke ks, MouseBinding mb) {
			this.originalKeyStroke = ks;
			this.currentKeyStroke = ks;
			this.originalMouseBinding = mb;
			this.currentMouseBinding = mb;
		}

		abstract KeyBindingData getCurrentKeyBindingData();

		// restores the key/mouse binding options to their default values
		abstract void restore(ToolOptions options);

		KeyBindingData getOriginalKeyBindingData() {

			if (originalKeyStroke == null && originalMouseBinding == null) {
				return null; // the key binding data does not exist or has been cleared
			}

			ActionTrigger trigger = new ActionTrigger(originalKeyStroke, originalMouseBinding);
			return new KeyBindingData(trigger);
		}

		@Override
		public String getBindingText() {
			String text = "";
			String fullName = getFullName();
			KeyStroke ks = getKeyStroke(fullName);
			if (ks != null) {
				text += KeyBindingUtils.parseKeyStroke(ks);
			}

			MouseBinding mb = getMouseBinding(fullName);
			if (mb != null) {
				text += " (" + mb.getDisplayText() + ")";
			}

			return text.trim();
		}

		MouseBinding getCurrentMouseBinding() {
			return currentMouseBinding;
		}

		void setCurrentMouseBinding(MouseBinding newMouseBinding) {
			this.currentMouseBinding = newMouseBinding;
		}

		KeyStroke getCurrentKeyStroke() {
			return currentKeyStroke;
		}

		void setCurrentKeyStroke(KeyStroke newKeyStroke) {
			this.currentKeyStroke = newKeyStroke;
		}

		void clearChanges() {
			currentKeyStroke = originalKeyStroke;
			currentMouseBinding = originalMouseBinding;
		}

		void apply(ToolOptions keyStrokeOptions) {
			if (!hasChanged()) {
				return;
			}

			KeyBindingData kbd = getCurrentKeyBindingData();
			apply(keyStrokeOptions, kbd);
		}

		void apply(ToolOptions keyStrokeOptions, KeyBindingData keyBinding) {
			String fullName = getFullName();
			if (keyBinding == null) {
				keyStrokeOptions.setActionTrigger(fullName, null);
				currentKeyStroke = null;
				currentMouseBinding = null;
				return;
			}

			// 1) update the options with the new value
			ActionTrigger newTrigger = keyBinding.getActionTrigger();
			keyStrokeOptions.setActionTrigger(fullName, newTrigger);

			// 2) update our state so the UI shows the new value
			currentKeyStroke = newTrigger.getKeyStroke();
			currentMouseBinding = newTrigger.getMouseBinding();
		}

		boolean matches(KeyBindingData kbData) {

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

		boolean hasChanged() {
			return !Objects.equals(originalKeyStroke, currentKeyStroke) ||
				!Objects.equals(originalMouseBinding, currentMouseBinding);
		}
	}

	/**
	 * Represents info for an action that is known by the options, but has not been registered.
	 */
	private class UnregisteredActionKeyBindingState extends KeyBindingState {

		private String fullName;
		private String actionName;
		private String ownerName;

		UnregisteredActionKeyBindingState(String fullName, KeyStroke ks, MouseBinding mb) {
			super(ks, mb);
			this.fullName = fullName;

			int descriptionIndex = fullName.indexOf("(");
			this.actionName = fullName.substring(0, descriptionIndex).trim();

			int lastParen = fullName.lastIndexOf(")");
			this.ownerName = fullName.substring(descriptionIndex + 1, lastParen).trim();
		}

		@Override
		public String getName() {
			return actionName;
		}

		@Override
		public String getFullName() {
			return fullName;
		}

		@Override
		public String getOwnerDescription() {
			return ownerName;
		}

		@Override
		public String getDescription() {
			return ""; // no action; no description
		}

		@Override
		public DockingActionIf getRepresentativeAction() {
			return null; // no action
		}

		@Override
		public boolean isRegistered() {
			return false;
		}

		@Override
		KeyBindingData getCurrentKeyBindingData() {
			if (currentKeyStroke == null && currentMouseBinding == null) {
				return null; // no bindings or the values have been cleared
			}

			ActionTrigger trigger = new ActionTrigger(currentKeyStroke, currentMouseBinding);
			return new KeyBindingData(trigger);
		}

		@Override
		void restore(ToolOptions options) {

			if (!hasChanged()) {
				return;
			}

			KeyBindingData defaultBinding = getOriginalKeyBindingData();

			clearChanges();

			if (!matches(defaultBinding)) {
				apply(options, defaultBinding);
			}
		}

	}

	/**
	 * A class to store current and original values for key strokes and mouse bindings.  This is 
	 * used to apply changes and restore default values.
	 */
	private class ActionKeyBindingState extends KeyBindingState {

		private List<DockingActionIf> actions = new ArrayList<>();

		ActionKeyBindingState(List<DockingActionIf> actions, KeyStroke ks, MouseBinding mb) {
			super(ks, mb);
			this.actions.addAll(actions);
		}

		@Override
		public String getName() {
			// pick one action, they are all conceptually the same
			return getRepresentativeAction().getName();
		}

		@Override
		public String getFullName() {
			return getRepresentativeAction().getFullName();
		}

		@Override
		public String getOwnerDescription() {
			return getRepresentativeAction().getOwnerDescription();
		}

		@Override
		public String getDescription() {
			return getRepresentativeAction().getDescription();
		}

		@Override
		public DockingActionIf getRepresentativeAction() {
			// pick one action, they are all conceptually the same
			return actions.get(0);
		}

		@Override
		public boolean isRegistered() {
			return true;
		}

		@Override
		KeyBindingData getCurrentKeyBindingData() {

			if (currentKeyStroke == null && currentMouseBinding == null) {
				return null; // the key binding data does not exist or has been cleared
			}

			DockingActionIf action = getRepresentativeAction();
			KeyBindingData kbData = action.getKeyBindingData();
			ActionTrigger trigger = new ActionTrigger(currentKeyStroke, currentMouseBinding);
			return KeyBindingData.update(kbData, trigger);
		}

		// restores the options to their default values
		@Override
		void restore(ToolOptions options) {
			DockingActionIf action = getRepresentativeAction();
			KeyBindingData defaultBinding = action.getDefaultKeyBindingData();

			clearChanges();

			if (!matches(defaultBinding)) {
				apply(options, defaultBinding);
			}
		}

	}

}
