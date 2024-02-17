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
import ghidra.framework.options.ToolOptions;
import util.CollectionUtils;

/**
 * An object that maps actions to key strokes.
 * <p>
 * This class knows how to load all system actions and how to load any key bindings for those 
 * actions from the tool's options.   Clients can make changes to the state of this class that can
 * then be applied to the system by calling {@link #applyChanges()}.
 */
public class KeyBindings {

	private Tool tool;

	private Map<String, List<DockingActionIf>> actionsByFullName;
	private Map<String, List<String>> actionNamesByKeyStroke = new HashMap<>();
	private Map<String, KeyStroke> keyStrokesByFullName = new HashMap<>();
	private List<DockingActionIf> uniqueActions = new ArrayList<>();

	// to know what has been changed
	private Map<String, KeyStroke> originalKeyStrokesByFullName = new HashMap<>();
	private String longestActionName = "";

	private ToolOptions options;

	public KeyBindings(Tool tool) {
		this.tool = tool;

		options = tool.getOptions(DockingToolConstants.KEY_BINDINGS);

		init();
	}

	public List<DockingActionIf> getUniqueActions() {
		return Collections.unmodifiableList(uniqueActions);
	}

	public Map<String, KeyStroke> getKeyStrokesByFullActionName() {
		return Collections.unmodifiableMap(keyStrokesByFullName);
	}

	public boolean containsAction(String fullName) {
		return actionsByFullName.containsKey(fullName);
	}

	public KeyStroke getKeyStroke(String fullName) {
		return keyStrokesByFullName.get(fullName);
	}

	public String getActionsForKeyStrokeText(String keyStrokeText) {

		StringBuffer sb = new StringBuffer();
		List<String> names = actionNamesByKeyStroke.get(keyStrokeText);
		if (CollectionUtils.isBlank(names)) {
			return sb.toString();
		}

		names.sort((n1, n2) -> {
			return n1.compareToIgnoreCase(n2);
		});

		sb.append("Actions mapped to key " + keyStrokeText + ":\n");
		for (int i = 0; i < names.size(); i++) {
			sb.append("  ");

			String name = names.get(i);
			List<DockingActionIf> actions = actionsByFullName.get(name);
			DockingActionIf action = actions.get(0);
			sb.append(action.getName());
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

	public boolean setActionKeyStroke(String actionName, KeyStroke keyStroke) {
		String ksName = KeyBindingUtils.parseKeyStroke(keyStroke);

		// remove old keystroke for action name
		KeyStroke oldKs = keyStrokesByFullName.get(actionName);
		if (oldKs != null) {
			String oldName = KeyBindingUtils.parseKeyStroke(oldKs);
			if (oldName.equals(ksName)) {
				return false;
			}
			removeFromKeyMap(oldKs, actionName);
		}
		addActionKeyStroke(keyStroke, actionName);

		keyStrokesByFullName.put(actionName, keyStroke);
		return true;
	}

	public boolean removeKeyStroke(String actionName) {
		if (keyStrokesByFullName.containsKey(actionName)) {
			KeyStroke stroke = keyStrokesByFullName.get(actionName);
			if (stroke == null) {
				// nothing to remove; nothing has changed
				return false;
			}

			removeFromKeyMap(stroke, actionName);
			keyStrokesByFullName.put(actionName, null);
			return true;
		}
		return false;
	}

	/**
	 * Restores the tool options key bindings to the default values originally loaded when the 
	 * system started.
	 */
	public void restoreOptions() {

		Set<Entry<String, List<DockingActionIf>>> entries = actionsByFullName.entrySet();
		for (Entry<String, List<DockingActionIf>> entry : entries) {
			List<DockingActionIf> actions = entry.getValue();

			// pick one action, they are all conceptually the same
			DockingActionIf action = actions.get(0);
			String actionName = entry.getKey();
			KeyStroke currentKeyStroke = keyStrokesByFullName.get(actionName);
			KeyBindingData defaultBinding = action.getDefaultKeyBindingData();
			KeyStroke newKeyStroke =
				(defaultBinding == null) ? null : defaultBinding.getKeyBinding();

			updateOptions(actionName, currentKeyStroke, newKeyStroke);
		}
	}

	/**
	 * Cancels any pending changes that have not yet been applied.
	 */
	public void cancelChanges() {
		Iterator<String> iter = originalKeyStrokesByFullName.keySet().iterator();
		while (iter.hasNext()) {
			String actionName = iter.next();
			KeyStroke originalKS = originalKeyStrokesByFullName.get(actionName);
			KeyStroke modifiedKS = keyStrokesByFullName.get(actionName);
			if (modifiedKS != null && !modifiedKS.equals(originalKS)) {
				keyStrokesByFullName.put(actionName, originalKS);
			}
		}
	}

	/**
	 * Applies any pending changes.
	 */
	public void applyChanges() {
		Iterator<String> iter = keyStrokesByFullName.keySet().iterator();
		while (iter.hasNext()) {
			String actionName = iter.next();
			KeyStroke currentKeyStroke = keyStrokesByFullName.get(actionName);
			KeyStroke originalKeyStroke = originalKeyStrokesByFullName.get(actionName);
			updateOptions(actionName, originalKeyStroke, currentKeyStroke);
		}
	}

	private void removeFromKeyMap(KeyStroke ks, String actionName) {
		if (ks == null) {
			return;
		}
		String ksName = KeyBindingUtils.parseKeyStroke(ks);
		List<String> list = actionNamesByKeyStroke.get(ksName);
		if (list != null) {
			list.remove(actionName);
			if (list.isEmpty()) {
				actionNamesByKeyStroke.remove(ksName);
			}
		}
	}

	private void updateOptions(String fullActionName, KeyStroke currentKeyStroke,
			KeyStroke newKeyStroke) {

		if (Objects.equals(currentKeyStroke, newKeyStroke)) {
			return;
		}

		options.setKeyStroke(fullActionName, newKeyStroke);
		originalKeyStrokesByFullName.put(fullActionName, newKeyStroke);
		keyStrokesByFullName.put(fullActionName, newKeyStroke);

		List<DockingActionIf> actions = actionsByFullName.get(fullActionName);
		for (DockingActionIf action : actions) {
			action.setUnvalidatedKeyBindingData(new KeyBindingData(newKeyStroke));
		}

	}

	private void init() {

		actionsByFullName = KeyBindingUtils.getAllActionsByFullName(tool);
		Set<Entry<String, List<DockingActionIf>>> entries = actionsByFullName.entrySet();
		for (Entry<String, List<DockingActionIf>> entry : entries) {

			// pick one action, they are all conceptually the same
			List<DockingActionIf> actions = entry.getValue();
			DockingActionIf action = actions.get(0);
			uniqueActions.add(action);

			String actionName = entry.getKey();
			KeyStroke ks = options.getKeyStroke(actionName, null);
			keyStrokesByFullName.put(actionName, ks);
			addActionKeyStroke(ks, actionName);
			originalKeyStrokesByFullName.put(actionName, ks);

			String shortName = action.getName();
			if (shortName.length() > longestActionName.length()) {
				longestActionName = shortName;
			}
		}
	}

	private void addActionKeyStroke(KeyStroke ks, String actionName) {
		if (ks == null) {
			return;
		}
		String ksName = KeyBindingUtils.parseKeyStroke(ks);
		List<String> list = actionNamesByKeyStroke.get(ksName);
		if (list == null) {
			list = new ArrayList<>();
			actionNamesByKeyStroke.put(ksName, list);
		}
		if (!list.contains(actionName)) {
			list.add(actionName);
		}
	}

}
