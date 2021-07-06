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

import java.beans.PropertyChangeListener;
import java.util.*;

import javax.swing.JComponent;
import javax.swing.tree.TreePath;

import org.jdom.Element;

import docking.options.editor.OptionsDialog;
import docking.tool.ToolConstants;
import docking.tool.util.DockingToolConstants;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.dialog.KeyBindingsPanel;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * Created by PluginTool to manage the set of Options for each category.
 */
public class OptionsManager implements OptionsService, OptionsChangeListener {
	private OptionsDialog optionsDialog;
	private PluginTool tool;
	private Map<String, ToolOptions> optionsMap;

	/**
	 * Constructor
	 * @param tool associated with this OptionsManager
	 */
	public OptionsManager(PluginTool tool) {
		this.tool = tool;
		optionsMap = new HashMap<>();
	}

	public void dispose() {
		if (optionsDialog != null) {
			optionsDialog.dispose();
		}
		optionsMap.values().forEach(options -> options.dispose());
	}

	@Override
	public ToolOptions getOptions(String category) {

		ToolOptions opt = optionsMap.get(category);
		if (opt == null) {
			opt = new ToolOptions(category);
			opt.addOptionsChangeListener(this);
			optionsMap.put(category, opt);
		}
		return opt;
	}

	/**
	 * Updates saved options from an old name to a new name.  NOTE: this must be called before
	 * any calls to register or get options.
	 * @param oldName the old name of the options.
	 * @param newName the new name of the options.
	 */
	public void registerOptionNameChanged(String oldName, String newName) {
		if (optionsMap.containsKey(oldName)) {
			ToolOptions toolOptions = optionsMap.remove(oldName);
			toolOptions.setName(newName);
			optionsMap.put(newName, toolOptions);
		}
	}

	@Override
	public boolean hasOptions(String category) {
		return optionsMap.containsKey(category);
	}

	@Override
	public void showOptionsDialog(String category, String filterText) {
		if (optionsDialog != null && optionsDialog.isVisible()) {
			optionsDialog.toFront();
			return;
		}
		optionsDialog = createOptionsDialog();
		optionsDialog.displayCategory(category, filterText);
		tool.showDialog(optionsDialog);
	}

	@Override
	public ToolOptions[] getOptions() {
		ToolOptions[] opt = new ToolOptions[optionsMap.size()];
		int idx = 0;
		Iterator<String> iter = optionsMap.keySet().iterator();
		while (iter.hasNext()) {
			String key = iter.next();
			opt[idx] = optionsMap.get(key);
			++idx;
		}
		Arrays.sort(opt, new OptionsComparator());
		return opt;
	}

	/**
	 * Deregister the owner from the options; if options are empty, then
	 * remove the options from the map.
	 * @param ownerPlugin the owner plugin
	 */
	public void deregisterOwner(Plugin ownerPlugin) {
		List<String> deleteList = new ArrayList<>();
		Iterator<String> iter = optionsMap.keySet().iterator();
		while (iter.hasNext()) {
			String key = iter.next();
			ToolOptions opt = optionsMap.get(key);
			if (opt.getOptionNames().isEmpty()) {
				deleteList.add(opt.getName());
			}
		}
		removeUnusedOptions(deleteList);
	}

	/**
	 * Write this object out; first remove any unused options so they
	 * do not hang around.
	 * @return XML element containing the state of all the options
	 */
	public Element getConfigState() {
		Element root = new Element("OPTIONS");
		Iterator<String> iter = optionsMap.keySet().iterator();
		while (iter.hasNext()) {
			String key = iter.next();
			ToolOptions opt = optionsMap.get(key);
			if (hasNonDefaultValues(opt)) {
				root.addContent(opt.getXmlRoot(false));
			}
		}
		return root;
	}

	private boolean hasNonDefaultValues(Options options) {
		List<String> optionNames = options.getOptionNames();
		for (String string : optionNames) {
			if (!options.isDefaultValue(string)) {
				return true;
			}
		}
		return false;
	}

	public void removeUnusedOptions() {
		// 1st clean up any unused options before saving...
		List<String> deleteList = new ArrayList<>();
		Iterator<String> iter = optionsMap.keySet().iterator();
		while (iter.hasNext()) {
			String key = iter.next();
			ToolOptions opt = optionsMap.get(key);
			opt.removeUnusedOptions();
			if (opt.getOptionNames().isEmpty()) {
				deleteList.add(opt.getName());
			}
		}
		removeUnusedOptions(deleteList);
	}

	/**
	 * Restore Options objects using the given XML Element.
	 * @param root element to use to restore the Options objects
	 */
	public void setConfigState(Element root) {
		Iterator<?> iter = root.getChildren().iterator();
		while (iter.hasNext()) {
			ToolOptions opt = new ToolOptions((Element) iter.next());
			ToolOptions oldOptions = optionsMap.get(opt.getName());
			if (oldOptions == null) {
				opt.addOptionsChangeListener(this);
			}
			else {
				opt.takeListeners(oldOptions);
				opt.registerOptions(oldOptions);
			}
			optionsMap.put(opt.getName(), opt);
		}
	}

	public void editOptions() {
		if (optionsMap.isEmpty()) {
			Msg.showInfo(getClass(), tool.getToolFrame(), "No Options",
				"No Options set in this tool");
			return;
		}
		if (optionsDialog != null && optionsDialog.isVisible()) {
			optionsDialog.toFront();
			return;
		}
		optionsDialog = createOptionsDialog();
		tool.showDialog(optionsDialog);
	}

	public void validateOptions() {
		for (ToolOptions options : optionsMap.values()) {
			options.validateOptions();
		}
	}

	private OptionsDialog createOptionsDialog() {
		OptionsDialog dialog = null;
		if (optionsMap.size() == 0) {
			return null;
		}

		Options keyBindingOptions = getOptions(DockingToolConstants.KEY_BINDINGS);
		TreePath path = null;
		if (optionsDialog != null) {
			path = optionsDialog.getSelectedPath();
			optionsDialog.dispose();

			OptionsEditor oldEditor = keyBindingOptions.getOptionsEditor();
			oldEditor.dispose();
		}

		keyBindingOptions.registerOptionsEditor(new KeyBindingOptionsEditor());
		dialog = new OptionsDialog("Options for " + tool.getName(), "Options", getEditableOptions(),
			null, true);
		dialog.setSelectedPath(path);
		dialog.setHelpLocation(
			new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "ToolOptions_Dialog"));
		return dialog;
	}

	private Options[] getEditableOptions() {
		return tool.getOptions();
	}

	private void removeUnusedOptions(List<String> deleteList) {
		for (int i = 0; i < deleteList.size(); i++) {
			String name = deleteList.get(i);
			ToolOptions options = optionsMap.remove(name);
			options.removeOptionsChangeListener(this);
		}
	}

	private class OptionsComparator implements Comparator<ToolOptions> {
		@Override
		public int compare(ToolOptions o1, ToolOptions o2) {
			return o1.getName().compareTo(o2.getName());
		}
	}

	private class KeyBindingOptionsEditor implements OptionsEditor {

		private KeyBindingsPanel panel;

		KeyBindingOptionsEditor() {
			panel = new KeyBindingsPanel(tool, getOptions(DockingToolConstants.KEY_BINDINGS));
		}

		@Override
		public void apply() {
			panel.apply();
		}

		@Override
		public void cancel() {
			panel.cancel();
		}

		@Override
		public void reload() {
			panel.reload();
		}

		@Override
		public void dispose() {
			panel.dispose();
		}

		@Override
		public JComponent getEditorComponent(Options options,
				EditorStateFactory editorStateFactory) {
			return panel;
		}

		@Override
		public void setOptionsPropertyChangeListener(PropertyChangeListener listener) {
			panel.setOptionsPropertyChangeListener(listener);
		}
	}

	@Override
	public void optionsChanged(ToolOptions options, String name, Object oldValue, Object newValue) {
		tool.setConfigChanged(true);
	}
}
