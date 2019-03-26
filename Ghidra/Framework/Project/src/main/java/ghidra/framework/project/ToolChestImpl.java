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
package ghidra.framework.project;

import java.io.File;
import java.util.*;

import ghidra.framework.ToolUtils;
import ghidra.framework.model.*;
import ghidra.util.SystemUtilities;

/**
 * Implementation for the Project ToolChest.
 */
class ToolChestImpl implements ToolChest {

	private List<ToolChestChangeListener> listeners;
	private Map<String, ToolTemplate> map;

	/**
	 * Construct user's tool chest.
	 */
	ToolChestImpl() {
		// we want sorting by tool name, so use a sorted map
		map = ToolUtils.loadUserTools();
		listeners = new ArrayList<ToolChestChangeListener>(3);
	}

	@Override
	public void addToolChestChangeListener(ToolChestChangeListener l) {
		if (!listeners.contains(l)) {
			listeners.add(l);
		}
	}

	@Override
	public void removeToolChestChangeListener(ToolChestChangeListener l) {
		if (listeners.contains(l)) {
			listeners.remove(l);
		}
	}

	/**
	 * Get the tool template for the given tool name.
	 * @return null if there is no tool template for the given
	 * toolName.
	 */
	@Override
	public ToolTemplate getToolTemplate(String toolName) {
		return map.get(toolName);
	}

	/**
	 * Get the ToolConfigs from the tool chest.
	 * @return zero-length array if there are no ToolConfigs in the
	 * tool chest.
	 */
	@Override
	public ToolTemplate[] getToolTemplates() {
		Collection<ToolTemplate> c = map.values();
		ToolTemplate[] templates = new ToolTemplate[c.size()];
		c.toArray(templates);
		return templates;
	}

	/**
	 * @see ghidra.framework.model.ToolChest#getToolCount()
	 */
	@Override
	public int getToolCount() {
		return map.size();
	}

	/**
	 * Remove tool template from the tool chest.
	 * @return true if the template was removed from the tool chest.
	 */
	@Override
	public boolean remove(String name) {

		File toolFile = ToolUtils.getToolFile(name);
		boolean removed = toolFile.delete();
		if (!removed && toolFile.exists()) {
			return false;
		}

		map.remove(name);

		// notify listeners of removed ToolConfig
		SystemUtilities.runSwingNow(() -> {
			ToolChestChangeListener[] tcListeners = new ToolChestChangeListener[listeners.size()];
			listeners.toArray(tcListeners);
			for (int l = 0; l < tcListeners.length; l++) {
				tcListeners[l].toolRemoved(name);
			}
		});

		return true;
	}

	@Override
	public boolean replaceToolTemplate(ToolTemplate template) {
		return doAddToolTemplate(template);
	}

	@Override
	public boolean addToolTemplate(ToolTemplate template) {
		template.setName(ToolUtils.getUniqueToolName(template));
		return doAddToolTemplate(template);
	}

	// local method for adding tool templates and notifying listeners
	private boolean doAddToolTemplate(ToolTemplate template) {
		if (!ToolUtils.writeToolTemplate(template)) {
			return false; // unable to write template
		}

		map.put(template.getName(), template);

		// notify listeners of added tool template
		SystemUtilities.runSwingNow(() -> {
			for (ToolChestChangeListener listener : listeners) {
				listener.toolTemplateAdded(template);
			}
		});

		return true;
	}

	/**
	 * Returns a string representation of the object. In general, the
	 * <code>toString</code> method returns a string that
	 * "textually represents" this object. The result should
	 * be a concise but informative representation that is easy for a
	 * person to read.
	 */
	@Override
	public String toString() {
		return "Project Tool Chest at " + ToolUtils.getUserToolsDirectory();
	}
}
