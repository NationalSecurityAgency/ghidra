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
package ghidra.framework.plugintool.dialog;

import java.util.*;

import docking.util.image.ToolIconURL;
import resources.ResourceManager;

/**
 * Class with static methods to access a hash map of icons.
 * Loads the names in resources/images directory; the map is updated
 * as icons are needed.
 */
class IconMap {

	private static Map<String, ToolIconURL> map = createIconMap(); // map name to icon

	private static Map<String, ToolIconURL> createIconMap() {
		Map<String, ToolIconURL> iconMap = new HashMap<String, ToolIconURL>();
		load(iconMap); // load image names from classpath
		return iconMap;
	}

	/**
	 * Add the icon to the map; if name already exists, icon will
	 * replace the existing value.
	 */
	static void put(String name, ToolIconURL icon) {
		map.put(name, icon);
	}

	/**
	 * Remove the icon from the map; has no effect on the resources/images
	 * directory.
	 */
	static ToolIconURL remove(String name) {
		return map.remove(name);
	}

	/**
	 * Get the icon for the given name.
	 * @return the icon; return null if there is no icon by that name.
	 */
	static ToolIconURL get(String name) {
		return map.get(name);
	}

	/**
	 * Get the sorted list of icon names the icon map.
	 */
	static List<String> getIconNames() {
		List<String> list = new ArrayList<String>(map.keySet());
		Collections.sort(list);
		return list;
	}

	static List<ToolIconURL> getIcons() {
		List<ToolIconURL> list = new ArrayList<ToolIconURL>(map.values());
		Collections.sort(list);
		return list;
	}

	/**
	 * Load the map of icon.
	 */
	private static void load(Map<String, ToolIconURL> iconMap) {
		Set<String> images = ResourceManager.getToolImages();
		for (String filename : images) {
			int pos = filename.lastIndexOf('/');
			if (pos >= 0) {
				filename = filename.substring(pos + 1);
			}
			if (!iconMap.containsKey(filename)) {
				iconMap.put(filename, new ToolIconURL(filename));
			}
		}
	}

}
