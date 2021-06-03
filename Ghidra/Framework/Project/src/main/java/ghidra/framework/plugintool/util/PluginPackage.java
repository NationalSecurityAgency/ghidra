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
package ghidra.framework.plugintool.util;

import java.util.*;

import javax.swing.Icon;

import ghidra.MiscellaneousPluginPackage;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.classfinder.ExtensionPoint;

public abstract class PluginPackage implements ExtensionPoint, Comparable<PluginPackage> {
	public static final int CORE_PRIORITY = 0;
	public static final int FEATURE_PRIORITY = 4;
	public static final int MISCELLANIOUS_PRIORITY = 6;
	public static final int DEVELOPER_PRIORITY = 8;
	public static final int EXAMPLES_PRIORITY = 10;
	public static final int EXPERIMENTAL_PRIORITY = 12;

	private static Map<String, PluginPackage> packageMap;

	public static PluginPackage getPluginPackage(String packageName) {
		if (packageMap == null) {
			packageMap = createPackageMap();
		}
		PluginPackage pluginPackage = packageMap.get(packageName.toLowerCase());
		if (pluginPackage == null) {
			Msg.warn(PluginPackage.class,
				"Can't find plugin package for " + packageName + "! Creating stub...");
			pluginPackage = packageMap.get(MiscellaneousPluginPackage.NAME.toLowerCase());
		}
		return pluginPackage;
	}

	private static Map<String, PluginPackage> createPackageMap() {
		Map<String, PluginPackage> map = new HashMap<>();
		List<Class<? extends PluginPackage>> classes =
			ClassSearcher.getClasses(PluginPackage.class);
		for (Class<? extends PluginPackage> class1 : classes) {
			PluginPackage pluginPackage;
			try {
				pluginPackage = class1.newInstance();

				String name = pluginPackage.getName().toLowerCase();
				if (map.containsKey(name)) {
					Msg.error(PluginPackage.class, "PluginPackage already exist for name: " + name);
				}
				else {
					map.put(name, pluginPackage);
				}
			}
			catch (Exception e) {
				Msg.error(PluginPackage.class, "Could not instantiate " + class1.getName(), e);
			}
		}

		// make sure this is always there (in case it is not discovered)
		map.put(MiscellaneousPluginPackage.NAME.toLowerCase(), new MiscellaneousPluginPackage());

		return map;
	}

	private final String name;
	private final Icon icon;
	private final String description;
	private final int priority;

	protected PluginPackage(String name, Icon icon, String description) {
		this(name, icon, description, FEATURE_PRIORITY);
	}

	protected PluginPackage(String name, Icon icon, String description, int priority) {
		this.name = name;
		this.icon = icon;
		this.description = description;
		this.priority = priority;
	}

	public String getName() {
		return name;
	}

	public Icon getIcon() {
		return icon;
	}

	public String getDescription() {
		return description;
	}

	@Override
	public int compareTo(PluginPackage other) {
		if (priority == other.priority) {
			return name.compareTo(other.name);
		}
		return priority - other.priority;
	}

	public boolean isfullyAddable() {
		return true;
	}
}
