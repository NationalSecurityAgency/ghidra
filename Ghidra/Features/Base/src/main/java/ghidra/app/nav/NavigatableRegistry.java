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
package ghidra.app.nav;

import java.util.*;

import ghidra.framework.plugintool.PluginTool;

public class NavigatableRegistry {
	private static Map<Long, Navigatable> navigatableMap = new HashMap<Long, Navigatable>();
	private static Map<PluginTool, List<Navigatable>> toolMap =
		new HashMap<PluginTool, List<Navigatable>>();

	public static void registerNavigatable(PluginTool tool, Navigatable navigatable) {
		navigatableMap.put(navigatable.getInstanceID(), navigatable);
		List<Navigatable> list = toolMap.get(tool);
		if (list == null) {
			list = new ArrayList<Navigatable>();
			toolMap.put(tool, list);
		}
		list.add(navigatable);
	}

	public static void unregisterNavigatable(PluginTool tool, Navigatable navigatable) {
		navigatableMap.remove(navigatable.getInstanceID());
		List<Navigatable> list = toolMap.get(tool);
		if (list == null) {
			return;
		}
		list.remove(navigatable);
		if (list.isEmpty()) {
			toolMap.remove(tool);
		}
	}

	public static List<Navigatable> getRegisteredNavigatables(PluginTool tool) {
		List<Navigatable> list = toolMap.get(tool);
		if (list == null) {
			list = new ArrayList<Navigatable>(navigatableMap.values());
		}
		return list;
	}

	public static Navigatable getNavigatable(long navigationID) {
		return navigatableMap.get(navigationID);
	}
}
