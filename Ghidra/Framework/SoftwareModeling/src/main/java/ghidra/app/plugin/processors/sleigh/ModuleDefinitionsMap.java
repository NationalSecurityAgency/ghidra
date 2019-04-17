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
package ghidra.app.plugin.processors.sleigh;

import java.util.*;

import generic.jar.ResourceFile;
import ghidra.framework.Application;

public class ModuleDefinitionsMap {
	private static HashMap<String, String> moduleMap;

	public static synchronized Map<String, String> getModuleMap() {
		if (moduleMap == null) {
			Collection<ResourceFile> moduleRootDirectories = Application.getModuleRootDirectories();
			moduleMap = new HashMap<String, String>();
			for (ResourceFile resourceFile : moduleRootDirectories) {
				moduleMap.put(resourceFile.getName(), resourceFile.getAbsolutePath());
			}
		}
		return Collections.unmodifiableMap(moduleMap);
	}
}
