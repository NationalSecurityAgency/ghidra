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

import java.util.Collections;

import ghidra.framework.plugintool.Plugin;

/**
 * A basic stub that allows tests to create plugin descriptions
 */
public class StubPluginDescription extends PluginDescription {

	public StubPluginDescription(Class<? extends Plugin> pluginClass, PluginPackage pluginPackage,
			String category, String shortDescription, PluginStatus status) {
		super(pluginClass, pluginPackage.getName(), category, shortDescription,
			"Full description for " + pluginClass.getName(), status, false, Collections.emptyList(),
			Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
	}

}
