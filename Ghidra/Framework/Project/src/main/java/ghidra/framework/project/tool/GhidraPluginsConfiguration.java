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
package ghidra.framework.project.tool;

import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.util.PluginsConfiguration;

/**
 * A configuration that allows all general plugins and application plugins.  Plugins that may only
 * exist at the application level are filtered out.
 */
class GhidraPluginsConfiguration extends PluginsConfiguration {

	@Override
	protected boolean accepts(Class<? extends Plugin> c) {
		return !(ApplicationLevelOnlyPlugin.class.isAssignableFrom(c));
	}
}
