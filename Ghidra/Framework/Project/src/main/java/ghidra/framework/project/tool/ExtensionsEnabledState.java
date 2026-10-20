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

import java.util.Map;
import java.util.Set;

import ghidra.util.classfinder.ClassFileInfo;

/**
 * An interface to help describe extensions' enable state for a given tool.
 */
public interface ExtensionsEnabledState {

	/**
	 * {@return a map of all known extensions to a set of their plugins}
	 */
	public Map<String, Set<ClassFileInfo>> getAllKnownExtensions();

	/**
	 * All plugins installed in the current tool will be removed from the given set. This allows the
	 * client to have a set of plugins that are not currently installed.
	 * @param allPlugins the plugins set to update
	 */
	public void removeInstalledPlugins(Set<ClassFileInfo> allPlugins);

	/**
	 * Shows a window to prompt the user to configure any new extension plugins.
	 * @param newPlugins the new extension plugins
	 */
	public void propmtToConfigureNewPlugins(Set<ClassFileInfo> newPlugins);
}
