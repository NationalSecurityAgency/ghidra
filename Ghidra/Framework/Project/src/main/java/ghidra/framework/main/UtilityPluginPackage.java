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
package ghidra.framework.main;

import ghidra.framework.plugintool.util.PluginPackage;
import resources.ResourceManager;

public class UtilityPluginPackage extends PluginPackage {

	public static final String NAME = "Utility";

	public UtilityPluginPackage() {
		super(NAME, ResourceManager.loadImage("images/applications-development-web.png"),
			"These plugins provide basic functionality useful to all tools.", UTILITY_PRIORITY);
	}
}
