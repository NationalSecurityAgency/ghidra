/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app;

import ghidra.framework.plugintool.util.PluginPackage;
import resources.ResourceManager;

public class DeveloperPluginPackage extends PluginPackage {
	public static final String NAME = "Developer";
	
	public DeveloperPluginPackage() {
		super(NAME, ResourceManager.loadImage("images/applications-engineering.png"),
				"These plugins provide features useful for developing and debugging plugins.",
				DEVELOPER_PRIORITY);
	}
}
