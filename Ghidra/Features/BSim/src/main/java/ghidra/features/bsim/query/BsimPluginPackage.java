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
package ghidra.features.bsim.query;

import ghidra.framework.plugintool.util.PluginPackage;
import ghidra.framework.plugintool.util.PluginStatus;
import resources.ResourceManager;

public class BsimPluginPackage extends PluginPackage {

	public static final String NAME = "BSim";

	public BsimPluginPackage() {
		super(NAME, ResourceManager.loadImage("images/preferences-web-browser-shortcuts-32.png"),
			"An API and set of plugins for creating, managing and accessing function by similarity",
			FEATURE_PRIORITY);
	}

	@Override
	public PluginStatus getActivationLevel() {
		// bsim allows 'released' and 'stable' plugins for now
		return PluginStatus.STABLE;
	}
}
