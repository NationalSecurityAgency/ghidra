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
package ghidra.app.decompiler.component.hover;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

/**
 * A plugin to show tool tip text for hovering over scalar values in the decompiler.
 *
 * 
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.DECOMPILER,
	shortDescription = "Scalar Value Hover",
	description = "Pop-up display of various interpretations of the hovered-over decompiler scalar",
	servicesProvided = { DecompilerHoverService.class }
)
//@formatter:on
public class ScalarValueDecompilerHoverPlugin extends Plugin {

	private ScalarValueDecompilerHover scalarHoverService;

	public ScalarValueDecompilerHoverPlugin(PluginTool tool) {
		super(tool);
		scalarHoverService = new ScalarValueDecompilerHover(tool);
		registerServiceProvided(DecompilerHoverService.class, scalarHoverService);
	}
}
