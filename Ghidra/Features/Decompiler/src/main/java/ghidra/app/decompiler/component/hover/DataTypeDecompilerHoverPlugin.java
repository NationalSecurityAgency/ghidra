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
 * A plugin to show tool tip text for hovering over data types in the decompiler.
 *
 * 
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.DECOMPILER,
	shortDescription = "Data Type Hover",
	description = "Displays data type information in a tooltip as you hover over a data type name in the decompiler.",
	servicesProvided = { DecompilerHoverService.class }
)
//@formatter:on
public class DataTypeDecompilerHoverPlugin extends Plugin {

	private DataTypeDecompilerHover dataTypeHoverService;

	public DataTypeDecompilerHoverPlugin(PluginTool tool) {
		super(tool);
		dataTypeHoverService = new DataTypeDecompilerHover(tool);
		registerServiceProvided(DecompilerHoverService.class, dataTypeHoverService);
	}

}
