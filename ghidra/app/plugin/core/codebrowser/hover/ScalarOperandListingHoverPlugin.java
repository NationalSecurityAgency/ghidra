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
package ghidra.app.plugin.core.codebrowser.hover;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

/**
 * A plugin to show tool tip text for hovering over scalar values in the listing.
 *
 * 
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Scalar Operand Hover",
	description = "Pop-up display of data about a scalar at the current address." +
			"Scalars are shown as 1-, 2-, 4-, and 8-byte values, each in base 10, 16, and " +
			"as ASCII characters.",
	servicesProvided = { ListingHoverService.class }
)
//@formatter:on
public class ScalarOperandListingHoverPlugin extends Plugin {

	private ScalarOperandListingHover scalarHoverService;

	public ScalarOperandListingHoverPlugin(PluginTool tool) {
		super(tool);
		scalarHoverService = new ScalarOperandListingHover(tool);
		registerServiceProvided(ListingHoverService.class, scalarHoverService);
	}

	@Override
	public void dispose() {
		scalarHoverService.dispose();
	}
}
