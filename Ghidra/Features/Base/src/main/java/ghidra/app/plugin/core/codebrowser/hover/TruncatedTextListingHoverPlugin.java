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
 * A plugin to show tool tip text for hovering over over-length fields in the listing.
 *
 * 
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Shows full text over truncated fields",
	description = "This plugin extends the functionality of the code browser by adding a "
			+ "\tooltip\" over fields in the browser that don't have the space to display all "
			+ "relevant information associated with that field.  For example, if a comment is too "
			+ "long to display, it will end with \"...\" This plugin will then provide a "
			+ "popup displaying the full text when the mouse is moved over that field.",
	servicesProvided = { ListingHoverService.class }
)
//@formatter:on
public class TruncatedTextListingHoverPlugin extends Plugin {

	private TruncatedTextListingHover truncatedTextHoverService;

	public TruncatedTextListingHoverPlugin(PluginTool tool) {
		super(tool);
		truncatedTextHoverService = new TruncatedTextListingHover(tool);
		registerServiceProvided(ListingHoverService.class, truncatedTextHoverService);
	}

	@Override
	public void dispose() {
		truncatedTextHoverService.dispose();
	}
}
