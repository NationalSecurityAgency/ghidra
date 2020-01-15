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
package ghidra.app.plugin.core.navigation;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

/**
 * Plugin to go to the next or previous highlighted range in the program.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.NAVIGATION,
	shortDescription = "Navigate highlights",
	description = "Adds actions for navigating to the next/previous highlight in the code browser or byte viewer"
)
//@formatter:on
public class NextPrevHighlightRangePlugin extends Plugin {

	static final String ACTION_SUB_GROUP = "2";

	private NavigationOptions navOptions;

	private NextHighlightedRangeAction nextAction;
	private PreviousHighlightedRangeAction previousAction;

	public NextPrevHighlightRangePlugin(PluginTool tool) {
		super(tool);
		navOptions = new NavigationOptions(tool);
		createActions();
	}

	@Override
	protected void dispose() {
		navOptions.dispose();
		super.dispose();
	}

	/**
	 * Create the actions and add them to the tool.
	 */
	private void createActions() {
		nextAction = new NextHighlightedRangeAction(tool, getName(), navOptions);
		tool.addAction(nextAction);

		previousAction = new PreviousHighlightedRangeAction(tool, getName(), navOptions);
		tool.addAction(previousAction);
	}

}
