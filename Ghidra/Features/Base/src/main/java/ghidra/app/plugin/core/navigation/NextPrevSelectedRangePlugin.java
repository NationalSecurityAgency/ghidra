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
 * Plugin to go to the next or previous selected range in the program.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.NAVIGATION,
	shortDescription = "Navigates selection ranges",
	description = "Provides actions for navigating from one selection range to the next or previous selection range."
)
//@formatter:on
public class NextPrevSelectedRangePlugin extends Plugin {

	static final String ACTION_SUB_GROUP = "1";

	private NavigationOptions navOptions;

	private NextSelectedRangeAction nextAction;
	private PreviousSelectedRangeAction previousAction;

	public NextPrevSelectedRangePlugin(PluginTool tool) {
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
		nextAction = new NextSelectedRangeAction(tool, getName(), navOptions);
		tool.addAction(nextAction);

		previousAction = new PreviousSelectedRangeAction(tool, getName(), navOptions);
		tool.addAction(previousAction);
	}

}
