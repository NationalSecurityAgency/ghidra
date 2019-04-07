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
package ghidra.examples;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

/**
 * A very simple example plugin.  It creates an action that, when invoked, prints "Hello World" to
 * the console.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Displays 'Hello World'",
	description = "Simplest possible sample plugin.  Displays the message, 'Hello World!', to the console."
)
//@formatter:on
public class HelloWorldPlugin extends Plugin {

	private DockingAction helloAction;

	/**
	 * Plugin constructor - all plugins must have a constructor with this signature
	 * @param tool the pluginTool that this plugin is added to.
	 */
	public HelloWorldPlugin(PluginTool tool) {
		super(tool);

		// Create the hello action.
		helloAction = new DockingAction("Hello World", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				Msg.info(this, "Hello World!");
			}
		};
		// Enable the action - by default actions are disabled.
		helloAction.setEnabled(true);

		// Put the action in the global "View" menu.
		helloAction.setMenuBarData(new MenuData(new String[] { "View", "Hello World" }));

		// Add the action to the tool.
		tool.addAction(helloAction);
	}

}
