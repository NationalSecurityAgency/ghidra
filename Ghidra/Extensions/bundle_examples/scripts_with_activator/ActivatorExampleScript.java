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
// Example script that cleans up actions with a bundle activator.
//@category Examples.Bundle

import docking.ActionContext;
import docking.action.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.ProgramLocation;
import internal.MyActivator;
import resources.Icons;

public class ActivatorExampleScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		PluginTool tool = state.getTool();
		println("This script is from a bundle with a custom activator class, " +
			MyActivator.class.getCanonicalName() + ".");
		println("When the bundle is activated, its start method is called.");
		println("When deactivated, the activator's stop method is called.");
		println("To demonstrate how it can be useful, this script adds an action to the toolbar,");
		println("  it's a gear icon with tooltip \"Added by script!!\".");
		println("The activator will remove the action if this bundle is deactivated,");
		println("  e.g. if this script is modified and the bundle needs to be reloaded.");

		DockingAction action = new DockingAction("Added by script!!", null, false) {
			@Override
			public void actionPerformed(ActionContext context) {
				ConsoleService console = tool.getService(ConsoleService.class);
				CodeViewerService codeviewer = tool.getService(CodeViewerService.class);
				ProgramLocation loc = codeviewer.getCurrentLocation();
				console.getStdOut().printf("Current location is %s\n", loc);
			}
		};
		action.setToolBarData(new ToolBarData(Icons.CONFIGURE_FILTER_ICON));
		MyActivator.addAction(tool, action);
	}
}
