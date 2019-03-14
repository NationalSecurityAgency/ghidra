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
package ghidra.examples2;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Sample Search Table Plugin",
	description = "Sample plugin for searching and creating a table for the results"
)
//@formatter:on
public class SampleSearchTablePlugin extends ProgramPlugin {

	private SampleSearchTableProvider provider;

	public SampleSearchTablePlugin(PluginTool tool) {
		super(tool, false, false);
		createActions();
	}

	@Override
	protected void dispose() {
		if (provider != null) {
			provider.dispose();
		}
	}

	private void createActions() {
		DockingAction action = new DockingAction("Search Stuff", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				search();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return currentProgram != null;
			}
		};
		action.setMenuBarData(
			new MenuData(new String[] { "Search", "No Arg Functions" }, "MyGroup"));
		tool.addAction(action);
	}

	protected void search() {
		SampleSearcher searcher = new SampleSearcher(currentProgram);
		provider = new SampleSearchTableProvider(this, searcher);
		tool.addComponentProvider(provider, true);
	}
}
