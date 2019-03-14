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

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * Plugin that is a component provider to show a text area.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Show Info",
	description = "Sample plugin demonstrating how to access information from a program. "
			+ " To see it work, use with the CodeBrowser."
)
//@formatter:on
public class ShowInfoPlugin extends ProgramPlugin {

	private ShowInfoComponentProvider provider;

	public ShowInfoPlugin(PluginTool tool) {
		super(tool, true, false);
		provider = new ShowInfoComponentProvider(tool, getName());
	}

	@Override
	protected void programDeactivated(Program program) {
		provider.clear();
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		provider.locationChanged(currentProgram, loc);
	}

}
