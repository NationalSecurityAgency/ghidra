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

import java.util.List;

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Sample Table Plugin",
	description = "Sample plugin for creating and manipulating a table"
)
//@formatter:on
public class SampleTablePlugin extends ProgramPlugin {

	private SampleTableProvider provider;
	private Function currentFunction;

	public SampleTablePlugin(PluginTool tool) {
		super(tool, true /*location changes*/, true/*selection changes*/);

		provider = new SampleTableProvider(this);
		provider.addToTool();
	}

	@Override
	protected void locationChanged(ProgramLocation location) {
		if (location == null) {
			currentFunction = null;
			return;
		}

		FunctionManager functionManager = currentProgram.getFunctionManager();
		currentFunction = functionManager.getFunctionContaining(location.getAddress());
	}

	@Override
	protected void selectionChanged(ProgramSelection selection) {
		Msg.info(this, "selectionChanged(): " + selection);
	}

	public Function getFunction() {
		return currentFunction;
	}

	public List<FunctionAlgorithm> getAlgorithms() {
		return provider.getAlgorithms();
	}

	public boolean resetExisingTableData() {
		return provider.resetExistingTableData();
	}

	@Override
	protected void dispose() {
		provider.dispose();
	}
}
