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
package ghidra.app.plugin.core.assembler;

import docking.action.DockingAction;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

/**
 * A plugin for assembly
 * 
 * This plugin currently provides a single action: {@link AssembleDockingAction}, which allows the
 * user to assemble an instruction at the current address.
 * 
 * The API for assembly is available from {@link Assemblers}.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.PATCHING,
	shortDescription = "Assembler",
	description = "This plugin provides functionality for assembly patching. " +
			"The assembler supports most processor languages also supported by the " +
			"disassembler. Depending on the particular processor, your mileage may vary. " +
			"We are in the process of testing and improving support for all our processors. " +
			"You can access the assembler by pressing Ctrl-Shift-G, and then modifying the " +
			"instruction in place. As you type, a content assist will guide you and provide " +
			"assembled bytes when you have a complete instruction."
)
//@formatter:on
public class AssemblerPlugin extends ProgramPlugin {
	public static final String ASSEMBLER_NAME = "Assembler";

	private DockingAction assembleAction;

	public AssemblerPlugin(PluginTool tool) {
		super(tool, false, false, false);
		createActions();
	}

	private void createActions() {
		assembleAction = new AssembleDockingAction(tool, "Assemble", getName());
		assembleAction.setEnabled(true);
		tool.addAction(assembleAction);
	}

	@Override
	protected void dispose() {
		assembleAction.dispose();
	}

}
