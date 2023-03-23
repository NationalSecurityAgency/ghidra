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

import docking.ActionContext;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.data.DataType;
import ghidra.program.model.mem.MemBuffer;

/**
 * A plugin for assembly
 * 
 * <p>
 * This plugin currently provides two actions: {@link PatchInstructionAction}, which allows the user
 * to assemble an instruction at the current address; and {@link PatchDataAction}, which allows the
 * user to "assemble" data at the current address.
 * 
 * <p>
 * The API for instruction assembly is available from {@link Assemblers}. For data assembly, the API
 * is in {@link DataType#encodeRepresentation(String, MemBuffer, Settings, int)}.
 */
@PluginInfo(status = PluginStatus.RELEASED, packageName = CorePluginPackage.NAME, category = PluginCategoryNames.PATCHING, shortDescription = "Assembler", description = "This plugin provides functionality for assembly patching. " +
	"The assembler supports most processor languages also supported by the " +
	"disassembler. Depending on the particular processor, your mileage may vary. " +
	"We are in the process of testing and improving support for all our processors. " +
	"You can access the assembler by pressing Ctrl-Shift-G, and then modifying the " +
	"instruction in place. As you type, a content assist will guide you and provide " +
	"assembled bytes when you have a complete instruction.")
public class AssemblerPlugin extends ProgramPlugin {
	public static final String ASSEMBLER_NAME = "Assembler";

	/*test*/ PatchInstructionAction patchInstructionAction;
	/*test*/ PatchDataAction patchDataAction;

	public AssemblerPlugin(PluginTool tool) {
		super(tool);
		createActions();
	}

	private void createActions() {
		// Debugger provides its own "Patch Instruction" action
		patchInstructionAction = new PatchInstructionAction(this) {
			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (!super.isEnabledForContext(context)) {
					return false;
				}
				if (!(context instanceof ListingActionContext)) {
					return false;
				}
				ListingActionContext lac = (ListingActionContext) context;
				return !lac.getNavigatable().isDynamic();
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				if (!super.isAddToPopup(context)) {
					return false;
				}
				if (!(context instanceof ListingActionContext)) {
					return false;
				}
				ListingActionContext lac = (ListingActionContext) context;
				return !lac.getNavigatable().isDynamic();
			}
		};
		tool.addAction(patchInstructionAction);

		patchDataAction = new PatchDataAction(this);
		tool.addAction(patchDataAction);
	}

	@Override
	protected void dispose() {
		patchInstructionAction.dispose();
		patchDataAction.dispose();
	}
}
