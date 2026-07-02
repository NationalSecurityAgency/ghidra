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
import docking.ComponentProvider;
import docking.action.*;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.HelpLocation;

public class AssemblePatchAction extends DockingAction {
	protected final Plugin plugin;

	public AssemblePatchAction(Plugin plugin, String name) {
		super(name, plugin.getName());
		setPopupMenuData(createMenuData(name));
		setKeyBindingData(new KeyBindingData("ctrl shift J"));
		setHelpLocation(new HelpLocation(plugin.getName(), "assemble_patch"));
		this.plugin = plugin;
	}

	protected MenuData createMenuData(String name) {
		return new MenuData(new String[] { "Assemble..." }, AbstractPatchAction.MENU_GROUP);
	}

	protected boolean isApplicableToContext(ActionContext context) {
		if (!(context instanceof ListingActionContext lac)) {
			return false;
		}

		ComponentProvider provider = lac.getComponentProvider();
		if (!(provider instanceof CodeViewerProvider codeViewer)) {
			return false;
		}

		if (codeViewer.isReadOnly()) {
			return false;
		}

		Program program = lac.getProgram();
		if (program == null) {
			return false;
		}

		Address address = lac.getAddress();
		if (address == null) {
			return false;
		}
		MemoryBlock block = program.getMemory().getBlock(address);
		if (block == null || !block.isInitialized()) {
			return false;
		}
		return true;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return super.isEnabledForContext(context) && isApplicableToContext(context);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return super.isAddToPopup(context) && isApplicableToContext(context);
	}

	protected RegisterValue getInitialContext(Instruction ins, Program program, Address entry) {
		if (ins != null) {
			return ins.getRegisterValue(ins.getBaseContextRegister());
		}
		ProgramContext context = program.getProgramContext();
		return context.getRegisterValue(context.getBaseContextRegister(), entry);
	}

	/**
	 * {@return a dialog for assembly a patch or null if the context is unsuitable}
	 * 
	 * @param ctx the context
	 */
	protected AbstractAssemblePatchDialog<?> newDialog(ListingActionContext ctx) {
		Program program = ctx.getProgram();
		Address entry = ctx.getAddress();
		Instruction ins = program.getListing().getInstructionContaining(entry);
		return new AssemblePatchDialog(plugin.getTool(), ctx.getNavigatable(), program, entry,
			getInitialContext(ins, program, entry));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (!(context instanceof ListingActionContext ctx)) {
			return;
		}
		AbstractAssemblePatchDialog<?> dialog = newDialog(ctx);
		if (dialog == null) {
			return;
		}
		plugin.getTool().showDialog(dialog);
	}
}
