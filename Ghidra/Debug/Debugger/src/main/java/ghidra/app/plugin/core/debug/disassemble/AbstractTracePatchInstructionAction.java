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
package ghidra.app.plugin.core.debug.disassemble;

import docking.ActionContext;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.app.plugin.core.assembler.AssemblyDualTextField;
import ghidra.app.plugin.core.assembler.PatchInstructionAction;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.DefaultLanguageService;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.program.TraceProgramView;

public abstract class AbstractTracePatchInstructionAction extends PatchInstructionAction {
	protected final DebuggerDisassemblerPlugin plugin;

	public AbstractTracePatchInstructionAction(DebuggerDisassemblerPlugin plugin, String name) {
		super(plugin, name);
		this.plugin = plugin;
	}

	protected abstract TracePlatform getPlatform(CodeUnit cu);

	protected RegisterValue getContextValue(CodeUnit cu) {
		return DebuggerDisassemblerPlugin.deriveAlternativeDefaultContext(
			getPlatform(cu).getLanguage(), getAlternativeLanguageID(cu), cu.getAddress());
	}

	protected LanguageID getAlternativeLanguageID(CodeUnit cu) {
		return getPlatform(cu).getLanguage().getLanguageID();
	}

	@Override
	protected AssemblyDualTextField newAssemblyDualTextField() {
		return new AssemblyDualTextField() {
			AssemblyPatternBlock ctx = null;

			@Override
			protected AssemblyPatternBlock getContext() {
				return ctx;
			}

			@Override
			public void setAddress(Address address) {
				super.setAddress(address);
				RegisterValue rv = getContextValue(getCodeUnit());
				ctx = rv == null ? AssemblyPatternBlock.nop()
						: AssemblyPatternBlock.fromRegisterValue(rv).fillMask();
			}
		};
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!super.isAddToPopup(context)) {
			return false;
		}
		CodeUnit cu = getCodeUnit(context);
		return isApplicableToUnit(cu);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!super.isEnabledForContext(context)) {
			return false;
		}
		CodeUnit cu = getCodeUnit(context);
		return isApplicableToUnit(cu);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		/*
		 * Ensure the load has happened. Otherwise, it happens during completion and cancels the
		 * action.
		 */
		try {
			DefaultLanguageService.getLanguageService()
					.getLanguage(getAlternativeLanguageID(getCodeUnit(context)));
		}
		catch (LanguageNotFoundException e) {
			throw new AssertionError(e); // I just looked it up
		}
		super.actionPerformed(context);
	}

	@Override
	protected Language getLanguage(CodeUnit cu) {
		return getPlatform(cu).getLanguage();
	}

	@Override
	protected Assembler getAssembler(CodeUnit cu) {
		return Assemblers.getAssembler(language);
	}

	@Override
	protected void applyPatch(byte[] data) throws MemoryAccessException {
		TraceProgramView view = getView();
		if (view == null) {
			return;
		}
		Address address = getAddress();
		// Get code unit and dependencies before invalidating it, just in case.
		CodeUnit cu = getCodeUnit();
		RegisterValue contextValue = getContextValue(cu);
		TracePlatform platform = getPlatform(cu);
		view.getMemory().setBytes(address, data); // This invalidates cu
		AddressSetView set = new AddressSet(address, address.add(data.length - 1));
		TraceDisassembleCommand dis = new TraceDisassembleCommand(platform, address, set);
		if (contextValue != null) {
			dis.setInitialContext(contextValue);
		}
		dis.run(tool, view);
	}

	protected TraceProgramView getView() {
		Program program = getProgram();
		if (!(program instanceof TraceProgramView)) {
			return null;
		}
		return (TraceProgramView) program;
	}
}
