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
package ghidra.app.util.demangler;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.CreateThunkFunctionCmd;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import utility.function.Dummy;

public class DemangledThunk extends DemangledObject {

	private DemangledFunction thunkedFunctionObject;

	private String signaturePrefix;

	private boolean covariantReturnThunk = false;

	public DemangledThunk(String mangled, String originalDemangled,
			DemangledFunction thunkedFunctionObject) {
		super(mangled, originalDemangled);
		this.thunkedFunctionObject = thunkedFunctionObject;
		this.namespace = thunkedFunctionObject.getNamespace();
		setName(thunkedFunctionObject.getName());
	}

	public void setCovariantReturnThunk() {
		this.covariantReturnThunk = true;
	}

	public void setSignaturePrefix(String prefix) {
		signaturePrefix = prefix;
	}

	@Override
	public String getSignature(boolean format) {

		String refSignature = thunkedFunctionObject.getSignature(format);
		return (signaturePrefix != null ? signaturePrefix : "thunk ") + refSignature;
	}

	@Override
	protected boolean isAlreadyDemangled(Program program, Address address) {
		Function f = program.getListing().getFunctionAt(address);
		if (f == null) {
			return false;
		}

		if (f.getSymbol().getSource() == SourceType.USER_DEFINED) {
			return true;
		}
		if (!f.isThunk()) {
			return false;
		}
		return super.isAlreadyDemangled(program, address);
	}

	@Override
	public boolean applyTo(Program program, Address thunkAddress, DemanglerOptions options,
			TaskMonitor monitor) throws Exception {

		if (isAlreadyDemangled(program, thunkAddress)) {
			return true;
		}

		if (!super.applyTo(program, thunkAddress, options, monitor)) {
			return false;
		}

		Function thunkedFunction = findThunkedFunction(program, thunkAddress, options, monitor);

		if (covariantReturnThunk) {
			// Just lay down a function instead of a thunk so that the return type can be
			// set independent of the "thunked-function" which is called by the thunk.
			return thunkedFunctionObject.applyTo(program, thunkAddress, options, monitor);
		}

		Function function =
			createPreThunkFunction(program, thunkAddress, options.doDisassembly(), monitor);
		if (function == null) {
			// no function whose signature we need to update
			// NOTE: This does not much sense
			// renameExistingSymbol(program, thunkAddress, symbolTable);
			// DemangledFunction.maybeCreateUndefined(program, thunkAddress);
			return false;
		}

		// For pre-existing default thunks - apply demangling to thunked function who owns mangled name
		while (function.getSymbol().getSource() == SourceType.DEFAULT && function.isThunk()) {
			function = function.getThunkedFunction(false);
		}

		if (thunkedFunction != null && mangled.equals(function.getName()) &&
			!function.isThunk()) {
			function.setThunkedFunction(thunkedFunction);
		}

		Symbol s = applyDemangledName(thunkAddress, function.isThunk(), false, program);
		return s != null;
	}

	private Function createPreThunkFunction(Program prog, Address addr, boolean doDisassembly,
			TaskMonitor monitor) {

		Listing listing = prog.getListing();

		Function func = listing.getFunctionAt(addr);
		if (func != null) {
			return func;
		}

		if (doDisassembly) {
			// make sure it is executable!
			AddressSetView execSet = prog.getMemory().getExecuteSet();
			if (execSet.contains(addr)) {
				DisassembleCommand cmd = new DisassembleCommand(addr, null, true);
				cmd.applyTo(prog, monitor);
			}
		}

		AddressSet body = new AddressSet();
		Instruction instr = listing.getInstructionAt(addr);
		while (instr != null) {
			// This is done in a way to handle potential delay slots
			InstructionContext instructionContext = instr.getInstructionContext();
			Address fallThru = instructionContext.getAddress()
					.add(
						instr.getPrototype().getFallThroughOffset(instructionContext));
			Address maxAddr = fallThru.previous();
			if (maxAddr.compareTo(instr.getMinAddress()) < 0) {
				// just in case we wrapped
				maxAddr = instr.getMaxAddress();
			}
			body.add(instr.getMinAddress(), maxAddr);
			if (!instr.getFlowType().hasFallthrough()) {
				break;
			}
			instr = listing.getInstructionAt(fallThru);
		}
		if (body.isEmpty()) {
			body.add(addr); // assume no disassembly was performed
		}

		CreateFunctionCmd cmd = new CreateFunctionCmd(null, addr, body, SourceType.DEFAULT);
		cmd.applyTo(prog, monitor);

		return listing.getFunctionAt(addr);
	}

	private Function findThunkedFunction(Program program, Address thunkAddress,
			DemanglerOptions options, TaskMonitor monitor) throws Exception {

		// Safeguard: restrict to function contained within same block as thunk (may be unnecessary)

		MemoryBlock block = program.getMemory().getBlock(thunkAddress);
		if (block == null) {
			return null;
		}

		Symbol s = SymbolUtilities.getExpectedLabelOrFunctionSymbol(program,
			mangled, Dummy.consumer());
		if (s == null) {
			Address thunkedAddr =
				CreateThunkFunctionCmd.getThunkedAddr(program, thunkAddress, false);
			if (thunkedAddr != null) {
				s = program.getSymbolTable().getPrimarySymbol(thunkedAddr);
			}
		}

		if (s == null || !block.contains(s.getAddress())) {
			Msg.warn(this, "Unable to find or create thunk for " + mangled + " at " + thunkAddress);
			return null;
		}

		Address addr = s.getAddress();
		DemanglerOptions subOptions = new DemanglerOptions(options);
		subOptions.setApplySignature(true);

		thunkedFunctionObject.applyTo(program, addr, subOptions, monitor);

		return program.getFunctionManager().getFunctionAt(addr);
	}
}
