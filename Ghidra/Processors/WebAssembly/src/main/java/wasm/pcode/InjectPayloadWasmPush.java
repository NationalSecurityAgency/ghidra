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
package wasm.pcode;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import wasm.WasmLoader;
import wasm.analysis.WasmAnalysis;
import wasm.analysis.WasmFunctionAnalysis;
import wasm.analysis.WasmFunctionAnalysis.StackEffect;
import wasm.format.WasmEnums.ValType;

/**
 * Handle variable-length pushes from the stack to registers. We use this to
 * handle branches (pushing block arguments from temporary registers) and
 * function calls (pushing function return values from output registers).
 */
public class InjectPayloadWasmPush extends InjectPayloadCallother {

	public InjectPayloadWasmPush(String sourceName) {
		super(sourceName);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		PcodeOpEmitter ops = new PcodeOpEmitter(program.getLanguage(), con.baseAddr);

		long regoffset = con.inputlist.get(0).getOffset();
		Address baseAddress = program.getAddressFactory().getAddressSpace("register").getAddress(regoffset);

		WasmAnalysis state = WasmAnalysis.getState(program);
		WasmFunctionAnalysis funcAnalysis;
		try {
			funcAnalysis = state.getFunctionAnalysis(
					program.getFunctionManager().getFunctionContaining(con.baseAddr).getEntryPoint());
		} catch (Exception e) {
			return ops.getPcodeOps();
		}
		if (funcAnalysis == null) {
			return ops.getPcodeOps();
		}

		StackEffect stackEffect = funcAnalysis.getStackEffect(con.baseAddr);
		if (stackEffect == null) {
			return ops.getPcodeOps();
		}

		long stackHeight = stackEffect.getPushHeight();
		ValType[] todo = stackEffect.getToPush();
		Address stackAddress = program.getRegister("s0").getAddress().add(stackHeight * WasmLoader.REG_SIZE);
		for (int i = 0; i < todo.length; i++) {
			ops.emitCopy(baseAddress.add(i * WasmLoader.REG_SIZE), stackAddress.add(i * WasmLoader.REG_SIZE), todo[i].getSize());
		}

		return ops.getPcodeOps();
	}
}
