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
import wasm.analysis.WasmFuncSignature;
import wasm.format.WasmEnums.ValType;

/**
 * The function entry injection for a Wasm function. We inject code to copy from
 * the artificial "inputs" registers into the real "locals" registers.
 */
public class InjectPayloadWasmEntry extends InjectPayloadCallother {

	public InjectPayloadWasmEntry(String sourceName) {
		super(sourceName);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		PcodeOpEmitter ops = new PcodeOpEmitter(program.getLanguage(), con.baseAddr);

		WasmAnalysis state = WasmAnalysis.getState(program);
		Address funcBase = program.getFunctionManager().getFunctionContaining(con.baseAddr).getEntryPoint();
		WasmFuncSignature sig = state.getFunctionByAddress(funcBase);
		if (sig == null || sig.isImport()) {
			return ops.getPcodeOps();
		}

		Address inputBase = program.getRegister("i0").getAddress();
		Address localsBase = program.getRegister("l0").getAddress();
		ValType[] params = sig.getParams();
		ValType[] locals = sig.getLocals();
		for (int i = 0; i < params.length; i++) {
			ops.emitCopy(inputBase.add(i * WasmLoader.REG_SIZE), localsBase.add(i * WasmLoader.REG_SIZE), params[i].getSize());
		}
		Address zero = program.getAddressFactory().getConstantAddress(0L);
		for (int i = params.length; i < locals.length; i++) {
			ops.emitCopy(zero, localsBase.add(i * WasmLoader.REG_SIZE), locals[i].getSize());
		}
		return ops.getPcodeOps();
	}
}
