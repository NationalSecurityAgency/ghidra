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
import ghidra.program.model.lang.InjectPayloadSleigh;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import wasm.analysis.WasmAnalysis;
import wasm.analysis.WasmFuncSignature;
import wasm.format.WasmEnums.ValType;

/**
 * The "uponentry" injection for a Wasm function. We inject code to copy from
 * the artificial "inputs" registers into the real "locals" registers.
 */
public class InjectPayloadWasmEntry extends InjectPayloadSleigh {

	public InjectPayloadWasmEntry(String nm, int tp, String sourceName) {
		super(nm, tp, sourceName);
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
			ops.emitCopy(inputBase.add(i * 8L), localsBase.add(i * 8L), params[i].getSize());
		}
		Address zero = program.getAddressFactory().getConstantAddress(0L);
		for (int i = params.length; i < locals.length; i++) {
			ops.emitCopy(zero, localsBase.add(i * 8L), locals[i].getSize());
		}
		return ops.getPcodeOps();
	}
}
