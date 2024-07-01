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
package wasm.analysis;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.plugin.core.analysis.TransientProgramProperties;
import ghidra.app.plugin.core.analysis.TransientProgramProperties.SCOPE;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import wasm.WasmLoader;
import wasm.format.WasmEnums.ValType;
import wasm.format.WasmModule;
import wasm.format.sections.structures.WasmCodeEntry;
import wasm.format.sections.structures.WasmFuncType;

public class WasmAnalysis {
	/**
	 * Return persistent <code>WasmAnalysis</code> which corresponds to
	 * the specified program instance.
	 *
	 * @param program
	 * @return <code>WasmAnalysis</code> for specified program instance
	 */
	public static synchronized WasmAnalysis getState(Program program) {
		return TransientProgramProperties.getProperty(program, WasmAnalysis.class, SCOPE.PROGRAM, WasmAnalysis.class, () -> {
			Memory mem = program.getMemory();
			Address moduleStart = WasmLoader.getModuleAddress(program.getAddressFactory());
			ByteProvider memByteProvider = new MemoryByteProvider(mem, moduleStart);
			BinaryReader memBinaryReader = new BinaryReader(memByteProvider, true);
			WasmModule module;
			try {
				module = new WasmModule(memBinaryReader);
			} catch (IOException e) {
				throw new RuntimeException(e);
			}

			return new WasmAnalysis(program.getAddressFactory(), module);
		});
	}

	private WasmModule module = null;
	private List<WasmFuncSignature> functions = null;
	private Map<Address, WasmFuncSignature> functionsByAddress = new HashMap<>();
	private Map<Address, WasmFunctionAnalysis> functionAnalyses = new HashMap<>();

	public WasmAnalysis(AddressFactory addressFactory, WasmModule module) {
		this.module = module;
		this.functions = getFunctions(addressFactory, module);
		for (WasmFuncSignature func : functions) {
			functionsByAddress.put(func.getStartAddr(), func);
		}
	}

	public WasmModule getModule() {
		return module;
	}

	public List<WasmFuncSignature> getFunctions() {
		return Collections.unmodifiableList(functions);
	}

	public WasmFuncSignature getFunction(int funcIdx) {
		return functions.get(funcIdx);
	}

	public WasmFuncSignature getFunctionByAddress(Address address) {
		return functionsByAddress.get(address);
	}

	public synchronized WasmFunctionAnalysis getFunctionAnalysis(Address entryPoint) throws IOException {
		if (!functionAnalyses.containsKey(entryPoint)) {
			WasmFuncSignature func = getFunctionByAddress(entryPoint);
			if (func == null) {
				return null;
			}
			WasmCodeEntry code = module.getFunctionCode(func.getFuncIdx());
			if (code == null) {
				return null;
			}
			BinaryReader codeReader = new BinaryReader(new ByteArrayProvider(code.getInstructions()), true);
			WasmFunctionAnalysis funcAnalysis = new WasmFunctionAnalysis(func);
			funcAnalysis.analyzeFunction(this, codeReader);
			functionAnalyses.put(entryPoint, funcAnalysis);
		}
		return functionAnalyses.get(entryPoint);
	}

	public WasmFuncType getType(int typeidx) {
		return module.getType(typeidx);
	}

	public ValType getGlobalType(int globalidx) {
		return module.getGlobalType(globalidx).getType();
	}

	public ValType getTableType(int tableidx) {
		return module.getTableType(tableidx).getElementType();
	}

	private static List<WasmFuncSignature> getFunctions(AddressFactory addressFactory, WasmModule module) {
		int numFunctions = module.getFunctionCount();
		List<WasmFuncSignature> functions = new ArrayList<>(numFunctions);
		for (int funcidx = 0; funcidx < numFunctions; funcidx++) {
			WasmFuncType funcType = module.getFunctionType(funcidx);
			Address startAddress = WasmLoader.getFunctionAddress(addressFactory, module, funcidx);
			Address endAddress = startAddress.add(WasmLoader.getFunctionSize(module, funcidx) - 1);
			String name = WasmLoader.getFunctionName(module, funcidx);

			WasmCodeEntry code = module.getFunctionCode(funcidx);
			ValType[] params = funcType.getParamTypes();
			ValType[] returns = funcType.getReturnTypes();
			if (code == null) {
				/* import */
				functions.add(new WasmFuncSignature(params, returns, funcidx, name, startAddress));
			} else {
				ValType[] nonParamLocals = code.getLocals();
				ValType[] locals = new ValType[params.length + nonParamLocals.length];

				System.arraycopy(params, 0, locals, 0, params.length);
				System.arraycopy(nonParamLocals, 0, locals, params.length, nonParamLocals.length);
				functions.add(new WasmFuncSignature(params, returns, funcidx, name, startAddress, endAddress, locals));
			}
		}
		return functions;
	}
}
