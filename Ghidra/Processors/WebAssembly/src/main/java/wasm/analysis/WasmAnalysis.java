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

import ghidra.app.plugin.core.analysis.AnalysisState;
import ghidra.app.plugin.core.analysis.AnalysisStateInfo;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import wasm.WasmLoader;
import wasm.format.WasmEnums.ValType;
import wasm.format.WasmModule;
import wasm.format.sections.structures.WasmFuncType;

public class WasmAnalysis implements AnalysisState {
	/**
	 * Return persistent <code>ClassFileAnalysisState</code> which corresponds to
	 * the specified program instance.
	 * 
	 * @param program
	 * @return <code>ClassFileAnalysisState</code> for specified program instance
	 */
	public static synchronized WasmAnalysis getState(Program program) {
		WasmAnalysis analysisState = AnalysisStateInfo.getAnalysisState(program, WasmAnalysis.class);
		if (analysisState == null) {
			analysisState = new WasmAnalysis(program);
			AnalysisStateInfo.putAnalysisState(program, analysisState);
		}
		return analysisState;
	}

	private Program program;
	private WasmModule module = null;
	private List<WasmFuncSignature> functions = null;
	private Map<Address, WasmFuncSignature> functionsByAddress = new HashMap<>();
	private Map<Function, WasmFunctionAnalysis> functionAnalyses = new HashMap<>();

	public WasmAnalysis(Program program) {
		Memory mem = program.getMemory();
		Address moduleStart = mem.getBlock(".module").getStart();
		ByteProvider memByteProvider = new MemoryByteProvider(mem, moduleStart);
		BinaryReader memBinaryReader = new BinaryReader(memByteProvider, true);
		try {
			module = new WasmModule(memBinaryReader);
		} catch (IOException e) {
			Msg.error(this, "Failed to construct WasmModule", e);
		}

		this.program = program;
		this.functions = getFunctions(program, module);
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

	public synchronized WasmFunctionAnalysis getFunctionAnalysis(Function f) {
		if (!functionAnalyses.containsKey(f)) {
			WasmFuncSignature func = getFunctionByAddress(f.getEntryPoint());
			BinaryReader codeReader = new BinaryReader(new MemoryByteProvider(program.getMemory(), func.getStartAddr()), true);
			WasmFunctionAnalysis funcAnalysis = new WasmFunctionAnalysis(func);
			try {
				funcAnalysis.analyzeFunction(program, codeReader);
				functionAnalyses.put(f, funcAnalysis);
			} catch (Exception e) {
				Msg.error(this, "Failed to analyze function " + func.getName(), e);
				f.setComment("WARNING: Wasm function analysis failed, output may be incorrect: " + e);
			}
		}
		return functionAnalyses.get(f);
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

	private static List<WasmFuncSignature> getFunctions(Program program, WasmModule module) {
		int numFunctions = module.getFunctionCount();
		List<WasmFuncSignature> functions = new ArrayList<>(numFunctions);
		for (int funcidx = 0; funcidx < numFunctions; funcidx++) {
			WasmFuncType funcType = module.getFunctionType(funcidx);
			Address startAddress = WasmLoader.getFunctionAddress(program, module, funcidx);
			Address endAddress = startAddress.add(WasmLoader.getFunctionSize(program, module, funcidx) - 1);

			String name = null;
			Symbol[] labels = program.getSymbolTable().getSymbols(startAddress);
			if (labels.length > 0) {
				name = labels[0].getName();
			}

			ValType[] params = funcType.getParamTypes();
			ValType[] returns = funcType.getReturnTypes();
			ValType[] nonParamLocals = module.getFunctionLocals(funcidx);
			if (nonParamLocals == null) {
				/* import */
				functions.add(new WasmFuncSignature(params, returns, name, startAddress));
			} else {
				ValType[] locals = new ValType[params.length + nonParamLocals.length];

				System.arraycopy(params, 0, locals, 0, params.length);
				System.arraycopy(nonParamLocals, 0, locals, params.length, nonParamLocals.length);
				functions.add(new WasmFuncSignature(params, returns, name, startAddress, endAddress, locals));
			}
		}
		return functions;
	}
}
