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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import wasm.format.WasmEnums.ValType;

public class WasmSignatureAnalyzer extends AbstractAnalyzer {
	private final static String NAME = "Wasm Signature Analyzer";
	private final static String DESCRIPTION = "Apply function signatures from Wasm metadata";

	public WasmSignatureAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// run immediately after Apply Data Archives, since that pass might introduce
		// invalid signatures
		setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.after().after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(Processor.findOrPossiblyCreateProcessor("WebAssembly"));
	}

	private static boolean paramsMatch(List<Parameter> newParams, Parameter[] existingParams) {
		/* TODO: what if existingParams has a struct which occupies multiple slots? */
		if (newParams.size() != existingParams.length) {
			return false;
		}
		for (int i = 0; i < existingParams.length; i++) {
			if (newParams.get(i).getLength() != existingParams[i].getLength()) {
				return false;
			}
		}
		return true;
	}

	private static void setFunctionSignature(Program program, Function function, WasmFuncSignature sig) throws Exception {
		DataType returnType;
		if (sig.getReturns().length > 0) {
			/* TODO handle multiple returns */
			returnType = sig.getReturns()[0].asDataType();
		} else {
			returnType = VoidDataType.dataType;
		}

		function.setCallingConvention("__wasm");

		if (returnType.getLength() != function.getReturnType().getLength()) {
			/* function return type is wrong: reset it */
			function.setReturnType(returnType, SourceType.IMPORTED);
		}

		List<Parameter> params = new ArrayList<>();
		ValType[] rawParams = sig.getParams();
		for (int i = 0; i < rawParams.length; i++) {
			params.add(new ParameterImpl("param" + (i + 1), rawParams[i].asDataType(), program));
		}

		if (!paramsMatch(params, function.getParameters())) {
			function.replaceParameters(params, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.IMPORTED);
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
		WasmAnalysis state = WasmAnalysis.getState(program);
		List<WasmFuncSignature> functions = state.getFunctions();
		monitor.initialize(functions.size());
		for (int i = 0; i < functions.size(); i++) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.setProgress(i);

			WasmFuncSignature func = functions.get(i);
			Function function = program.getListing().getFunctionAt(func.getStartAddr());
			try {
				setFunctionSignature(program, function, func);
			} catch (Exception e) {
				Msg.error(this, "Failed to set function signature for " + func.getName(), e);
			}
		}
		return true;
	}
}
