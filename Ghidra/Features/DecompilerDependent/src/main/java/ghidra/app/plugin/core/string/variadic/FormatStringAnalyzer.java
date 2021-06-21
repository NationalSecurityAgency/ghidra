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
package ghidra.app.plugin.core.string.variadic;

import java.util.*;

import org.apache.commons.collections4.IteratorUtils;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.parallel.*;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.util.DefinedDataIterator;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class FormatStringAnalyzer extends AbstractAnalyzer {

	// Array of substrings of variadic function names that are searched for 
	private static final String[] VARIADIC_SUBSTRINGS = { "printf", "scanf" };
	private static final String NAME = "Variadic Function Signature Override";
	private static final String DESCRIPTION =
		"Detects variadic function calls in the bodies of each function that intersect the " +
			"current selection and parses their format string arguments to infer the correct " +
			"signatures. Currently, this analyzer only supports printf, scanf, and their variants " +
			"(e.g., snprintf, fscanf). If the current selection is empty, it searches through " +
			"every function. Once the correct signatures are inferred, they are overridden.";
	private final static boolean OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED = false;
	private final static String OPTION_NAME_CREATE_BOOKMARKS = "Create Analysis Bookmarks";
	private static final String OPTION_DESCRIPTION_CREATE_BOOKMARKS =
		"Select this check box if you want this analyzer to create analysis bookmarks " +
			"when items of interest are created/identified by the analyzer.";

	private boolean createBookmarksEnabled = OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED;

	// Any function name containing this substring is determined to be an input type function
	private static final String INPUT_FUNCTION_SUBSTRING = "scanf";
	private Program currentProgram = null;
	private FormatStringParser parser;

	public FormatStringAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_SIGNATURES_ANALYZER);
		setSupportsOneTimeAnalysis();
		setPriority(AnalysisPriority.LOW_PRIORITY);
		setDefaultEnablement(false);
		setPrototype();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return true;
	}

	private synchronized FormatStringParser getParser() {
		if (parser == null) {
			parser = new FormatStringParser(currentProgram);
		}
		return parser;
	}

	private synchronized void disposeParser() {
		parser = null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		this.currentProgram = program;
		try {
			run(set, monitor);
		}
		catch (CancelledException e) {
			// User cancelled analysis
		}
		finally {
			disposeParser();
		}
		return true;
	}

	private void run(AddressSetView selection, TaskMonitor monitor)
			throws CancelledException {

		DefinedDataIterator dataIterator = DefinedDataIterator.definedStrings(currentProgram);
		Map<Address, Data> stringsByAddress = new HashMap<>();
		for (Data data : dataIterator) {
			String s = data.getDefaultValueRepresentation();
			if (s.contains("%")) {
				stringsByAddress.put(data.getAddress(), data);
			}
			monitor.checkCanceled();
		}

		FunctionIterator functionIterator = currentProgram.getListing().getFunctions(true);
		FunctionIterator externalIterator = currentProgram.getListing().getExternalFunctions();
		Iterator<Function> programFunctionIterator = IteratorUtils.chainedIterator(functionIterator,externalIterator);
		Map<String, List<DataType>> namesToParameters = new HashMap<>();

		Map<String, DataType> namesToReturn = new HashMap<>();
		Set<Function> toDecompile = new HashSet<>();
		Set<String> variadicFunctionNames = new HashSet<>();

		// Find variadic function names and their parameter data types
		for (Function function : IteratorUtils.asIterable(programFunctionIterator)) {
			String name = function.getName().strip();
            if (usesVariadicFormatString(function)) {
                for (String variadicSubstring : VARIADIC_SUBSTRINGS) {
                    if (name.contains(variadicSubstring)) {
                        variadicFunctionNames.add(name);
                        namesToParameters.put(name, getParameters(function));
                        namesToReturn.put(name, function.getReturnType());
                        break;
                    }
                }
            }
			monitor.checkCanceled();
		}

		Iterator<Function> functionsToSearchIterator = selection != null
				? currentProgram.getFunctionManager()
						.getFunctionsOverlapping(selection)
				: currentProgram.getFunctionManager().getFunctionsNoStubs(true);

		// Find functions that call variadic functions
		while (functionsToSearchIterator.hasNext()) {
			Function function = functionsToSearchIterator.next();
			Set<Function> calledFunctions = function.getCalledFunctions(monitor);
			for (Function calledFunction : calledFunctions) {
				// If this function calls a variadic function, add it to functions to decompile
				if (namesToParameters.containsKey(calledFunction.getName())) {
					toDecompile.add(function);
					break;
				}
			}
			monitor.checkCanceled();
		}

		decompile(currentProgram, monitor, stringsByAddress, variadicFunctionNames,
			namesToParameters,
			namesToReturn,
			toDecompile);
	}

	private void decompile(Program program, TaskMonitor monitor,
			Map<Address, Data> stringsByAddress,
			Set<String> variadicFunctionNames,
			Map<String, List<DataType>> namesToParameters, Map<String, DataType> namesToReturn,
			Set<Function> toDecompile) {

		DecompilerCallback<Void> callback = initDecompilerCallback(program, stringsByAddress,
			variadicFunctionNames, namesToParameters, namesToReturn);
		if (toDecompile.isEmpty()) {
			Msg.info(this, "No functions detected that make variadic function calls with " +
				"format strings containing format specifiers");
			return;
		}
		try {
			ParallelDecompiler.decompileFunctions(callback, toDecompile, monitor);
		}
		catch (Exception e) {
			Msg.error(this, "Error: could not decompile functions with ParallelDecompiler", e);
		}
		finally {
			callback.dispose();
		}
	}

	private DecompilerCallback<Void> initDecompilerCallback(Program program,
			Map<Address, Data> stringsByAddress,
			Set<String> variadicFuncNames, Map<String, List<DataType>> namesToParameters,
			Map<String, DataType> namesToReturn) {
		return new DecompilerCallback<>(program,
			new VariadicSignatureDecompileConfigurer()) {
			@Override
			public Void process(DecompileResults results, TaskMonitor tMonitor) throws Exception {
				if (results == null) {
					return null;
				}
				Function function = results.getFunction();
				PcodeFunctionParser pcodeParser = new PcodeFunctionParser(program);
				if (results.getHighFunction() == null ||
					results.getHighFunction().getPcodeOps() == null) {
					return null;
				}
				Iterator<PcodeOpAST> pcodeOpASTIterator = results.getHighFunction().getPcodeOps();
				List<PcodeOpAST> pcodeOpASTs = new ArrayList<>();
				if ((results.getHighFunction() != null) && pcodeOpASTIterator != null) {
					while (pcodeOpASTIterator.hasNext()) {
						PcodeOpAST pcodeAST = pcodeOpASTIterator.next();
						pcodeOpASTs.add(pcodeAST);
					}
				}
				List<FunctionCallData> functionCallDataList = pcodeParser.parseFunctionForCallData(
					pcodeOpASTs, stringsByAddress, variadicFuncNames);
				if (functionCallDataList != null && functionCallDataList.size() > 0) {
					overrideCallList(program, function, functionCallDataList, namesToParameters,
						namesToReturn);
				}
				tMonitor.checkCanceled();
				return null;
			}
		};
	}

	private List<DataType> getParameters(Function function) {
		// NOTE: Currently only considers variadic functions with format string
		// arguments.
		List<DataType> dataTypes = new ArrayList<>();
		for (ParameterDefinition pd : function.getSignature().getArguments()) {
			dataTypes.add(pd.getDataType());
		}
		return dataTypes;
	}

	private boolean usesVariadicFormatString(Function function) {
		int paramCount = function.getParameterCount();
		return function.hasVarArgs() && paramCount > 0 &&
			isCharPointer(function.getParameters()[paramCount - 1].getDataType());
	}

	private boolean isCharPointer(DataType dataType) {
		if (dataType instanceof TypeDef) {
			dataType = ((TypeDef) dataType).getBaseDataType();
		}
		if (!(dataType instanceof Pointer)) {
			return false;
		}
		DataType dt = ((Pointer) dataType).getDataType();
		return dt instanceof CharDataType || dt instanceof WideCharDataType ||
			dt instanceof WideChar16DataType || dt instanceof WideChar32DataType;
	}

	private class VariadicSignatureDecompileConfigurer implements DecompileConfigurer {

		// DecompInterface allows for control of decompilation processes
		@Override
		public void configure(DecompInterface decompiler) {
			decompiler.toggleCCode(true); // Produce C code
			decompiler.toggleSyntaxTree(true); // Produce syntax tree
			decompiler.openProgram(currentProgram);
			decompiler.setSimplificationStyle("normalize");
			DecompileOptions options = new DecompileOptions();
			options.grabFromProgram(currentProgram);
			decompiler.setOptions(options);
		}
	}

	private ParameterDefinition[] parseParameters(Function function,
			Address address,
			String callFunctionName, String formatString,
			Map<String, List<DataType>> namesToParameters) {

		Program functionProgram = function.getProgram();

		FormatStringParser parser = getParser();

		// DataTypes of arguments are treated differently when the variadic function
		// looks like scanf since it takes in inputs. We need this information
		// so that the correct DataType arguments are generated
		boolean isOutputType = !callFunctionName.contains(INPUT_FUNCTION_SUBSTRING);
		List<FormatArgument> formatArguments =
			parser.convertToFormatArgumentList(formatString, isOutputType);

		DataType[] dataTypes = isOutputType ? parser.convertToOutputDataTypes(formatArguments)
				: parser.convertToInputDataTypes(formatArguments);

		if (dataTypes == null) {

			currentProgram.getBookmarkManager()
					.setBookmark(address, BookmarkType.ANALYSIS, "Unrecognized format string",
						"Format string could not be parsed: " + formatString);
			return null;
		}
		ParameterDefinition[] paramDefs =
			createParameters(callFunctionName, dataTypes, functionProgram, namesToParameters);
		return paramDefs;
	}

	private ParameterDefinition[] createParameters(String callFunctionName, DataType[] dataTypes,
			Program program, Map<String, List<DataType>> namesToParameters) {
		List<DataType> initialFunctionParameters = namesToParameters.get(callFunctionName);
		int numberOfParameters = initialFunctionParameters.size() + dataTypes.length;
		if (numberOfParameters == 0) {
			return null; // Invalid function
		}
		ParameterDefinition[] parameterDefinitions = new ParameterDefinition[numberOfParameters];
		for (int i = 0; i < numberOfParameters; i++) {
			if (i < initialFunctionParameters.size()) {
				parameterDefinitions[i] =
					new ParameterDefinitionImpl("param" + i, initialFunctionParameters.get(i), "");
			}
			else {
				parameterDefinitions[i] = new ParameterDefinitionImpl("param" + i,
					dataTypes[i - initialFunctionParameters.size()], "");
			}
		}
		return parameterDefinitions;
	}

	private FunctionSignature initSignature(Function function, Address address,
			String callFunctionName, String formatString,
			Map<String, List<DataType>> namesToParameters, Map<String, DataType> namesToReturn) {
		ParameterDefinition[] parameterDefinitions =
			parseParameters(function, address, callFunctionName, formatString, namesToParameters);
		if (parameterDefinitions == null || parameterDefinitions.length == 0) {
			return null;
		}

		FunctionDefinitionDataType signature = new FunctionDefinitionDataType(callFunctionName);
		signature.setArguments(parameterDefinitions);
		signature.setReturnType(namesToReturn.get(callFunctionName));
		return signature;
	}

	private void overrideCallList(Program program, Function function,
			List<FunctionCallData> functionCallDataList,
			Map<String, List<DataType>> namesToParameters, Map<String, DataType> namesToReturn) {
		if (function == null || functionCallDataList == null) {
			return;
		}
		for (FunctionCallData data : functionCallDataList) {
			overrideFunctionCall(program, function, data.getAddressOfCall(), data.getCallFuncName(),
				data.getFormatString(), namesToParameters, namesToReturn);
		}
	}

	private void overrideFunctionCall(Program program, Function function, Address address,
			String callFunctionName, String formatString,
			Map<String, List<DataType>> namesToParameters,
			Map<String, DataType> namesToReturn) {
		if (formatString == null) {
			return;
		}
		FunctionSignature functionSignature = initSignature(function, address, callFunctionName,
			formatString, namesToParameters, namesToReturn);
		if (functionSignature == null || function == null || address == null) {
			return;
		}

		try {
			if (createBookmarksEnabled) {
				BookmarkManager bookmark = program.getBookmarkManager();
				bookmark.setBookmark(address, BookmarkType.ANALYSIS,
					"Function Signature Override",
					"Override for call to function " + callFunctionName);
			}
			HighFunctionDBUtil.writeOverride(function, address, functionSignature);
		}
		catch (InvalidInputException e) {
			Msg.error(this, "Error: invalid input given to writeOverride()", e);
		}
	}

	@Override
	public boolean removed(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		return false;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled, null,
			OPTION_DESCRIPTION_CREATE_BOOKMARKS);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		createBookmarksEnabled =
			options.getBoolean(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled);
	}
}
