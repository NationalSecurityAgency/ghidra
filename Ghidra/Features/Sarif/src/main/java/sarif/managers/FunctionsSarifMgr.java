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
package sarif.managers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.swing.Icon;

import com.google.gson.JsonArray;

import generic.theme.GIcon;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.SymbolPath;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.listing.VariableUtilities;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import sarif.SarifProgramOptions;
import sarif.export.SarifWriterTask;
import sarif.export.func.SarifFunctionWriter;

public class FunctionsSarifMgr extends SarifMgr {

	public static String KEY = "FUNCTIONS";

	public final static String LIB_BOOKMARK_CATEGORY = "Library Identification";
	public final static String FID_BOOKMARK_CATEGORY = "Function ID Analyzer";
	public static final Set<String> LIBRARY_BOOKMARK_CATEGORY_STRINGS = Set.of(LIB_BOOKMARK_CATEGORY,
			FID_BOOKMARK_CATEGORY);

	private DtParser dtParser;
	private Library extenalNamespace;

	FunctionsSarifMgr(Program program, MessageLog log) {
		super(KEY, program, log);
		int txId = program.startTransaction("SARIF FunctionMgr");
		try {
			SymbolTable symbolTable = program.getSymbolTable();
			Symbol extLib = symbolTable.getLibrarySymbol("<EXTERNAL>");
			if (extLib == null) {
				extenalNamespace = symbolTable.createExternalLibrary(Library.UNKNOWN, SourceType.IMPORTED);
			}
		} catch (Exception e) {
			log.appendException(e);
		} finally {
			program.endTransaction(txId, true);
		}
	}

	////////////////////////////
	// SARIF READ CURRENT DTD //
	////////////////////////////

	@Override
	protected void readResults(List<Map<String, Object>> list, SarifProgramOptions options, TaskMonitor monitor)
			throws AddressFormatException, CancelledException {
		if (list != null) {
			monitor.setMessage("Processing " + key + "...");
			monitor.setMaximum(list.size() * 2);
			firstPass = true;
			for (Map<String, Object> result : list) {
				monitor.checkCancelled();
				read(result, options, monitor);
				monitor.increment();
			}
			firstPass = false;
			for (Map<String, Object> result : list) {
				monitor.checkCancelled();
				read(result, options, monitor);
				monitor.increment();
			}
			monitor.incrementProgress();
		} else {
			monitor.setMessage("Skipping over " + key + " ...");
		}
	}

	/**
	 * Parses a list of {@link Function function} definitions from SARIF and creates
	 * then, adding them to the current {@link Program program}.
	 * <p>
	 * Information from a TYPEINFO_COMMENT is used in preference to information from
	 * RETURN_TYPE and STACK_FRAME/STACK_VARs that are tagged as parameters.
	 * <p>
	 * DTD for the FUNCTION element:
	 * 
	 * <pre>
	 * <code>
	 * &lt;!ELEMENT FUNCTION (RETURN_TYPE?, ADDRESS_RANGE*, REGULAR_CMT?, REPEATABLE_CMT?, TYPEINFO_CMT?, STACK_FRAME?, REGISTER_VAR*)&gt;
	 * </code>
	 * </pre>
	 * <p>
	 * 
	 * @param result             the parser
	 * @param overwriteConflicts true to overwrite any conflicts
	 * @param monitor            the task monitor
	 * @throws AddressFormatException if any address is not parsable
	 * @throws CancelledException     if the operation is cancelled through the
	 *                                monitor
	 */
	@SuppressWarnings("unchecked")
	@Override
	public boolean read(Map<String, Object> result, SarifProgramOptions options, TaskMonitor monitor)
			throws AddressFormatException, CancelledException {

		DataTypeManager dataManager = listing.getDataTypeManager();
		BuiltInDataTypeManager builtInMgr = BuiltInDataTypeManager.getDataTypeManager();

		try {
			dtParser = new DtParser(dataManager);

			try {
				String key = (String) result.get("Message");
				boolean isThunk = (boolean) result.get("isThunk");
				boolean process = (firstPass && !isThunk) || (!firstPass && isThunk);
				if (!key.equals("Function") || !process) {
					return true;
				}

				Address entryPoint = getEntryPoint(result);
				// Grab the original symbols
				Symbol[] symbols = program.getSymbolTable().getSymbols(entryPoint);

				Function func = createFunction(result, isThunk, entryPoint);

				// Restore the original labels
				for (Symbol symbol : symbols) {
					SourceType srcType = symbol.getSource();
					if (!srcType.equals(SourceType.DEFAULT)) {
						program.getSymbolTable().createLabel(entryPoint, symbol.getName(true), srcType);
					}
				}

				String source = (String) result.get("sourceType");
				SourceType sourceType = source.equals("DEFAULT") ? SourceType.IMPORTED : getSourceType(source);
				String typeInfoComment = setProperties(result, func, entryPoint);

				// Process stack
				List<Variable> stackParams = new ArrayList<>();
				List<Map<String, Object>> regVars = (List<Map<String, Object>>) result.get("regVars");
				for (Map<String, Object> var : regVars) {
					readRegisterVars(var, func, stackParams);
				}

				Map<String, Object> stack = (Map<String, Object>) result.get("stack");
				readStackFrame(stack, func, stackParams, sourceType);

				List<Map<String, Object>> parms = (List<Map<String, Object>>) result.get("params");
				List<Variable> formalParams = new ArrayList<>();
				for (Map<String, Object> p : parms) {
					readParameter(p, func, formalParams);
				}

				// Process formal parameters and return
				Map<String, Object> ret = (Map<String, Object>) result.get("ret");
				ReturnParameterImpl retImpl = null;
				if (ret != null) {
					retImpl = readReturnType(ret, func);
				}
				List<Variable> plist = stackParams;
				if (typeInfoComment != null) {
					plist = formalParams;
				}

				if (plist != null) {
					updateFunction(func, retImpl, plist, sourceType);
				}

				postProcess(result, func, stack);

			} catch (Exception e) {
				log.appendException(e);
			}
		} finally {
			builtInMgr.close();
		}
		return true;
	}

	private Address getEntryPoint(Map<String, Object> result) throws AddressFormatException {
		String entryPointStr = (String) result.get("location");
		if (entryPointStr == null) {
			throw new RuntimeException("No entry point provided.");
		}
		Address entryPoint = parseAddress(factory, entryPointStr);
		if (entryPoint == null) {
			throw new AddressFormatException("Incompatible Function Entry Point Address: " + entryPointStr);
		}
		return entryPoint;
	}

	private Function createFunction(Map<String, Object> result, boolean isThunk, Address entryPoint)
			throws InvalidInputException, OverlappingFunctionException, DuplicateNameException,
			AddressOverflowException {
		AddressSet body = new AddressSet(entryPoint, entryPoint);
		getLocations(result, body);
		Function func = program.getFunctionManager().getFunctionAt(entryPoint);
		if (func == null) {
			String source = (String) result.get("sourceType");
			SourceType sourceType = getSourceType(source);
			func = program.getFunctionManager().createFunction(null, null, entryPoint, body, sourceType);
		}

		String name = (String) result.get("name");
		if (isThunk) {
			createThunk(result, func);
		}
		setName(entryPoint, func, name, result);
		return func;
	}

	private void setName(Address entryPoint, Function func, String name, Map<String, Object> result) {
		SymbolPath path = new SymbolPath(name);
		if (name != null) {
			String nss = (String) result.get("namespace");
			boolean isThunk = (boolean) result.get("isThunk");
			if (nss != null && !isThunk) {
				SymbolPath parentPath = new SymbolPath(nss);
				if (!name.startsWith(nss)) {
					path = new SymbolPath(parentPath, name);
				}
			}
			name = path.getName();
		}

		Symbol symbol = func.getSymbol();
		if (path != null) {
			try {
				Namespace ns = NamespaceUtils.getFunctionNamespaceAt(program, path, entryPoint);
				if (ns == null) {
					ns = program.getGlobalNamespace();
					SymbolPath parent = path.getParent();
					if (parent != null && !parent.getName().equals(ns.getName())) {
						Boolean isClass = (Boolean) result.get("namespaceIsClass");
						String source = (String) result.get("sourceType");
						SourceType sourceType = source.equals("DEFAULT") ? SourceType.IMPORTED : getSourceType(source);
						ns = walkNamespace(program.getGlobalNamespace(), parent.getPath() + "::", entryPoint,
								sourceType, isClass);
						symbol.setNameAndNamespace(name, ns, getSourceType("DEFAULT"));
						return;
					}
				}
				if (path != null && path.getName().contains(Library.UNKNOWN)) {
					ns = extenalNamespace;
				}
				if (ns.getParentNamespace() == null) {
					symbol.setName(name, getSourceType("DEFAULT"));
				} else {
					symbol.setNameAndNamespace(name, ns.getParentNamespace(), getSourceType("DEFAULT")); // symbol.getSource());
				}
			} catch (Exception e) {
				// name may already be set if symbols were loaded...
			}
		}
	}

	private String setProperties(Map<String, Object> result, Function func, Address entryPoint)
			throws InvalidInputException {
		boolean isLibrary = (boolean) result.get("isLibrary");
		if (isLibrary) {
			BookmarkManager bm = program.getBookmarkManager();
			BookmarkType bt = bm.getBookmarkType("IMPORTED");
			if (bt == null) {
				Icon icon = new GIcon("icon.base.util.xml.functions.bookmark");
				bt = bm.defineType("IMPORTED", icon, Palette.DARK_GRAY, 0);
			}
			bm.setBookmark(entryPoint, "IMPORTED", LIB_BOOKMARK_CATEGORY, "Library function");
		}

		String callingConvention = (String) result.get("callingConvention");
		if (callingConvention != null) {
			func.setCallingConvention(callingConvention);
		}

		boolean hasVarArgs = (boolean) result.get("hasVarArgs");
		boolean isInline = (boolean) result.get("isInline");
		boolean hasNoReturn = (boolean) result.get("hasNoReturn");
		boolean hasCustomStorage = (boolean) result.get("hasCustomStorage");
		func.setVarArgs(hasVarArgs);
		func.setInline(isInline);
		func.setNoReturn(hasNoReturn);
		func.setCustomVariableStorage(hasCustomStorage);

		String regularComment = (String) result.get("comment");
		func.setComment(regularComment);
		String repeatableComment = (String) result.get("repeatableComment");
		func.setRepeatableComment(repeatableComment);
		String typeInfoComment = (String) result.get("value");
		return typeInfoComment;
	}

	private void updateFunction(Function func, ReturnParameterImpl retImpl, List<Variable> plist,
			SourceType sourceType) {
		try {
			Variable[] arr = new Variable[plist.size()];
			int i = 0;
			for (Variable variable : plist) {
				arr[i++] = variable;
			}
			FunctionUpdateType type = func.hasCustomVariableStorage() ? FunctionUpdateType.CUSTOM_STORAGE
					: FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS;
			func.updateFunction(func.getCallingConventionName(), retImpl, type, true, SourceType.IMPORTED, arr);
		} catch (DuplicateNameException e) {
			log.appendMsg("Could not set name of a parameter in function: " + funcDesc(func) + ": " + e.getMessage());
		} catch (InvalidInputException iie) {
			log.appendMsg("Bad parameter definition in function: " + funcDesc(func) + ": " + iie.getMessage());
		}
	}

	private void postProcess(Map<String, Object> result, Function func, Map<String, Object> stack) {
		String signatureSource = (String) result.get("signatureSource");
		if (signatureSource != null) {
			SourceType signatureSourceType = getSourceType(signatureSource);
			func.setSignatureSource(signatureSourceType);
		}

		Boolean purgeValid = (Boolean) result.get("isStackPurgeSizeValid");
		Double purgeSize = (Double) stack.get("purgeSize");
		if (purgeSize != null) {
			if (purgeValid == null) {
				func.setStackPurgeSize((int) (double) purgeSize);
			} else {
				func.setStackPurgeSize(purgeValid ? (int) (double) purgeSize : Function.UNKNOWN_STACK_DEPTH_CHANGE);
			}
		}
	}

	private void createThunk(Map<String, Object> result, Function func)
			throws InvalidInputException, DuplicateNameException {
		String thunkStr = (String) result.get("thunkAddress");
		if (thunkStr == null) {
			throw new RuntimeException("No thunk address provided.");
		}
		Function thunkFn = null;
		Address thunk = parseAddress(factory, thunkStr);
		if (thunk.isExternalAddress()) {
			Symbol symbol = externalMap.get(thunkStr).getSymbol();
			if (symbol.getSymbolType() == SymbolType.FUNCTION) {
				thunkFn = (Function) symbol.getObject();
				func.setThunkedFunction(thunkFn);
			}
		} else {
			thunkFn = program.getFunctionManager().getFunctionAt(thunk);
			if (thunkFn == null) {
				CreateFunctionCmd cmd = new CreateFunctionCmd(thunk);
				if (!cmd.applyTo(program)) {
					Msg.error(this, "Failed to create function at " + thunk + ": " + cmd.getStatusMsg());
				}
				thunkFn = cmd.getFunction();
			}
			func.setThunkedFunction(thunkFn);
		}
	}

	private void addLocalVar(Function function, Variable v, SourceType sourceType, boolean overwriteConflicts) throws InvalidInputException {
		VariableUtilities.checkVariableConflict(function, v, v.getVariableStorage(), overwriteConflicts);

		try {
			function.addLocalVariable(v, sourceType);
		} catch (DuplicateNameException e) {
			log.appendMsg("Could not add local variable to function " + funcDesc(function) + ": " + v.getName() + ": "
					+ e.getMessage());
		}
	}

	private static String funcDesc(Function func) {
		return func.getName() + "[" + func.getEntryPoint().toString() + "]";
	}

	private DataType findDataType(Map<String, Object> result) {
		String name = (String) result.get("name");
		if (name == null) {
			return DataType.DEFAULT;
		}
		CategoryPath cp = new CategoryPath((String) result.get("location"));
		Double size = (Double) result.get("size");
		return dtParser.parseDataType(name, cp, size == null ? -1 : (int) (double) size);
	}

	@SuppressWarnings("unchecked")
	private void readStackFrame(Map<String, Object> result, Function func, List<Variable> stackParams, SourceType sourceType) {
		if (func == null) {
			return;
		}
		StackFrame frame = func.getStackFrame();

		Double localVarSize = (Double) result.get("localVarSize");
		if (localVarSize != null) {
			frame.setLocalSize((int) (double) localVarSize);
		}
//		Double paramOffset = (Double) result.get("parameterOffset");
//		if (paramOffset != null) {
//			frame.setParameterOffset((int) (double) paramOffset));
//		}
		Double retOffset = (Double) result.get("returnAddressOffset");
		if (retOffset != null) {
			frame.setReturnAddressOffset((int) (double) retOffset);
		}
//		Double purgeSize = (Double) result.get("purgeSize");
//		if (purgeSize != null && validPurge) {
//			func.setStackPurgeSize((int) (double) purgeSize);
//		}
		List<Map<String, Object>> stackVars = (List<Map<String, Object>>) result.get("stackVars");
		for (Map<String, Object> var : stackVars) {
			readVariable(var, func, stackParams, sourceType);
		}
	}

	@SuppressWarnings("unchecked")
	private void readVariable(Map<String, Object> result, Function function, List<Variable> stackParams, SourceType sourceType) {

		int offset = (int) (double) result.get("offset");
		int size = (int) (double) result.get("size");

		Map<String, Object> type = (Map<String, Object>) result.get("type");
		DataType dt = findDataType(type);
		if (dt == null) {
			log.appendMsg("Missing datatype: " + type.get("name"));
			dt = Undefined.getUndefinedDataType(size);
		}

		String name = (String) result.get("name");
		if (name != null) {
			name = getUniqueVarName(function, name, offset);
		}

		try {
			Variable var = new LocalVariableImpl(name, dt, offset, program);
			VariableUtilities.checkVariableConflict(function, var, var.getVariableStorage(), true);

			StackFrame stackFrame = function.getStackFrame();
			boolean isParameter = stackFrame.isParameterOffset(offset);
			if (!isParameter) {
				isParameter = stackFrame.isParameterOffset(offset + size - 1);
			}
			if (isParameter) {
				var = new ParameterImpl(name, dt, offset, program);
				stackParams.add(var);
			} else {
				var = new LocalVariableImpl(name, dt, offset, program);
				addLocalVar(function, var, sourceType, true);
			}
			String regularComment = (String) result.get("comment");
			var.setComment(regularComment);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}

	@SuppressWarnings("unchecked")
	private DataType readParameter(Map<String, Object> result, Function function, List<Variable> formalParams) {

		String name = (String) result.get("name");
		// int ordinal = (int) (double) result.get("ordinal");
		int size = (int) (double) result.get("size");
		String regularComment = (String) result.get("comment");

		Map<String, Object> type = (Map<String, Object>) result.get("formalType");
		DataType dt = findDataType(type);
		if (dt == null) {
			log.appendMsg("Missing datatype: " + type.get("name"));
			dt = Undefined.getUndefinedDataType(size);
		}

		try {
			ParameterImpl var;

			ProgramContext context = program.getProgramContext();
			List<String> rnames = (List<String>) result.get("registers");
			if (rnames != null) {
				if (formalParams != null) {
					for (String r : rnames) {
						Register register = context.getRegister(r);
						var = new ParameterImpl(name, dt, register, program);
						var.setComment(regularComment);
						formalParams.add(var);
					}
				}
				return dt;
			}

			int offset = (int) (double) result.get("stackOffset");
			if (formalParams != null) {
				var = new ParameterImpl(name, dt, offset, program);
				var.setComment(regularComment);
				formalParams.add(var);
			}
			return dt;
		} catch (InvalidInputException e) {
			log.appendException(e);
			return null;
		}
	}

	@SuppressWarnings("unchecked")
	private ReturnParameterImpl readReturnType(Map<String, Object> result, Function function) {

		int size = (int) (double) result.get("size");
		int offset = (int) (double) result.get("stackOffset");

		Map<String, Object> type = (Map<String, Object>) result.get("formalType");
		DataType dt = findDataType(type);
		if (dt == null) {
			log.appendMsg("Missing datatype: " + type.get("name"));
			dt = Undefined.getUndefinedDataType(size);
		}

		try {
			List<String> rnames = (List<String>) result.get("registers");
			if (rnames != null) {
				List<Varnode> vnodes = convertRegisterListToVarnodeStorage(rnames, dt.getLength(), offset);
				VariableStorage returnStorage = new VariableStorage(program, vnodes);
				return new ReturnParameterImpl(dt, returnStorage, true, program);
			}

			if (offset >= 0) {
				return new ReturnParameterImpl(dt, offset, program);
			}
			return new ReturnParameterImpl(dt, program);
		} catch (InvalidInputException e) {
			log.appendException(e);
			return null;
		}
	}

	private String getUniqueVarName(Function function, String name, int offset) {
		Symbol s = program.getSymbolTable().getVariableSymbol(name, function);
		if (s == null) {
			return name;
		}
		SymbolType st = s.getSymbolType();
		if (st == SymbolType.LOCAL_VAR || st == SymbolType.PARAMETER) {
			Variable v = (Variable) s.getObject();
			if (v.isStackVariable() && offset == v.getStackOffset()) {
				return name;
			}
		}
		return name + "_" + offset;
	}

	@SuppressWarnings("unchecked")
	private void readRegisterVars(Map<String, Object> result, Function function, List<Variable> stackParams) {
		try {
			ProgramContext context = program.getProgramContext();
			String name = (String) result.get("name");
			String registerName = (String) result.get("register");
			if (registerName == null) {
				return;
			}
			Register register = context.getRegister(registerName);

			Map<String, Object> type = (Map<String, Object>) result.get("type");
			DataType dt = findDataType(type);
			if (dt != null && dt.getLength() > register.getMinimumByteSize()) {
				log.appendMsg("Data type [" + result.get("type") + "] too large for register [" + registerName + "]");
				dt = null;
			}

			Variable registerParam = new ParameterImpl(name, dt, register, program);
			String comment = (String) result.get("comment");
			registerParam.setComment(comment);

			stackParams.add(registerParam);
		} catch (InvalidInputException e) {
			log.appendException(e);
		} catch (IllegalArgumentException e) {
			log.appendException(e);
		}
	}

	public List<Varnode> convertRegisterListToVarnodeStorage(List<String> registNames, int dataTypeSize,
			int stackOffset) {
		List<Varnode> results = new ArrayList<>();
		ProgramContext context = program.getProgramContext();
		for (String rname : registNames) {
			Register reg = context.getRegister(rname);
			int regSize = reg.getMinimumByteSize();
			int bytesUsed = Math.min(dataTypeSize, regSize);
			Address addr = reg.getAddress();
			if (reg.isBigEndian() && bytesUsed < regSize) {
				addr = addr.add(regSize - bytesUsed);
			}
			results.add(new Varnode(addr, bytesUsed));
			dataTypeSize -= bytesUsed;
		}
		if (dataTypeSize != 0 && stackOffset >= 0) {
			results.add(new Varnode(program.getAddressFactory().getStackSpace().getAddress(stackOffset), dataTypeSize));
		}
		return results;
	}

	/////////////////////////////
	// SARIF WRITE CURRENT DTD //
	/////////////////////////////

	void write(JsonArray results, AddressSetView addrs, TaskMonitor monitor) throws IOException, CancelledException {
		monitor.setMessage("Writing FUNCTIONS ...");

		List<Function> request = new ArrayList<>();
		FunctionIterator iter = listing.getFunctions(addrs, true);
		while (iter.hasNext()) {
			request.add(iter.next());
		}

		writeAsSARIF(program, request, results);
	}

	public static void writeAsSARIF(Program program, List<Function> request, JsonArray results) throws IOException {
		SarifFunctionWriter writer = new SarifFunctionWriter(program.getFunctionManager(), request, null);
		new TaskLauncher(new SarifWriterTask("Functions", writer, results), null);
	}

}
