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
package ghidra.test.compilers.support;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.function.Consumer;

import org.apache.commons.lang3.ArrayUtils;

import com.google.common.primitives.*;

import ghidra.app.cmd.function.ApplyFunctionDataTypesCmd;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.floatformat.FloatFormat;
import ghidra.pcode.floatformat.FloatFormatFactory;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.DataConverter;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Utility for testing prototype models defined in cspec files.
 */
public class CSpecPrototypeTestUtil {

	private static HexFormat hexFormat = HexFormat.of();

	public static record TestResult(String message, boolean hasError) {}

	/**
	 * Returns a byte array that represents parameters from the emulator.
	 * This data is used to compare against the representation of parameters constructed from
	 * the binary's source code.
	 * @param emulatorThread the active emulator thread to inspect
	 * @param piece basic elements of a parameter
	 * @param addrSpace the address space where the stack resides 
	 * @param stackReg the register acting as the stack pointer 
	 * @param langCompPair the language/compiler specification pair
	 * @param dataConverter used to determine endianness and convert data to byte representation.
	 * @return byte[] byte array representation of parameter pieces
	 * @throws Exception if there is a problem reading the emulator stack or getting the correct
	 * language.
	 */
	public static byte[] readParameterPieces(PcodeThread<byte[]> emulatorThread,
			ParameterPieces piece,
			AddressSpace addrSpace, Register stackReg, LanguageCompilerSpecPair langCompPair,
			DataConverter dataConverter)
			throws Exception {
		if (piece.type instanceof VoidDataType) {
			return new byte[0];
		}
		if (piece.joinPieces != null) {
			Varnode[] varnodes = piece.joinPieces.clone();
			if (!langCompPair.getLanguage().isBigEndian()) {
				ArrayUtils.reverse(varnodes); // probably correct...
			}
			byte[] bytes = null;
			for (Varnode vn : varnodes) {
				byte[] varnodeBytes = null;

				if (vn.getAddress().isStackAddress()) {
					varnodeBytes =
						readEmulatorStack(emulatorThread, stackReg, addrSpace, (int) vn.getOffset(),
							vn.getSize(), dataConverter);
				}
				else {
					varnodeBytes =
						readEmulatorMemory(emulatorThread, vn.getAddress(), vn.getSize());
				}
				bytes = ArrayUtils.addAll(bytes, varnodeBytes);
			}
			return bytes;
		}
		int dataTypeSize = piece.type.getLength();
		byte[] bytes = null;
		if (piece.address.isStackAddress()) {
			bytes =
				readEmulatorStack(emulatorThread, stackReg, addrSpace,
					(int) piece.address.getOffset(),
					dataTypeSize, dataConverter);
		}
		else {
			bytes = readEmulatorMemory(emulatorThread, piece.address, dataTypeSize);
		}
		if ((piece.hiddenReturnPtr || piece.isIndirect) && (piece.address != null)) {
			// value is an address, we need to verify the value stored there
			if (!(piece.type instanceof PointerDataType pointerType)) {
				return bytes;
			}
			if (!langCompPair.getLanguage().isBigEndian()) {
				ArrayUtils.reverse(bytes);
			}
			long offset = -1;
			switch (bytes.length) {
				case 2:
					offset = Shorts.fromByteArray(bytes);
					break;
				case 4:
					offset = Ints.fromByteArray(bytes);
					break;
				case 8:
					offset = Longs.fromByteArray(bytes);
					break;
				default:
					throw new AssertionError("unsupported size: " + bytes.length);
			}
			Address addr = addrSpace.getAddress(offset);
			DataType base = pointerType.getDataType();
			bytes = readEmulatorMemory(emulatorThread, addr, base.getLength());
		}
		return bytes;
	}

	/**
	 * Reads data from emulator's memory at the given Address and for the given size and returns as
	 * a byte array.
	 * @param emulatorThread the active emulator thread to inspect
	 * @param address Address of memory to read
	 * @param size Size of memory chunk to read
	 * @return byte[] containing the data read from the emulator's memory
	 */
	public static byte[] readEmulatorMemory(PcodeThread<byte[]> emulatorThread, Address address,
			int size) {
		return emulatorThread.getState().getVar(address, size, false, Reason.INSPECT);
	}

	/**
	 * Reads data from the emulator's stack memory by resolving the current stack pointer 
	 * and applying a specified offset.
	 * @param emulatorThread the active emulator thread to inspect
	 * @param stackReg the register acting as the stack pointer 
	 * @param addrSpace the address space where the stack resides 
	 * @param offset the byte offset from the stack pointer
	 * @param size the number of bytes to read from the stack
	 * @param dataConverter the converter used to interpret the stack pointer's endianness
	 * @return byte[] containing the data read from the emulator's memory
	 * @throws Exception if the register cannot be read or the address is invalid within the state
	 */
	public static byte[] readEmulatorStack(PcodeThread<byte[]> emulatorThread, Register stackReg,
			AddressSpace addrSpace, int offset, int size, DataConverter dataConverter)
			throws Exception {
		byte[] stackPtr = emulatorThread.getState().getVar(stackReg, Reason.INSPECT);
		ByteBuffer stackPtrBuf = ByteBuffer.wrap(stackPtr);
		stackPtrBuf.order(
			dataConverter.isBigEndian() ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
		long stackPtrVal;
		if (stackPtr.length >= 8) {
			stackPtrVal = stackPtrBuf.getLong();
		}
		// Avoid sign-extending negative values
		else if (stackPtr.length >= 4) {
			stackPtrVal = Integer.toUnsignedLong(stackPtrBuf.getInt());
		}
		else {
			stackPtrVal = Short.toUnsignedLong(stackPtrBuf.getShort());
		}
		Address addr = addrSpace.getAddress(stackPtrVal + offset);
		return emulatorThread.getState().getVar(addr, size, false, Reason.INSPECT);
	}

	/**
	 * For a given function, and list of parameter pieces, return a list of bytes representing the 
	 * values of the parameters. This data is produced from the source code of the binary which is 
	 * used in cspec tests to compare against the list of bytes representing parameter values from 
	 * the emulator.
	 * @param func Function to get the parameter values of.
	 * @param pieces ParameterPieces representing basic elements of the parameters of the function.
	 * @param dataConverter used to convert data to bytes and vice versa.
	 * @param logger {@code Consumer<String>} lambda function to print logging information
	 * @return {@code List<byte[]>} byte representation of function parameter values
	 * @throws MemoryAccessException if there is a problem accessing the function's program memory.
	 */
	public static List<byte[]> getPassedValues(Function func, List<ParameterPieces> pieces,
			DataConverter dataConverter, Consumer<String> logger)
			throws MemoryAccessException {
		Program program = func.getProgram();
		List<byte[]> groundTruth = new ArrayList<>();
		for (int i = 0; i < pieces.size(); ++i) {
			ParameterPieces piece = pieces.get(i);
			DataType dt = piece.type;
			if (dt == null) {
				throw new AssertionError("null datatype for piece " + i + " in " + func.getName());
			}
			if (dt instanceof VoidDataType) {
				groundTruth.add(new byte[0]); // for testing return values
				continue;
			}
			boolean isPointer = false;
			DataType baseType = dt;
			if (dt instanceof Pointer pointer) {
				baseType = pointer.getDataType();
				isPointer = true;
			}
			int index = i;
			if (i >= 1) {
				Parameter param = func.getParameter(i - 1);
				if (param != null) {
					AutoParameterType autoType = param.getAutoParameterType();
					if (autoType != null &&
						param.getAutoParameterType().equals(AutoParameterType.RETURN_STORAGE_PTR)) {
						index = 0;
					}
				}
			}

			String symbolName = baseType.getName() + "_" + Integer.toString(index);
			Symbol symbol = program.getSymbolTable().getSymbols(symbolName).next();
			if (symbol == null) {
				// Sometimes compilers will prepend a leading underscore to symbol names
				// try -fno-leading-underscore
				symbolName = "_" + symbolName;
				symbol = program.getSymbolTable().getSymbols(symbolName).next();
				if (symbol == null) {
					throw new AssertionError("null Symbol for name " + symbolName + " in " +
						func.getName() + " piece " + i);
				}

			}
			byte[] value = new byte[dt.getLength()];
			if (isPointer) {
				if ((piece.hiddenReturnPtr || piece.isIndirect) && (piece.address != null)) {
					value = new byte[baseType.getLength()];
					program.getMemory().getBytes(symbol.getAddress(), value);
				}
				else {
					long offset = symbol.getAddress().getAddressableWordOffset();
					dataConverter.getBytes(offset, dt.getLength(), value, 0);
				}
			}
			else {
				program.getMemory().getBytes(symbol.getAddress(), value);
				// handle calling-convention enforced conversions, such as 
				// converting floats to doubles
				if (piece.joinPieces != null && piece.joinPieces.length == 1 &&
					piece.joinPieces[0].getSize() != dt.getLength()) {
					value = getExtendedValue(value, dt, piece.joinPieces[0], dataConverter, logger);
				}
			}
			groundTruth.add(value);
		}
		return groundTruth;

	}

	/**
	 * Extends the byte representation of values from their original DataType to the DataType that 
	 * is indicated by the joinPiece Varnode's size.
	 * @param value the raw byte array of the original value
	 * @param dt the source data type (e.g., FloatDataType, DoubleDataType, or Structure)
	 * @param joinPiece representing the target storage, used to determine target size
	 * @param dataConverter the converter used to determine endianness
	 * @param logger {@code Consumer<String>} lambda function to print logging information
	 * @return byte[] a byte array containing the extended value,
	 */
	public static byte[] getExtendedValue(byte[] value, DataType dt, Varnode joinPiece,
			DataConverter dataConverter, Consumer<String> logger) {
		byte[] extended = new byte[joinPiece.getSize()];
		// float -> double
		if (dt instanceof FloatDataType && dt.getLength() == 4 && joinPiece.getSize() == 8) {
			ByteOrder byteOrder =
				dataConverter.isBigEndian() ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
			float floatValue = ByteBuffer.wrap(value).order(byteOrder).getFloat();
			double doubleValue = floatValue;
			extended = ByteBuffer.allocate(8).order(byteOrder).putDouble(doubleValue).array();
		}
		// float -> double, but the float is a single-element HFA
		else if (dt instanceof Structure struct &&
			struct.getComponent(0).getDataType() instanceof FloatDataType && dt.getLength() == 4 &&
			joinPiece.getSize() == 8) {

			ByteOrder byteOrder =
				dataConverter.isBigEndian() ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
			float floatValue = ByteBuffer.wrap(value).order(byteOrder).getFloat();
			double doubleValue = floatValue;
			extended = ByteBuffer.allocate(8).order(byteOrder).putDouble(doubleValue).array();
		}
		// float -> 80 bit floating point format
		else if (dt instanceof FloatDataType && dt.getLength() == 4 && joinPiece.getSize() == 10) {
			ByteOrder byteOrder =
				dataConverter.isBigEndian() ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
			float floatValue = ByteBuffer.wrap(value).order(byteOrder).getFloat();
			// See OpBehaviorFloatFloat2Float
			FloatFormat inFF = FloatFormatFactory.getFloatFormat(4);
			FloatFormat outFF = FloatFormatFactory.getFloatFormat(10);
			long inEncoded = inFF.getEncoding(floatValue);
			BigInteger inEncodedBig = BigInteger.valueOf(inEncoded);
			BigInteger outEncoded = inFF.opFloat2Float(inEncodedBig, outFF);

			byte[] outBytes = outEncoded.toByteArray(); // Returned as Big-Endian
			// Pad to expected size and/or flip byte order
			if (byteOrder == ByteOrder.BIG_ENDIAN) {
				for (int i = 10 - outBytes.length; i < 10; i++) {
					extended[i] = outBytes[i];
				}
			}
			else {
				for (int i = 0; i < outBytes.length; i++) {
					extended[9 - i] = outBytes[i];
				}
			}
		}
		// double -> 80 bit floating point format
		else if (dt instanceof DoubleDataType && dt.getLength() == 8 && joinPiece.getSize() == 10) {
			ByteOrder byteOrder =
				dataConverter.isBigEndian() ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
			double doubleValue = ByteBuffer.wrap(value).order(byteOrder).getDouble();
			// See OpBehaviorFloatFloat2Float
			FloatFormat inFF = FloatFormatFactory.getFloatFormat(8);
			FloatFormat outFF = FloatFormatFactory.getFloatFormat(10);
			long inEncoded = inFF.getEncoding(doubleValue);
			BigInteger inEncodedBig = BigInteger.valueOf(inEncoded);
			BigInteger outEncoded = inFF.opFloat2Float(inEncodedBig, outFF);

			byte[] outBytes = outEncoded.toByteArray(); // Returned as Big-Endian
			// Pad to expected size and/or flip byte order
			if (byteOrder == ByteOrder.BIG_ENDIAN) {
				for (int i = 10 - outBytes.length; i < 10; i++) {
					extended[i] = outBytes[i];
				}
			}
			else {
				for (int i = 0; i < outBytes.length; i++) {
					extended[9 - i] = outBytes[i];
				}
			}
		}
		else {
			logger.accept("Unhandled extension: dt=%s; size=%d, extended size=%d\n"
					.formatted(dt.getDisplayName(), dt.getLength(), joinPiece.getSize()));
		}
		return extended;
	}

	/**
	 * Gets the parameters between a caller and callee and organizes them in a PrototypePieces 
	 * object by prototypeModel. ParameterPieces may be spread between them depending on the calling
	 * convention being used.
	 * @param caller The function that calls the callee.
	 * @param callee The function being called by the caller.
	 * @param model PrototypeModel corresponding to the calling convention.
	 * @return {@code ArrayList<ParameterPieces>}
	 */
	public static ArrayList<ParameterPieces> getParameterPieces(Function caller, Function callee,
			PrototypeModel model) {
		Program program = callee.getProgram();
		PrototypePieces pieces = new PrototypePieces(model, null);
		FunctionSignature funcSig = callee.getSignature(true);
		pieces.outtype = funcSig.getReturnType();
		if (callee.hasVarArgs()) {
			// args for callsite encode in caller's name
			List<DataType> types = getVarArgsParamTypes(caller);
			for (DataType type : types) {
				pieces.intypes.add(type);
			}
			pieces.firstVarArgSlot = funcSig.getArguments().length;
		}
		else {
			for (ParameterDefinition def : funcSig.getArguments()) {
				pieces.intypes.add(def.getDataType());
			}
		}
		ArrayList<ParameterPieces> paramPieces = new ArrayList<>();
		model.assignParameterStorage(pieces, program.getDataTypeManager(), paramPieces, true);
		return paramPieces;
	}

	/**
	 * All functions in the source code for these Cspec tests are named in such a way that the
	 * parameter types of the function are encoded in the name. This function decodes the
	 * function names to retrieve the function parameter types as a list.
	 * @param func The function to decode into it's parameter's datatypes
	 * @return {@code List<DataType>} the datatypes of the parameters of the function.
	 */
	public static List<DataType> getVarArgsParamTypes(Function func) {
		List<DataType> types = new ArrayList<>();
		String name = func.getName();
		String[] parts = name.split("_");
		DataTypeManager dtManager = func.getProgram().getDataTypeManager();
		// name is paramsVariadic_(type list)_counter
		for (int i = 1; i < parts.length - 1; ++i) {
			DataType type = null;
			switch (parts[i]) {
				case "c":
					type = new CharDataType(dtManager);
					break;
				case "C":
					type = new UnsignedCharDataType(dtManager);
					break;
				case "s":
					type = new ShortDataType(dtManager);
					break;
				case "S":
					type = new UnsignedShortDataType(dtManager);
					break;
				case "i":
					type = new IntegerDataType(dtManager);
					break;
				case "I":
					type = new UnsignedIntegerDataType(dtManager);
					break;
				case "l":
					type = new LongDataType(dtManager);
					break;
				case "L":
					type = new UnsignedLongDataType(dtManager);
					break;
				case "f":
					type = new FloatDataType(dtManager);
					break;
				case "d":
					type = new DoubleDataType(dtManager);
					break;
				default:
					throw new AssertionError("Unsupported data type: " + parts[i]);
			}
			types.add(type);
		}
		return types;
	}

	/**
	 * Returns the function that calls the given function first.
	 * @param function the callee which is searched for
	 * @return Function the caller which is first
	 */
	public static Function getFirstCall(Function function) {
		String[] parts = function.getName().split("_");
		String count = parts[parts.length - 1];
		Set<Function> callees = function.getCalledFunctions(TaskMonitor.DUMMY);
		if (callees.size() == 0) {
			throw new AssertionError("no called functions found for " + function.getName());
		}
		for (Function callee : callees) {
			String calleeName = getAdjustedCalleeName(callee.getName());

			if (calleeName.startsWith(CSpecPrototypeTestConstants.EXTERNAL) ||
				calleeName.startsWith(CSpecPrototypeTestConstants.PRODUCER)) {
				if (calleeName.endsWith(count)) {
					return callee;
				}
			}
		}
		throw new AssertionError("no appropriate functions called by " + function.getName());
	}

	/**
	 * Adjusts the name of a function to remove characters prepended by compilers.
	 * @param calleeName the name of the function
	 * @return String the name of the function after it has been adjusted
	 */
	public static String getAdjustedCalleeName(String calleeName) {
		// Hack for PowerPC 64-bit object files that prepend plt_call.<funcname> on the extern calls
		if (!calleeName.contains("plt_call.")) {
			return calleeName;
		}
		return calleeName.split("plt_call.")[1];
	}

	/**
	 * Returns the PrototypeModel from the compiler spec of the given LanguageCompilerSpecPair and 
	 * calling convention specified in the program's name.
	 * @param program Program whose name contains the desired calling convention
	 * @param langComp the language/compiler specification pair to query
	 * @return PrototypeModel Model corresponding to the extracted calling convention
	 * @throws CompilerSpecNotFoundException if the compiler specification cannot be found/loaded
	 * @throws LanguageNotFoundException if the specified language is not available
	 */
	public static PrototypeModel getProtoModelToTest(Program program,
			LanguageCompilerSpecPair langComp)
			throws CompilerSpecNotFoundException, LanguageNotFoundException {
		String name = program.getName();
		// Expected program name format: <arch>_<endian>_<bits>_<machine>_<compiler>_<callingconv>

		//Handle cases where the architecture name contains underscores
		String architecture = name.split("_LE_|_BE_")[0];
		if (architecture.contains("_")) {
			String cleanArchitecture = name.replace("_", "");
			name = name.replaceFirst(architecture, cleanArchitecture);
		}

		String[] splitname = name.split("_");

		// Handle cases where calling convention contains underscores
		String ccName = String.join("_", Arrays.copyOfRange(splitname, 5, splitname.length));

		return langComp.getCompilerSpec().getCallingConvention(ccName);
	}

	/**
	 * Parses function definitions and data types of global variables from the source code and 
	 * applies them to the binary. Also applies the correct signature overrides to calls of 
	 * variadic functions.
	 * @param program Program produced from the source code being parsed.
	 * @param model The PrototypeModel of the program.
	 * @throws ParseException when the c source code cannot be parsed.
	 * @throws IOException when the c source code cannot be parsed.
	 * @throws ghidra.app.util.cparser.CPP.ParseException when the c source code cannot be parsed.
	 * @throws CodeUnitInsertionException When code units cannot be created at the given address.
	 */
	public static void applyInfoFromSourceIfNeeded(Program program, PrototypeModel model)
			throws ParseException, IOException, ghidra.app.util.cparser.CPP.ParseException,
			CodeUnitInsertionException {

		Category funcsFromSource = getFuncDefs(program);
		if (funcsFromSource != null) {
			return; // assume that this method has already been run on the test binary.
		}

		DataTypeManager dtManager = program.getDataTypeManager();

		// Parse the c source file. This assumes that the name of the source file is the
		// name of the test binary + ".c" and that the two files are in the same directory
		CParserUtils.parseHeaderFiles(null, new String[] { program.getExecutablePath() + ".c" },
			new String[0], dtManager, TaskMonitor.DUMMY);

		funcsFromSource = getFuncDefs(program);
		if (funcsFromSource == null) {
			throw new AssertionError("Error parsing C file; datatypes not added");
		}
		FunctionIterator fIter = program.getFunctionManager().getExternalFunctions();
		AddressSet entryPoints = new AddressSet();
		while (fIter.hasNext()) {
			entryPoints.add(fIter.next().getEntryPoint());
		}
		entryPoints = entryPoints.union(program.getMemory().getExecuteSet());

		ApplyFunctionDataTypesCmd cmd = new ApplyFunctionDataTypesCmd(funcsFromSource, entryPoints,
			SourceType.USER_DEFINED, true, true);
		cmd.applyTo(program, TaskMonitor.DUMMY);

		// set the calling convention on the test functions
		// first the external test functions
		fIter = program.getFunctionManager().getExternalFunctions();
		while (fIter.hasNext()) {
			Function func = fIter.next();
			try {
				func.setCallingConvention(model.getName());
			}
			catch (InvalidInputException e) {
				// shouldn't happen
				throw new AssertionError(
					"Bad calling convention name for prototype: " + model.getName());
			}
		}
		// now the "producer" functions used for testing returned values
		fIter = program.getFunctionManager().getFunctions(true);
		while (fIter.hasNext()) {
			Function func = fIter.next();
			if (!func.getName().startsWith(CSpecPrototypeTestConstants.PRODUCER)) {
				continue;
			}
			try {
				func.setCallingConvention(model.getName());
			}
			catch (InvalidInputException e) {
				// shouldn't happen
				throw new AssertionError(
					"Bad calling convention name for prototype: " + model.getName());
			}
		}

		// apply the correct overrides to the varargs functions
		ReferenceManager refManager = program.getReferenceManager();
		fIter = program.getFunctionManager().getFunctions(true);
		while (fIter.hasNext()) {
			Function func = fIter.next();
			if (!func.getName().startsWith(CSpecPrototypeTestConstants.PARAMS_VARIADIC)) {
				continue;
			}
			Function varArgsFunc = CSpecPrototypeTestUtil.getFirstCall(func);
			if (!varArgsFunc.hasVarArgs()) {
				throw new AssertionError(varArgsFunc.getName() + " should be marked varargs");
			}
			Reference call = null;
			ReferenceIterator refIter = refManager.getReferencesTo(varArgsFunc.getEntryPoint());
			while (refIter.hasNext()) {
				Reference ref = refIter.next();
				if (!ref.getReferenceType().isCall()) {
					continue;
				}
				if (func.getBody().contains(ref.getFromAddress())) {
					call = ref; // assume the first one found is what we want
					break;
				}
			}
			if (call == null) {
				throw new AssertionError(
					"no call references to " + varArgsFunc.getName() + " in " + func.getName());
			}
			List<DataType> types = CSpecPrototypeTestUtil.getVarArgsParamTypes(func);
			FunctionDefinitionDataType override =
				new FunctionDefinitionDataType(varArgsFunc.getName(), program.getDataTypeManager());
			try {
				override.setCallingConvention(model.getName());
			}
			catch (InvalidInputException e) {
				// shouldn't happen
				throw new AssertionError("bad calling convention name: " + model.getName());
			}
			override.setReturnType(VoidDataType.dataType);
			ParameterDefinition[] paramDefs = new ParameterDefinition[types.size()];
			for (int i = 0; i < types.size(); ++i) {
				paramDefs[i] = new ParameterDefinitionImpl("param" + i, types.get(i), null);
			}
			override.setArguments(paramDefs);
			try {
				HighFunctionDBUtil.writeOverride(func, call.getFromAddress(), override);
			}
			catch (InvalidInputException e) {
				throw new AssertionError("bad overriding signature for variadic function");
			}
		}

		// finally, apply datatypes to global variables
		SymbolIterator symbolIter = program.getSymbolTable().getDefinedSymbols();
		CategoryPath source =
			new CategoryPath(CategoryPath.ROOT, List.of(program.getName() + ".c"));
		while (symbolIter.hasNext()) {
			Symbol symbol = symbolIter.next();
			String name = symbol.getName();
			if (name == null) {
				continue;
			}
			int underScoreIndex = name.indexOf('_');
			if (underScoreIndex == -1) {
				continue;
			}
			String typeName = name.substring(0, underScoreIndex);
			DataType type = null;
			switch (typeName) {
				case "char":
				case "short":
				case "int":
				case "long":
				case "longlong":
				case "float":
				case "double":
					type = dtManager.getDataType(CategoryPath.ROOT, typeName);
					break;
				case CSpecPrototypeTestConstants.STRUCT_CHAR_SINGLETON_NAME:
				case CSpecPrototypeTestConstants.STRUCT_SHORT_SINGLETON_NAME:
				case CSpecPrototypeTestConstants.STRUCT_INT_SINGLETON_NAME:
				case CSpecPrototypeTestConstants.STRUCT_LONG_SINGLETON_NAME:
				case CSpecPrototypeTestConstants.STRUCT_LONG_LONG_SINGLETON_NAME:
				case CSpecPrototypeTestConstants.STRUCT_FLOAT_SINGLETON_NAME:
				case CSpecPrototypeTestConstants.STRUCT_DOUBLE_SINGLETON_NAME:
				case CSpecPrototypeTestConstants.STRUCT_CHAR_PAIR_NAME:
				case CSpecPrototypeTestConstants.STRUCT_SHORT_PAIR_NAME:
				case CSpecPrototypeTestConstants.STRUCT_INT_PAIR_NAME:
				case CSpecPrototypeTestConstants.STRUCT_LONG_PAIR_NAME:
				case CSpecPrototypeTestConstants.STRUCT_LONG_LONG_PAIR_NAME:
				case CSpecPrototypeTestConstants.STRUCT_FLOAT_PAIR_NAME:
				case CSpecPrototypeTestConstants.STRUCT_DOUBLE_PAIR_NAME:
				case CSpecPrototypeTestConstants.STRUCT_CHAR_TRIP_NAME:
				case CSpecPrototypeTestConstants.STRUCT_SHORT_TRIP_NAME:
				case CSpecPrototypeTestConstants.STRUCT_INT_TRIP_NAME:
				case CSpecPrototypeTestConstants.STRUCT_LONG_TRIP_NAME:
				case CSpecPrototypeTestConstants.STRUCT_LONG_LONG_TRIP_NAME:
				case CSpecPrototypeTestConstants.STRUCT_FLOAT_TRIP_NAME:
				case CSpecPrototypeTestConstants.STRUCT_DOUBLE_TRIP_NAME:
				case CSpecPrototypeTestConstants.STRUCT_CHAR_QUAD_NAME:
				case CSpecPrototypeTestConstants.STRUCT_SHORT_QUAD_NAME:
				case CSpecPrototypeTestConstants.STRUCT_INT_QUAD_NAME:
				case CSpecPrototypeTestConstants.STRUCT_LONG_QUAD_NAME:
				case CSpecPrototypeTestConstants.STRUCT_LONG_LONG_QUAD_NAME:
				case CSpecPrototypeTestConstants.STRUCT_FLOAT_QUAD_NAME:
				case CSpecPrototypeTestConstants.STRUCT_DOUBLE_QUAD_NAME:
				case CSpecPrototypeTestConstants.STRUCT_INT_LONG_INT:
				case CSpecPrototypeTestConstants.STRUCT_FLOAT_INT_FLOAT:
				case CSpecPrototypeTestConstants.STRUCT_LONG_DOUBLE_LONG:
				case CSpecPrototypeTestConstants.STRUCT_FLOAT_DOUBLE_FLOAT:
				case CSpecPrototypeTestConstants.UNION_CHAR:
				case CSpecPrototypeTestConstants.UNION_SHORT:
				case CSpecPrototypeTestConstants.UNION_INT:
				case CSpecPrototypeTestConstants.UNION_LONG:
				case CSpecPrototypeTestConstants.UNION_LONG_LONG:
				case CSpecPrototypeTestConstants.UNION_INT_LONG:
				case CSpecPrototypeTestConstants.UNION_FLOAT_DOUBLE:
				case CSpecPrototypeTestConstants.UNION_INT_FLOAT:
				case CSpecPrototypeTestConstants.UNION_LONG_DOUBLE:
				case CSpecPrototypeTestConstants.UNION_INT_DOUBLE:
				case CSpecPrototypeTestConstants.UNION_LONG_FLOAT:
				case CSpecPrototypeTestConstants.UNION_STRUCT_INT:
				case CSpecPrototypeTestConstants.UNION_STRUCT_FLOAT:
				case CSpecPrototypeTestConstants.UNION_MIXED_STRUCT_INTEGRAL:
				case CSpecPrototypeTestConstants.UNION_MIXED_STRUCT_FLOATING:
				case CSpecPrototypeTestConstants.UNION_MIXED_STRUCT_ALL_SMALL:
				case CSpecPrototypeTestConstants.UNION_MIXED_STRUCT_ALL_LARGE:
				case CSpecPrototypeTestConstants.UNION_STRUCT_TRIP_CHAR:
				case CSpecPrototypeTestConstants.UNION_STRUCT_TRIP_SHORT:
					type = dtManager.getDataType(source, typeName);
					break;
				default:
					break;
			}
			if (type == null) {
				continue;
			}
			// first clear any types that an analyzer may have laid down 
			// for example, the ASCII string searcher
			program.getListing()
					.clearCodeUnits(symbol.getAddress(), symbol.getAddress().add(type.getLength()),
						false);
			program.getListing().createData(symbol.getAddress(), type);
		}
	}

	/**
	 * Returns a TestResult record that includes a message detailing the differences between
	 * parameter data in the c source code, and parameter data in the Ghidra emulator between a
	 * specific caller function and callee function.
	 * @param caller The function that calls the callee.
	 * @param callee The function being called by the caller.
	 * @param pieces {@code ArrayList<ParameterPieces>} representing basic elements of the parameters 
	 * between callers and callees.
	 * @param fromEmulator Byte list representing parameter values from the emulator.
	 * @param groundTruth Byte list representing parameter values from the c source code.
	 * @return TestResult result record object that contains a message and a boolean hasError.
	 */
	public static TestResult getTestResult(Function callee, Function caller,
			ArrayList<ParameterPieces> pieces, List<byte[]> fromEmulator,
			List<byte[]> groundTruth) {
		boolean error = false;
		StringBuilder sb = new StringBuilder();
		sb.append("Caller: ");
		sb.append(caller.getName());
		sb.append("\nCallee: ");
		sb.append(callee.getName());
		sb.append("\n\n");

		boolean inputTest = pieces.get(0).type instanceof VoidDataType;
		int begin = inputTest ? 1 : 0;
		int end = inputTest ? fromEmulator.size() : 1;
		for (int i = begin; i < end; ++i) {
			if (!Arrays.equals(groundTruth.get(i), fromEmulator.get(i))) {
				error = true;
				sb.append("X ");
			}
			else {
				sb.append("  ");
			}
			sb.append(pieces.get(i).type.getDisplayName());
			if (i == 0) {
				sb.append(" return");
			}
			else {
				sb.append(" param");
				sb.append(Integer.toString(i));
			}
			sb.append("\n");
			sb.append("      location: ");
			String location = pieces.get(i).getVariableStorage(callee.getProgram()).toString();
			sb.append(location);
			sb.append("\n");
			ParameterPieces piece = pieces.get(i);
			if ((piece.hiddenReturnPtr || piece.isIndirect) && (piece.address != null)) {
				sb.append("      expected bytes points to: ");
			}
			else {
				sb.append("      expected bytes: ");
			}
			sb.append(hexFormat.formatHex(groundTruth.get(i)));
			sb.append("\n");

			if ((piece.hiddenReturnPtr || piece.isIndirect) && (piece.address != null)) {
				sb.append("      emulator points to:       ");
			}
			else {
				sb.append("      emulator:       ");
			}
			sb.append(hexFormat.formatHex(fromEmulator.get(i)));
			sb.append("\n");
		}

		return new TestResult(sb.toString(), error);
	}

	/**
	 * Returns the function definitions for the program as a {@link Category}.
	 * @param program Program to get the function definitions from.
	 * @return Category
	 */
	private static Category getFuncDefs(Program program) {
		String name = program.getName();
		CategoryPath path = new CategoryPath(CategoryPath.ROOT, List.of(name + ".c", "functions"));
		return program.getDataTypeManager().getCategory(path);
	}

}
