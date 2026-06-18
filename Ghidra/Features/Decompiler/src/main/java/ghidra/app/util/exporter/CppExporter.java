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
package ghidra.app.util.exporter;

import java.io.*;
import java.math.BigInteger;
import java.util.*;

import org.apache.commons.lang3.StringUtils;

import generic.cache.CachingPool;
import generic.cache.CountingBasicFactory;
import generic.concurrent.QCallback;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.DecompileOptions.CommentStyleEnum;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.parallel.ChunkingParallelDecompiler;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.app.util.*;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;
import util.CollectionUtils;

public class CppExporter extends ProgramExporter {

	public static final String CREATE_C_FILE = "Create C File (.c)";
	public static final String CREATE_HEADER_FILE = "Create Header File (.h)";
	public static final String USE_CPP_STYLE_COMMENTS = "Use C++ Style Comments (//)";
	public static final String EMIT_TYPE_DEFINITONS = "Emit Data-type Definitions";
	public static final String EMIT_REFERENCED_GLOBALS = "Emit Referenced Globals";
	public static final String EMIT_GLOBAL_DATA = "Emit Global Data Initializers";
	public static final String FUNCTION_TAG_FILTERS = "Function Tags to Filter";
	public static final String FUNCTION_TAG_EXCLUDE = "Function Tags Excluded";

	private static String EOL = System.getProperty("line.separator");

	private boolean isCreateHeaderFile = false;
	private boolean isCreateCFile = true;
	private boolean isUseCppStyleComments = true;
	private boolean emitDataTypeDefinitions = true;
	private boolean emitReferencedGlobals = true;
	private boolean emitGlobalData = true;
	private String tagOptions = "";

	private Set<FunctionTag> functionTagSet = new HashSet<>();
	private boolean excludeMatchingTags = true;

	private DecompileOptions options;
	private boolean userSuppliedOptions = false;

	public CppExporter() {
		super("C/C++", "c", new HelpLocation("ExporterPlugin", "c_cpp"));
	}

	public CppExporter(DecompileOptions options, boolean createHeader, boolean createFile,
			boolean emitTypes, boolean emitGlobals, boolean emitData, boolean excludeTags,
			String tags) {
		this();
		this.options = options;
		if (options != null) {
			userSuppliedOptions = true;
		}
		isCreateHeaderFile = createHeader;
		isCreateCFile = createFile;
		emitDataTypeDefinitions = emitTypes;
		emitReferencedGlobals = emitGlobals;
		emitGlobalData = emitData;
		excludeMatchingTags = excludeTags;
		if (tags != null) {
			tagOptions = tags;
		}
	}

	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView addrSet,
			TaskMonitor monitor) throws IOException, ExporterException {

		Program program;
		try {
			program = getProgram(domainObj);
		}
		catch (ClassCastException e) {
			log.appendMsg("Unsupported type: " + domainObj.getClass().getName());
			return false;
		}

		configureOptions(program);
		configureFunctionTags(program);

		if (addrSet == null) {
			addrSet = program.getMemory();
		}

		File header = getHeaderFile(file);
		PrintWriter headerWriter = null;
		if (isCreateHeaderFile) {
			headerWriter = new PrintWriter(header);
		}

		PrintWriter cFileWriter = null;
		if (isCreateCFile) {
			cFileWriter = new PrintWriter(file);
		}

		CachingPool<DecompInterface> decompilerPool =
			new CachingPool<>(new DecompilerFactory(program));
		ParallelDecompilerCallback callback = new ParallelDecompilerCallback(decompilerPool);
		ChunkingTaskMonitor chunkingMonitor = new ChunkingTaskMonitor(monitor);
		ChunkingParallelDecompiler<CPPResult> parallelDecompiler =
			ParallelDecompiler.createChunkingParallelDecompiler(callback, chunkingMonitor);

		try {
			if (emitDataTypeDefinitions) {
				writeEquates(program, header, headerWriter, cFileWriter, chunkingMonitor);
				writeProgramDataTypes(program, header, headerWriter, cFileWriter, chunkingMonitor);
			}
			chunkingMonitor.checkCancelled();

			decompileAndExport(addrSet, program, headerWriter, cFileWriter, parallelDecompiler,
				chunkingMonitor);

			return true;
		}
		catch (CancelledException e) {
			return false;
		}
		catch (Exception e) {
			Msg.error(this, "Error exporting C/C++", e);
			return false;
		}
		finally {
			decompilerPool.dispose();
			parallelDecompiler.dispose();

			if (headerWriter != null) {
				headerWriter.close();
			}
			if (cFileWriter != null) {
				cFileWriter.close();
			}
		}

	}

	private void decompileAndExport(AddressSetView addrSet, Program program,
			PrintWriter headerWriter, PrintWriter cFileWriter,
			ChunkingParallelDecompiler<CPPResult> parallelDecompiler,
			ChunkingTaskMonitor chunkingMonitor)
			throws InterruptedException, Exception, CancelledException {

		int functionCount = program.getFunctionManager().getFunctionCount();
		chunkingMonitor.doInitialize(functionCount);

		Listing listing = program.getListing();
		FunctionIterator iterator = listing.getFunctions(addrSet, true);
		List<Function> functions = new ArrayList<>();
		Set<Address> processedGlobals = new HashSet<>();
		for (int i = 0; iterator.hasNext(); i++) {
			//
			// Write results every so many items so that we don't blow out memory
			//
			if (i % 10000 == 0) {
				List<CPPResult> results = parallelDecompiler.decompileFunctions(functions);
				writeResults(results, processedGlobals, headerWriter, cFileWriter, chunkingMonitor);
				functions.clear();
			}

			Function currentFunction = iterator.next();
			if (excludeFunction(currentFunction)) {
				continue;
			}

			functions.add(currentFunction);
		}

		// handle any remaining functions
		List<CPPResult> results = parallelDecompiler.decompileFunctions(functions);
		writeResults(results, processedGlobals, headerWriter, cFileWriter, chunkingMonitor);
	}

	private boolean excludeFunction(Function currentFunction) {

		if (functionTagSet.isEmpty()) {
			return false;
		}

		Set<FunctionTag> tags = currentFunction.getTags();
		boolean hasTag = false;
		for (FunctionTag tag : functionTagSet) {
			if (tags.contains(tag)) {
				hasTag = true;
				break;
			}
		}

		return excludeMatchingTags == hasTag;
	}

	private void writeResults(List<CPPResult> results, Set<Address> processedGlobals,
			PrintWriter headerWriter, PrintWriter cFileWriter, TaskMonitor monitor)
			throws CancelledException {
		monitor.checkCancelled();

		Collections.sort(results);

		TreeMap<Address, String> newGlobalsByAddress = new TreeMap<>();
		List<String> nonAddressedGlobalDecls = new ArrayList<>();
		StringBuilder globalDecls = new StringBuilder();
		StringBuilder headers = new StringBuilder();
		StringBuilder bodies = new StringBuilder();

		for (CPPResult result : results) {
			monitor.checkCancelled();
			if (result == null) {
				continue;
			}
			if (emitReferencedGlobals) {
				for (GlobalDecl gd : result.globals()) {
					if (gd.address() != null) {
						if (processedGlobals.add(gd.address())) {
							newGlobalsByAddress.put(gd.address(), gd.declaration());
						}
					}
					else {
						nonAddressedGlobalDecls.add(gd.declaration());
					}
				}
			}
			String headerCode = result.headerCode();
			if (headerCode != null) {
				headers.append(headerCode);
				headers.append(EOL);
			}

			String bodyCode = result.bodyCode();
			if (bodyCode != null) {
				bodies.append(bodyCode);
				bodies.append(EOL);
			}
		}

		monitor.checkCancelled();

		for (String decl : nonAddressedGlobalDecls) {
			globalDecls.append(decl).append(EOL);
		}
		for (String decl : newGlobalsByAddress.values()) {
			globalDecls.append(decl).append(EOL);
		}

		if (headerWriter != null) {
			headerWriter.println(headers.toString());
		}
		if (cFileWriter != null) {
			cFileWriter.print(globalDecls.toString());
			cFileWriter.print(bodies.toString());
		}
	}

	private void configureOptions(Program program) {
		if (!userSuppliedOptions) {

			options = DecompilerUtils.getDecompileOptions(provider, program);

			if (isUseCppStyleComments) {
				options.setCommentStyle(CommentStyleEnum.CPPStyle);
			}
			else {
				options.setCommentStyle(CommentStyleEnum.CStyle);
			}
		}
	}

	private void configureFunctionTags(Program program) {
		if (StringUtils.isBlank(tagOptions)) {
			return;
		}

		FunctionManager functionManager = program.getFunctionManager();

		FunctionTagManager tagManager = functionManager.getFunctionTagManager();
		String[] split = tagOptions.split(",");
		for (String tag : split) {
			FunctionTag functionTag = tagManager.getFunctionTag(tag.trim());
			if (functionTag != null) {
				functionTagSet.add(functionTag);
			}
		}
	}

	private void writeProgramDataTypes(Program program, File header, PrintWriter headerWriter,
			PrintWriter cFileWriter, TaskMonitor monitor) throws IOException, CancelledException {
		if (headerWriter != null) {
			DataTypeManager dtm = program.getDataTypeManager();
			DataTypeWriter dataTypeWriter =
				new DataTypeWriter(dtm, headerWriter, isUseCppStyleComments);
			headerWriter.write(getFakeCTypeDefinitions(dtm.getDataOrganization()));
			dataTypeWriter.write(monitor);

			headerWriter.println("");
			headerWriter.println("");

			if (cFileWriter != null) {
				cFileWriter.println("#include \"" + header.getName() + "\"");
			}
		}
		else if (cFileWriter != null) {
			DataTypeManager dtm = program.getDataTypeManager();
			DataTypeWriter dataTypeWriter =
				new DataTypeWriter(dtm, cFileWriter, isUseCppStyleComments);
			dataTypeWriter.write(monitor);
		}

		if (cFileWriter != null) {
			cFileWriter.println("");
			cFileWriter.println("");
		}

	}

	private void writeEquates(Program program, File header, PrintWriter headerWriter,
			PrintWriter cFileWriter, TaskMonitor monitor) throws CancelledException {
		boolean equatesPresent = false;
		for (Equate equate : CollectionUtils.asIterable(program.getEquateTable().getEquates())) {
			monitor.checkCancelled();
			equatesPresent = true;
			String define =
				"#define %s %s".formatted(equate.getDisplayName(), equate.getDisplayValue());
			if (headerWriter != null) {
				headerWriter.println(define);
			}
			else if (cFileWriter != null) {
				cFileWriter.println(define);
			}
		}
		if (equatesPresent) {
			if (headerWriter != null) {
				headerWriter.println();
			}
			else if (cFileWriter != null) {
				cFileWriter.println();
			}
		}
	}

	private File getHeaderFile(File file) {
		String name = file.getName();
		int pos = name.lastIndexOf('.');
		if (pos > 0) {
			name = name.substring(0, pos);
		}
		return new File(file.getParent(), name + ".h");
	}

	@Override
	public List<Option> getOptions(DomainObjectService domainObjectService) {
		ArrayList<Option> list = new ArrayList<>();
		list.add(Option.newBoolean(CREATE_HEADER_FILE)
				.value(isCreateHeaderFile)
				.build());
		list.add(Option.newBoolean(CREATE_C_FILE)
				.value(isCreateCFile)
				.build());
		list.add(Option.newBoolean(USE_CPP_STYLE_COMMENTS)
				.value(isUseCppStyleComments)
				.build());
		list.add(Option.newBoolean(EMIT_TYPE_DEFINITONS)
				.value(emitDataTypeDefinitions)
				.build());
		list.add(Option.newBoolean(EMIT_REFERENCED_GLOBALS)
				.value(emitReferencedGlobals)
				.build());
		list.add(Option.newBoolean(EMIT_GLOBAL_DATA)
				.value(emitGlobalData)
				.build());
		list.add(Option.newString(FUNCTION_TAG_FILTERS)
				.value(tagOptions)
				.build());
		list.add(Option.newBoolean(FUNCTION_TAG_EXCLUDE)
				.value(excludeMatchingTags)
				.build());
		return list;
	}

	@Override
	public void setOptions(List<Option> options) throws OptionException {
		for (Option option : options) {
			String optName = option.getName();
			try {
				if (optName.equals(CREATE_HEADER_FILE)) {
					isCreateHeaderFile = ((Boolean) option.getValue()).booleanValue();
				}
				else if (optName.equals(CREATE_C_FILE)) {
					isCreateCFile = ((Boolean) option.getValue()).booleanValue();
				}
				else if (optName.equals(USE_CPP_STYLE_COMMENTS)) {
					isUseCppStyleComments = ((Boolean) option.getValue()).booleanValue();
				}
				else if (optName.equals(EMIT_TYPE_DEFINITONS)) {
					emitDataTypeDefinitions = ((Boolean) option.getValue()).booleanValue();
				}
				else if (optName.equals(EMIT_REFERENCED_GLOBALS)) {
					emitReferencedGlobals = ((Boolean) option.getValue()).booleanValue();
				}
				else if (optName.equals(EMIT_GLOBAL_DATA)) {
					emitGlobalData = ((Boolean) option.getValue()).booleanValue();
				}
				else if (optName.equals(FUNCTION_TAG_FILTERS)) {
					tagOptions = (String) option.getValue();
				}
				else if (optName.equals(FUNCTION_TAG_EXCLUDE)) {
					excludeMatchingTags = ((Boolean) option.getValue()).booleanValue();
				}
				else {
					throw new OptionException("Unknown option: " + optName);
				}
			}
			catch (ClassCastException e) {
				throw new OptionException(
					"Invalid type for option: " + optName + " - " + e.getMessage());
			}
		}
	}

	private static String getBuiltInDeclaration(String typeName, String ctypeName) {
		return "#define " + typeName + "   " + ctypeName + EOL;
	}

	private static String getBuiltInDeclaration(String typeName, int typeLen, boolean signed,
			DataOrganization dataOrganization) {
		return getBuiltInDeclaration(typeName,
			dataOrganization.getIntegerCTypeApproximation(typeLen, signed));
	}

	/**
	 * Generate suitable C-style definition statements (#define) for any fake data-type names
	 * which may be produced by the decompiler (e.g., unkint, unkuint, etc.).
	 * @param dataOrganization is the data organization to result the size of core types.
	 * @return multi-line string containing C-style declarations of fake decompiler types.
	 */
	private static String getFakeCTypeDefinitions(DataOrganization dataOrganization) {

		StringWriter writer = new StringWriter();

		// unkbyte - decompiler fabricated unknown types - need only cover sizes larger than the max Undefined size
		for (int n = 9; n <= 16; n++) {
			writer.write(getBuiltInDeclaration("unkbyte" + n, n, false, dataOrganization));
		}
		writer.write(EOL);

		// unkuint - decompiler fabricated unsigned integer types
		// need only cover sizes larger than the max integer size (i.e., AbstractIntegerDataType)
		for (int n = 9; n <= 16; n++) {
			writer.write(getBuiltInDeclaration("unkuint" + n, n, false, dataOrganization));
		}
		writer.write(EOL);

		// unkint - decompiler fabricated signed integer types
		// need only cover sizes larger than the max integer size (i.e., AbstractIntegerDataType)
		for (int n = 9; n <= 16; n++) {
			writer.write(getBuiltInDeclaration("unkint" + n, n, true, dataOrganization));
		}
		writer.write(EOL);

		// unkfloat - decompiler fabricated floating point types
		writer.write(getBuiltInDeclaration("unkfloat1", "float"));
		writer.write(getBuiltInDeclaration("unkfloat2", "float"));
		writer.write(getBuiltInDeclaration("unkfloat3", "float"));
		//writer.write(getBuiltInDeclaration("unkfloat4", "float")); // covered by fixed-size built-in float
		writer.write(getBuiltInDeclaration("unkfloat5", "double"));
		writer.write(getBuiltInDeclaration("unkfloat6", "double"));
		writer.write(getBuiltInDeclaration("unkfloat7", "double"));
		//writer.write(getBuiltInDeclaration("unkfloat8", "double")); // covered by fixed-size built-in double
		writer.write(getBuiltInDeclaration("unkfloat9", "long double"));
		//writer.write(getBuiltInDeclaration("unkfloat10", "long double")); // covered by fixed-size built-in longdouble
		writer.write(getBuiltInDeclaration("unkfloat11", "long double"));
		writer.write(getBuiltInDeclaration("unkfloat12", "long double"));
		writer.write(getBuiltInDeclaration("unkfloat13", "long double"));
		writer.write(getBuiltInDeclaration("unkfloat14", "long double"));
		writer.write(getBuiltInDeclaration("unkfloat15", "long double"));
		writer.write(getBuiltInDeclaration("unkfloat16", "long double"));
		writer.write(EOL);

		writer.write(getBuiltInDeclaration("BADSPACEBASE", "void"));
		writer.write(getBuiltInDeclaration("code", "void"));
		writer.write(EOL);

		return writer.toString();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * Builds a C initializer expression for the given data item.
	 * <p>
	 * Returns a string suitable for use as a C initializer (e.g., {@code 0x42},
	 * {@code "hello"}, {@code {1, 2, 3}}), or {@code null} if no valid initializer
	 * can be produced (e.g., for pointer types, function types, or uninitialized memory).
	 *
	 * @param data the data item to render as a C initializer
	 * @return C initializer string, or {@code null} if not representable
	 */
	private static String buildDataInitializer(Data data) {
		if (data == null) {
			return null;
		}

		DataType dt = data.getDataType();

		// Unwrap typedefs to check the base type
		DataType baseType = dt;
		while (baseType instanceof TypeDef td) {
			baseType = td.getBaseDataType();
		}

		// Skip pointer types - their address representation is not valid C syntax
		if (baseType instanceof Pointer || baseType instanceof FunctionDefinition) {
			return null;
		}

		// For non-string composites (arrays, structs, unions), recurse into components
		if (!data.hasStringValue()) {
			int numComponents = data.getNumComponents();
			if (numComponents > 0) {
				StringBuilder sb = new StringBuilder("{");
				for (int i = 0; i < numComponents; i++) {
					if (i > 0) {
						sb.append(", ");
					}
					Data component = data.getComponent(i);
					String compInit = buildDataInitializer(component);
					if (compInit == null) {
						return null;
					}
					sb.append(compInit);
				}
				sb.append("}");
				return sb.toString();
			}
		}

		// For strings: use the default representation (already properly quoted)
		if (data.hasStringValue()) {
			String repr = data.getDefaultValueRepresentation();
			return (repr != null && !repr.isEmpty() && !"??".equals(repr)) ? repr : null;
		}

		// For enums: use the default representation which returns the member name (valid C)
		if (baseType instanceof ghidra.program.model.data.Enum) {
			String repr = data.getDefaultValueRepresentation();
			return (repr != null && !repr.isEmpty() && !"??".equals(repr)) ? repr : null;
		}

		// For floats: use the default representation (decimal notation, valid C)
		if (baseType instanceof AbstractFloatDataType) {
			String repr = data.getDefaultValueRepresentation();
			return (repr != null && !repr.isEmpty() && !"??".equals(repr)) ? repr : null;
		}

		// For scalars (integers and undefined types): use getValue() to get the raw numeric
		// value and format as 0x-prefixed hex, avoiding the display-oriented h-suffix format.
		Object value = data.getValue();
		if (value == null) {
			return null; // uninitialized or inaccessible memory
		}

		if (value instanceof Scalar scalar) {
			int byteSize = scalar.bitLength() / 8;
			if (byteSize <= 0) {
				byteSize = data.getLength();
			}
			if (byteSize <= 0) {
				byteSize = 1;
			}
			String hex = Long.toHexString(scalar.getUnsignedValue()).toUpperCase();
			// Pad to the natural byte width of the type
			String padded = hex;
			int hexLen = byteSize * 2;
			while (padded.length() < hexLen) {
				padded = "0" + padded;
			}
			return "0x" + padded;
		}

		if (value instanceof BigInteger bigInt) {
			// Handle wide integer types (> 8 bytes): convert to unsigned representation
			if (bigInt.signum() < 0) {
				int bitLen = data.getLength() * 8;
				bigInt = bigInt.add(BigInteger.ONE.shiftLeft(bitLen));
			}
			String hex = bigInt.toString(16).toUpperCase();
			int hexLen = data.getLength() * 2;
			while (hex.length() < hexLen) {
				hex = "0" + hex;
			}
			return "0x" + hex;
		}

		return null;
	}


	private record GlobalDecl(Address address, String declaration) {}

	private record CPPResult(Address address, String headerCode, String bodyCode,
			List<GlobalDecl> globals) implements Comparable<CPPResult> {
		@Override
		public int compareTo(CPPResult other) {
			return address.compareTo(other.address);
		}
	}

	private class DecompilerFactory extends CountingBasicFactory<DecompInterface> {

		private Program program;

		DecompilerFactory(Program program) {
			this.program = program;
		}

		@Override
		public DecompInterface doCreate(int itemNumber) throws IOException {
			DecompInterface decompiler = new DecompInterface();
			decompiler.setOptions(options);
			decompiler.openProgram(program);
			decompiler.toggleSyntaxTree(true);
			return decompiler;
		}

		@Override
		public void doDispose(DecompInterface decompiler) {
			decompiler.dispose();
		}
	}

	private class ParallelDecompilerCallback implements QCallback<Function, CPPResult> {

		private CachingPool<DecompInterface> pool;

		ParallelDecompilerCallback(CachingPool<DecompInterface> decompilerPool) {
			this.pool = decompilerPool;
		}

		@Override
		public CPPResult process(Function function, TaskMonitor monitor) throws Exception {
			if (monitor.isCancelled()) {
				return null;
			}

			DecompInterface decompiler = pool.get();
			try {
				CPPResult result = doWork(function, decompiler, monitor);
				return result;
			}
			finally {
				pool.release(decompiler);
			}
		}

		private CPPResult doWork(Function function, DecompInterface decompiler,
				TaskMonitor monitor) {
			Address entryPoint = function.getEntryPoint();
			CodeUnit codeUnitAt = function.getProgram().getListing().getCodeUnitAt(entryPoint);
			if (codeUnitAt == null || !(codeUnitAt instanceof Instruction)) {
				return new CPPResult(entryPoint, function.getPrototypeString(false, false) + ';',
					null, List.of());
			}

			monitor.setMessage("Decompiling " + function.getName());

			DecompileResults dr =
				decompiler.decompileFunction(function, options.getDefaultTimeout(), monitor);
			String errorMessage = dr.getErrorMessage();
			if (!"".equals(errorMessage)) {
				Msg.warn(CppExporter.this, "Error decompiling: " + errorMessage);
				if (options.isWARNCommentIncluded()) {
					monitor.incrementProgress(1);
					return new CPPResult(entryPoint, null,
						"/*" + EOL + "Unable to decompile '" + function.getName() + "'" + EOL +
							"Cause: " + errorMessage + EOL + "*/" + EOL,
						List.of());
				}
				return null;
			}

			Program prog = function.getProgram();
			DecompiledFunction decompiledFunction = dr.getDecompiledFunction();
			List<GlobalDecl> globals =
				CollectionUtils.asStream(dr.getHighFunction().getGlobalSymbolMap().getSymbols())
						.map(hsym -> {
							String dt = hsym.getDataType().getDisplayName();
							String name = hsym.getName();
							String space = dt.endsWith("*") ? "" : " ";

							VariableStorage storage = hsym.getStorage();
							Address symAddr = (storage != null && storage.isMemoryStorage())
									? storage.getMinAddress()
									: null;

							String declaration;
							if (emitGlobalData && symAddr != null) {
								Data data = prog.getListing().getDataAt(symAddr);
								String initializer = buildDataInitializer(data);
								declaration = initializer != null
										? "%s%s%s = %s;".formatted(dt, space, name, initializer)
										: "%s%s%s;".formatted(dt, space, name);
							}
							else {
								declaration = "%s%s%s;".formatted(dt, space, name);
							}
							return new GlobalDecl(symAddr, declaration);
						})
						.toList();
			return new CPPResult(entryPoint, decompiledFunction.getSignature(),
				decompiledFunction.getC(), globals);
		}
	}

	/**
	 * A class that exists because we are doing something that the ConcurrentQ was not
	 * designed for--chunking.  We do not want out monitor being reset every time we start a new
	 * chunk. So, we wrap a real monitor, overriding the behavior such that initialize() has
	 * no effect when it is called by the queue.
	 */
	private class ChunkingTaskMonitor extends TaskMonitorAdapter {
		private TaskMonitor monitor;

		ChunkingTaskMonitor(TaskMonitor monitor) {
			this.monitor = monitor;
		}

		void doInitialize(long value) {
			// this lets us initialize when we want to
			monitor.initialize(value);
		}

		@Override
		public void setProgress(long value) {
			monitor.setProgress(value);
		}

		@Override
		public void checkCancelled() throws CancelledException {
			monitor.checkCancelled();
		}

		@Override
		public void setMessage(String message) {
			monitor.setMessage(message);
		}

		@Override
		public synchronized void addCancelledListener(CancelledListener listener) {
			monitor.addCancelledListener(listener);
		}

		@Override
		public synchronized void removeCancelledListener(CancelledListener listener) {
			monitor.removeCancelledListener(listener);
		}
	}
}
