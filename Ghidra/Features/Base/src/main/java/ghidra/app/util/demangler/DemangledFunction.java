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
package ghidra.app.util.demangler;

import java.util.*;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.*;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * A class to represent a demangled function.
 */
public class DemangledFunction extends DemangledObject {

	public static final String VOLATILE = "volatile";
	public static final String CONST = "const";
	public final static String PTR64 = "__ptr64";
	public static final String UNALIGNED = "__unaligned";
	public static final String RESTRICT = "__restrict";

	private static final String STD_NAMESPACE = "std";
	private static final String THIS_CALL = "__thiscall";
	protected DemangledDataType returnType;
	protected String callingConvention;// __cdecl, __thiscall, etc.
	protected boolean thisPassedOnStack = true;
	protected List<DemangledDataType> parameters = new ArrayList<>();
	protected DemangledTemplate template;
	protected boolean isOverloadedOperator = false;

	/** Special constructor where it has a templated type before the parameter list */
	private String templatedConstructorType;

	private boolean isTrailingConst;
	private boolean isTrailingVolatile;
	private boolean isTrailingPointer64;
	private boolean isTrailingUnaligned;
	private boolean isTrailingRestrict;
	private boolean isTypeCast;
	private String throwAttribute;

	public DemangledFunction(String mangled, String originalDemangled, String name) {
		super(mangled, originalDemangled);
		setName(name);
	}

	/**
	 * Sets the function return type.
	 * @param returnType the function return type
	 */
	public void setReturnType(DemangledDataType returnType) {
		this.returnType = returnType;
	}

	/**
	 * Sets the function calling convention. For example, "__cdecl".
	 * @param callingConvention the function calling convention
	 */
	public void setCallingConvention(String callingConvention) {
		this.callingConvention = callingConvention;
	}

	public void setTemplate(DemangledTemplate template) {
		this.template = template;
	}

	public DemangledTemplate getTemplate() {
		return template;
	}

	/**
	 * Sets whether this demangled function represents
	 * an overloaded operator. For example, "operator+()".
	 * @param isOverloadedOperator true if overloaded operator
	 */
	public void setOverloadedOperator(boolean isOverloadedOperator) {
		this.isOverloadedOperator = isOverloadedOperator;
	}

	public void addParameter(DemangledDataType parameter) {
		parameters.add(parameter);
	}

	public List<DemangledDataType> getParameters() {
		return new ArrayList<>(parameters);
	}

	/**
	 * Returns the return type or null, if unspecified.
	 * @return the return type or null, if unspecified
	 */
	public DemangledDataType getReturnType() {
		return returnType;
	}

	/**
	 * Returns the calling convention or null, if unspecified.
	 * @return the calling convention or null, if unspecified
	 */
	public String getCallingConvention() {
		return callingConvention;
	}

	/**
	 * Special constructor where it has a templated type before the parameter list
	 * @param type the type
	 */
	public void setTemplatedConstructorType(String type) {
		this.templatedConstructorType = type;
	}

	public boolean isTrailingConst() {
		return isTrailingConst;
	}

	public void setTrailingConst() {
		isTrailingConst = true;
	}

	public boolean isTrailingVolatile() {
		return isTrailingVolatile;
	}

	public void setTrailingVolatile() {
		isTrailingVolatile = true;
	}

	public boolean isTrailingPointer64() {
		return isTrailingPointer64;
	}

	public void setTrailingPointer64() {
		isTrailingPointer64 = true;
	}

	public boolean isTrailingUnaligned() {
		return isTrailingUnaligned;
	}

	public void setTrailingUnaligned() {
		isTrailingUnaligned = true;
	}

	public boolean isTrailingRestrict() {
		return isTrailingRestrict;
	}

	public void setTrailingRestrict() {
		isTrailingRestrict = true;
	}

	public boolean isTypeCast() {
		return isTypeCast;
	}

	public void setTypeCast() {
		isTypeCast = true;
	}

	public void setThrowAttribute(String throwAttribute) {
		this.throwAttribute = throwAttribute;
	}

	@Override
	public String getSignature(boolean format) {
		StringBuilder buffer = new StringBuilder();

		if (!(returnType instanceof DemangledFunctionPointer)) {
			buffer.append(specialPrefix == null ? "" : specialPrefix + " ");
			if (isThunk) {
				buffer.append("[thunk]:");
			}
			buffer.append(
				visibility == null || "global".equals(visibility) ? "" : visibility + " ");
			if (isVirtual) {
				buffer.append("virtual ");
			}
			if (isStatic) {
				buffer.append("static ");
			}
			if (!isTypeCast()) {
				buffer.append(returnType == null ? "" : returnType.getSignature() + " ");
			}
		}

		buffer.append(callingConvention == null ? "" : callingConvention + " ");
		if (namespace != null) {
			buffer.append(namespace.getNamespaceString());
			buffer.append(NAMESPACE_SEPARATOR);
		}

		buffer.append(getDemangledName());
		if (isTypeCast()) {
			buffer.append(returnType == null ? "" : " " + returnType.getSignature() + " ");
		}

		if (template != null) {
			buffer.append(template.toTemplate());
		}

		if (templatedConstructorType != null) {
			buffer.append('<').append(templatedConstructorType).append('>');
		}

		addParameters(buffer, format);

		buffer.append(storageClass == null ? "" : " " + storageClass);

		if (returnType instanceof DemangledFunctionPointer) {
			DemangledFunctionPointer funcPtr = (DemangledFunctionPointer) returnType;
			String partialSig = funcPtr.toSignature(buffer.toString());
			buffer = new StringBuilder();
			buffer.append(specialPrefix == null ? "" : specialPrefix + " ");
			buffer.append(
				visibility == null || "global".equals(visibility) ? "" : visibility + " ");
			if (isVirtual) {
				buffer.append("virtual ");
			}
			buffer.append(partialSig);
		}

		if (isTrailingConst()) {
			if (buffer.length() > 2) {
				buffer.append(SPACE);
			}
			buffer.append(CONST);
		}
		if (isTrailingVolatile()) {
			if (buffer.length() > 2) {
				buffer.append(SPACE);
			}
			buffer.append(VOLATILE);
		}
		if (isTrailingUnaligned) {
			if (buffer.length() > 2) {
				buffer.append(SPACE);
			}
			buffer.append(UNALIGNED);
		}
		if (isTrailingPointer64) {
			if (buffer.length() > 2) {
				buffer.append(SPACE);
			}
			buffer.append(PTR64);
		}
		if (isTrailingRestrict) {
			if (buffer.length() > 2) {
				buffer.append(SPACE);
			}
			buffer.append(RESTRICT);
		}
		if (throwAttribute != null) {
			if (buffer.length() > 2) {
				buffer.append(SPACE);
			}
			buffer.append(throwAttribute);
		}

		return buffer.toString();
	}

	protected void addParameters(StringBuilder buffer, boolean format) {
		Iterator<DemangledDataType> paramIterator = parameters.iterator();
		buffer.append('(');
		int padLength = format ? buffer.length() : 0;
		String pad = StringUtils.rightPad("", padLength);
		if (!paramIterator.hasNext()) {
			buffer.append("void");
		}

		while (paramIterator.hasNext()) {
			buffer.append(paramIterator.next().getSignature());
			if (paramIterator.hasNext()) {
				buffer.append(',');
				if (format) {
					buffer.append('\n');
				}
				buffer.append(pad);
			}
		}

		buffer.append(')');
	}

	@Override
	public String getNamespaceName() {
		return getName() + getParameterString();
	}

	public String getParameterString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append('(');
		Iterator<DemangledDataType> dditer = parameters.iterator();
		while (dditer.hasNext()) {
			buffer.append(dditer.next().getSignature());
			if (dditer.hasNext()) {
				buffer.append(',');
			}
		}
		buffer.append(')');
		return buffer.toString();
	}

	@Override
	protected boolean isAlreadyDemangled(Program program, Address address) {
		Function f = program.getListing().getFunctionAt(address);
		if (f != null && f.getSymbol().getSource() == SourceType.USER_DEFINED) {
			return true;
		}
		if (f == null || f.getSignatureSource() == SourceType.DEFAULT ||
			f.getSignatureSource() == SourceType.ANALYSIS) {
			return false;
		}
		return super.isAlreadyDemangled(program, address);
	}

	/**
	 * This method assumes preconditions test has been run.
	 */
	private boolean shouldDisassemble(Program program, Address address, DemanglerOptions options) {
		CodeUnit codeUnit = program.getListing().getCodeUnitAt(address);
		return (codeUnit instanceof Data); // preconditions check guarantees data is undefined data.
	}

	private boolean passesPreconditions(Program program, Address address) throws Exception {

		if (!demangledNameSuccessfully()) {
			throw new DemangledException("Symbol did not demangle at address: " + address);
		}

		if (isAlreadyDemangled(program, address)) {
			return false; // not an error, but signifies that we should not continue to process
		}

		if (address.isMemoryAddress()) {
			CodeUnit codeUnit = program.getListing().getCodeUnitAt(address);
			if (codeUnit == null) {
				throw new IllegalArgumentException(
					"Address not in memory or is off-cut data/instruction: " + address);
			}
			if (codeUnit instanceof Data) {
				if (((Data) codeUnit).isDefined()) {
					throw new IllegalArgumentException("Defined data at address: " + address);
				}
			}
		}
		return true;
	}

	@Override
	public boolean applyTo(Program program, Address address, DemanglerOptions options,
			TaskMonitor monitor) throws Exception {

		// Account for register context.  This class may trigger disassembly, so we need to make
		// sure that the context is correctly set before that happens.  Also, be sure to apply
		// the function to the correct address.
		address = PseudoDisassembler.setTargeContextForDisassembly(program, address);

		if (!passesPreconditions(program, address)) {
			return true; // eventually will not return anything 
		}

		if (!super.applyTo(program, address, options, monitor)) {
			return false;
		}

		boolean disassemble = shouldDisassemble(program, address, options);
		Function function = createFunction(program, address, disassemble, monitor);
		if (function == null) {
			// No function whose signature we need to update
			return false;
		}

		if (function.isThunk()) {
			// If thunked function has same mangled name we can discard our
			// symbol if no other symbols at this address (i.e., rely entirely on
			// thunked function).
			// NOTE: mangled name on external may be lost once it is demangled.
			if (shouldThunkBePreserved(function)) {
				// Preserve thunk and remove mangled symbol.  Allow to proceed normally by returning true.
				function.getSymbol().setName(null, SourceType.DEFAULT);
				return true;
			}

			// Break thunk relationship and continue applying demangle function below
			function.setThunkedFunction(null);
		}

		// If existing function signature is user defined - add demangled label only
		boolean makePrimary = (function.getSignatureSource() != SourceType.USER_DEFINED);

		Symbol demangledSymbol =
			applyDemangledName(function.getEntryPoint(), makePrimary, false, program);
		if (demangledSymbol == null) {
			return false;
		}

		if (!options.applySignature() || function.getSignatureSource() == SourceType.USER_DEFINED) {
			return true;
		}

		Structure classStructure = maybeUpdateCallingConventionAndCreateClass(program, function);

		FunctionDefinitionDataType signature = new FunctionDefinitionDataType(function, true);

		List<ParameterDefinitionImpl> args = convertMangledToParamDef(program);
		signature.setArguments(args.toArray(new ParameterDefinition[args.size()]));
		if (hasVarArgs()) {
			signature.setVarArgs(true);
		}
		if (!function.isExternal() && isParameterMismatch(function, signature)) {
			bookmarkParameterMismatch(program, function.getEntryPoint());
			return true;
		}

		DataType resolvedReturnType = resolveReturnType(program, function, classStructure);
		if (resolvedReturnType != null) {
			signature.setReturnType(resolvedReturnType);
		}

		ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(function.getEntryPoint(),
			signature, SourceType.IMPORTED, true, false);
		cmd.applyTo(program);

		return true;
	}

	/**
	 * Determine if existing thunk relationship should be preserved and mangled symbol
	 * discarded.  This is the case when the thunk function mangled name matches
	 * the thunked function since we want to avoid duplicate symbol names.
	 * @param thunkFunction thunk function with a mangled symbol which is currently
	 * being demangled.
	 * @return true if thunk should be preserved and mangled symbol discarded, otherwise
	 * false if thunk relationship should be eliminated and demangled function information
	 * should be applied as normal.
	 */
	private boolean shouldThunkBePreserved(Function thunkFunction) {
		Program program = thunkFunction.getProgram();
		SymbolTable symbolTable = program.getSymbolTable();
		if (thunkFunction.getSymbol().isExternalEntryPoint()) {
			return false; // entry point should retain its own symbol
		}
		Symbol[] symbols = symbolTable.getSymbols(thunkFunction.getEntryPoint());
		if (symbols.length > 1) {
			return false; // too many symbols present to preserve thunk
		}
		// NOTE: order of demangling unknown - thunked function may, or may not, have
		// already been demangled
		Function thunkedFunction = thunkFunction.getThunkedFunction(true);
		if (mangled.equals(thunkedFunction.getName())) {
			// thunked function has matching mangled name
			return true;
		}
		if (thunkedFunction.isExternal()) {
			if (thunkedFunction.getParentNamespace() instanceof Library) {
				// Thunked function does not have mangled name, if it did it would have
				// matched name check above or now reside in a different namespace
				return false;
			}
			// assume external contained with specific namespace
			ExternalLocation externalLocation =
				program.getExternalManager().getExternalLocation(thunkedFunction.getSymbol());
			String originalImportedName = externalLocation.getOriginalImportedName();
			if (originalImportedName == null) {
				// assume external manually manipulated without use of mangled name
				return false;
			}
			if (mangled.equals(externalLocation.getOriginalImportedName())) {
				// matching mangled name also resides at thunked function location
				return true;
			}

			// TODO: carefully compare signature in absence of matching mangled name
			return false;
		}

		if (symbolTable.getSymbol(mangled, thunkedFunction.getEntryPoint(),
			program.getGlobalNamespace()) != null) {
			// matching mangled name also resides at thunked function location
			return true;
		}

		return false;
	}

	private boolean hasVarArgs() {
		if (parameters.isEmpty()) {
			return false;
		}

		DemangledDataType lastType = parameters.get(parameters.size() - 1);
		return lastType.isVarArgs();
	}

	private boolean hasVoidParams() {
		if (parameters.size() == 1) {
			DemangledDataType ddt = parameters.get(0);
			return ddt.isVoid() && !ddt.isPointer();
		}
		return false;
	}

	private void bookmarkParameterMismatch(Program program, Address address) {

		if (parameters.isEmpty()) {
			return;
		}

		BookmarkManager bookmarkManager = program.getBookmarkManager();
		bookmarkManager.setBookmark(address, BookmarkType.ANALYSIS, "Demangler",
			"Couldn't apply demangled signature - mismatch with existing signature");
	}

	static void maybeCreateUndefined(Program program, Address address) {

		Listing listing = program.getListing();
		Instruction instruction = listing.getInstructionContaining(address);
		if (instruction != null) {
			return;
		}

		Data data = listing.getDefinedDataContaining(address);
		if (data != null) {
			return;
		}

		// put down a marker so other code does not try to disassemble
		DataType demangledDT = Undefined.getUndefinedDataType(1);
		try {
			listing.createData(address, demangledDT);
		}
		catch (CodeUnitInsertionException e) {
			// ignore
		}
		catch (DataTypeConflictException e) {
			// ignore - should not happen
		}
	}

	private DataType resolveReturnType(Program program, Function function,
			Structure classDataType) {
		// If something is returned as a Union, Structure, or Class return.
		//       It appears that is passed as an additional parameter.  Essentially, it accesses
		//       the stack assuming there is reserved space.
		if (returnType != null) {
			return returnType.getDataType(program.getDataTypeManager());
		}

		// If returnType is null check for constructor or destructor names
		if (THIS_CALL.equals(function.getCallingConventionName())) {
			String n = getName();
			if (n.equals(namespace.getName())) {
				// constructor
				return DataType.DEFAULT;
			}
			if (n.equals("~" + namespace.getName())) {
				// destructor
				return VoidDataType.dataType;
			}
		}
		return null;
	}

	private Structure maybeUpdateCallingConventionAndCreateClass(Program program,
			Function function) {

		String convention = validateCallingConvention(program, function);
		if (convention == null) {
			if (!isThisCall(function)) {
				return null;
			}
			convention = THIS_CALL;
		}

		try {
			function.setCallingConvention(convention);
			return maybeCreateClassStructure(program, function, convention);
		}
		catch (InvalidInputException e) {
			Msg.error(this, "Unexpected exception setting calling convention", e);
		}

		return null;
	}

	private String validateCallingConvention(Program program, Function function) {

		if (callingConvention == null) {
			return null;
		}

		if (program.getCompilerSpec().getCallingConvention(callingConvention) == null) {
			// warn that calling convention not found.  Datatypes are still good,
			// the real calling convention can be figured out later
			//   For example X64 can have __cdecl, __fastcall, __stdcall, that
			//   are accepted but ignored
			BookmarkManager bm = program.getBookmarkManager();
			Address entry = function.getEntryPoint();
			bm.setBookmark(entry, BookmarkType.ANALYSIS, "Demangler",
				"Could not apply calling convention \"" + callingConvention +
					"\" not defined in Compiler Spec (.cspec)");
			return null;
		}

		return callingConvention;
	}

	private List<ParameterDefinitionImpl> convertMangledToParamDef(Program program) {

		List<ParameterDefinitionImpl> args = new ArrayList<>();
		for (DemangledDataType param : parameters) {
			// stop when a void parameter is hit.  This probably the only defined parameter.
			if (param.isVoid() && !param.isPointer()) {
				break;
			}
			if (param.isVarArgs()) {
				break;
			}

			DataType dt = param.getDataType(program.getDataTypeManager());
			args.add(new ParameterDefinitionImpl(null, dt, null));
		}
		return args;
	}

	private boolean isParameterMismatch(Function func, FunctionSignature signature) {

		// Default source types can be overridden
		if (func.getSignatureSource() == SourceType.DEFAULT) {
			return false;
		}

		int existingParameterCount = func.getParameterCount();

		// If we don't know the parameters, and have already decided on This calling
		// convention. is not a problem.
		String callingConventionName = func.getCallingConventionName();
		if (existingParameterCount == 0 && THIS_CALL.equals(callingConventionName)) {
			return false;
		}

		// are the data types already on the signature better than analysis provided ones
		if (isDefinedFunctionDataTypes(func)) {
			return true;
		}

		// If this function is not in a namespace, we don't care if the parameters mismatch,
		// just apply them.
		if (namespace == null || namespace.getName().startsWith("__")) {
			return false;
		}

		// If a function is in a namespace, must be VERY careful
		int mangledParamterCount = parameters.size();
		if (hasVoidParams()) {
			mangledParamterCount = 0;
		}

		boolean hasVarArgs = false;
		if (mangledParamterCount != 0) {
			hasVarArgs = hasVarArgs();
			if (hasVarArgs) {
				--mangledParamterCount;
			}
		}

		if (hasVarArgs != func.hasVarArgs()) {
			return true;
		}

		if (existingParameterCount == 0 && mangledParamterCount > 0) {
			// if operator overloading can have up to two parameters and can detect this
			// without full function params.
			if (isOverloadedOperator && parameters.size() <= 2) {
				return false;
			}

			// if there is only one compiler spec, then don't need to worry, just assign
			// them as we see them
			PrototypeModel[] specs = func.getProgram().getCompilerSpec().getCallingConventions();
			if (specs == null || specs.length == 1) {
				return false;
			}

			// no params defined, can't tell if detected is different
			return true;
		}

		return false;
	}

	/**
	 * check if the return/param data types were defined by better than analysis (user, import)
	 *
	 * @param func the function to check
	 * @return true if the parameters are not undefined, or are of a higher source type.
	 */
	protected boolean isDefinedFunctionDataTypes(Function func) {
		Parameter[] funcParams = func.getParameters();

		for (Parameter parameter : funcParams) {
			if (parameter.isAutoParameter()) {
				// automatic parameter, is OK.
				continue;
			}
			// check for default type of data type
			DataType dt = parameter.getDataType();
			dt = DataTypeUtilities.getBaseDataType(dt);
			if (dt == null || Undefined.isUndefined(dt)) {
				continue;
			}
			// if the parameters source is higher than
			if (parameter.getSource().isHigherPriorityThan(SourceType.ANALYSIS)) {
				return true;
			}
		}

		// if already a return type and this one has a return type
		DataType returnDT = func.getReturnType();
		returnDT = DataTypeUtilities.getBaseDataType(returnDT);
		if (!(returnDT == null || Undefined.isUndefined(returnDT)) &&
			this.getReturnType() != null) {
			return true;
		}

		return false;
	}

	/**
	 * Overloaded operators with more than 1 parameter are global
	 * and therefore not contained inside a class.
	 * Note: global overloaded operators could be contained
	 * inside namespaces (e.g., std).
	 */
	private boolean isThisCall(Function func) {
		if (namespace == null || StringUtils.isBlank(namespace.getName())) {
			// must be global; no parent namespace
			return false;
		}

		// if we are a function, and the parent namespace is the STD namespace, not even
		// really in a class
		if (isInStdNameSpace()) {
			return false;
		}

		// if operator overloading and have less than one param, then can take this.
		int mangledParameterCount = parameters.size();
		if (isOverloadedOperator && mangledParameterCount <= 1) {
			return true;// not global; on a class
		}

		if (isOverloadedOperator && mangledParameterCount == 2) {
			return false;
		}

		String n = getName();
		if (n.startsWith("~")) {
			// class destructor
			return true;
		}

		// if the function name is the same name as it's namespace
		// TODO: this seems too flexible - why not use equals?
		if (n.startsWith(namespace.getName())) {
			return true;
		}

		// check if function is just an address pointer to another location
		Program program = func.getProgram();
		Data data = program.getListing().getDefinedDataAt(func.getEntryPoint());
		if (data != null && data.getAddress(0) != null) {
			Function newfunc = program.getFunctionManager().getFunctionAt(data.getAddress(0));
			// if that function is a this call
			if (newfunc != null) {
				if (THIS_CALL.equals(newfunc.getCallingConventionName())) {
					return true;
				}
				func = newfunc;
			}
		}

		// If we have # params detected == num params we do not have a this call
		// If we have # params detected == (num_params+1) we have this call
		if (func.getParameterCount() == mangledParameterCount + 1) {
			return true;
		}

		//       It STILL COULD be a this call, we just don't know!
		//       But is also could be a static member function!
		//       The only way to really tell is compare the number of detected parameters
		//       to the number of parameters we have, OR, to detect the calling convention
		//       based on say a passing of ECX
		return false;
	}

	/**
	 * Check that this function is not in the std namespace.
	 * NOTE: There could be other namespaces, but this is a key one.
	 *
	 * @return true if it is in the std namespace
	 */
	private boolean isInStdNameSpace() {
		Demangled ns = namespace;

		// if my immediate namespace is "std", then I am just a function in the std namespace.
		if (ns == null) {
			return false;
		}
		if (ns.getName().equalsIgnoreCase(STD_NAMESPACE)) {
			return true;
		}
		return false;
	}

	protected Structure maybeCreateClassStructure(Program program, Function function,
			String convention) {

		if (!THIS_CALL.equals(convention)) {
			return null;
		}

		if (namespace == null) {
			return null;
		}

		String className = namespace.getName();
		Symbol parentSymbol = function.getSymbol().getParentSymbol();
		if (parentSymbol.getSymbolType() == SymbolType.NAMESPACE) {
			try {
				NamespaceUtils.convertNamespaceToClass((Namespace) parentSymbol.getObject());
			}
			catch (InvalidInputException e) {
				throw new AssertException(e); // unexpected condition
			}
		}

		// Store class structure in parent namespace
		Demangled classNamespace = namespace.getNamespace();
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType existingType =
			DemangledDataType.findDataType(dataTypeManager, classNamespace, className);
		if (existingType != null && !(existingType instanceof Structure)) {
			BookmarkManager bm = program.getBookmarkManager();
			Address entry = function.getEntryPoint();
			bm.setBookmark(entry, BookmarkType.ANALYSIS, "Demangler",
				"Could not create class structure, data type already exists: " + existingType);
			return null;
		}

		Structure structure = (Structure) existingType;
		if (structure == null) {
			structure = DemangledDataType.createPlaceHolderStructure(className, classNamespace);
		}
		structure =
			(Structure) dataTypeManager.resolve(structure, DataTypeConflictHandler.DEFAULT_HANDLER);
		return structure;
	}

	protected Function createFunction(Program prog, Address addr, boolean doDisassembly,
			TaskMonitor monitor) throws DemangledException {
		Listing listing = prog.getListing();
		Function func = listing.getFunctionAt(addr);
		if (func != null) {
			return func;
		}

		if (addr.isExternalAddress()) {
			Symbol extSymbol = prog.getSymbolTable().getPrimarySymbol(addr);
			CreateExternalFunctionCmd cmd = new CreateExternalFunctionCmd(extSymbol);
			if (!cmd.applyTo(prog)) {
				throw new DemangledException("Unable to create function: " + cmd.getStatusMsg());
			}
		}
		else {
			if (doDisassembly) {
				// make sure it is executable!
				AddressSetView execSet = prog.getMemory().getExecuteSet();
				if (execSet.contains(addr)) {
					DisassembleCommand cmd = new DisassembleCommand(addr, null, true);
					cmd.applyTo(prog, monitor);
				}
			}
			CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
			if (!cmd.applyTo(prog, monitor)) {
				throw new DemangledException("Unable to create function: " + cmd.getStatusMsg());
			}
		}
		return listing.getFunctionAt(addr);
	}
}
