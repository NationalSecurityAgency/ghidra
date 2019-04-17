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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import util.demangler.*;

/**
 * A class to represent a demangled function.
 */
public class DemangledFunction extends DemangledObject implements ParameterReceiver {

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

	/**
	 * Constructs a new demangled function.
	 * @param name the name of the function
	 */
	public DemangledFunction(String name) {
		setName(name);
	}

	DemangledFunction(GenericDemangledFunction other) {
		super(other);

		GenericDemangledDataType otherReturnType = other.getReturnType();
		if (otherReturnType != null) {
			returnType = (DemangledDataType) DemangledObjectFactory.convert(otherReturnType);
		}
		callingConvention = other.getCallingConvention();
		thisPassedOnStack = other.isPassedOnStack();

		GenericDemangledTemplate otherTemplate = other.getTemplate();
		if (otherTemplate != null) {
			template = new DemangledTemplate(otherTemplate);
		}
		isOverloadedOperator = other.isOverloadedOperator();

		List<GenericDemangledDataType> otherParams = other.getParameters();
		for (GenericDemangledDataType parameter : otherParams) {
			parameters.add((DemangledDataType) DemangledObjectFactory.convert(parameter));
		}
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

	/**
	 * @see ghidra.app.util.demangler.ParameterReceiver
	 */
	@Override
	public void addParameter(DemangledDataType parameter) {
		parameters.add(parameter);
	}

	/**
	 * @see ghidra.app.util.demangler.ParameterReceiver
	 */
	@Override
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

	/** Special constructor where it has a templated type before the parameter list */
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
		StringBuffer buffer = new StringBuffer();

		if (!(returnType instanceof DemangledFunctionPointer)) {
			buffer.append(specialPrefix == null ? "" : specialPrefix + " ");
			if (isThunk) {
				buffer.append("[thunk]:");
			}
			buffer.append(
				visibility == null || "global".equals(visibility) ? "" : visibility + " ");
//			if (virtual) {
			if (isVirtual) {
				buffer.append("virtual ");
			}
			if (isStatic) {
				buffer.append("static ");
			}
			if (!isTypeCast()) {
				buffer.append(returnType == null ? "" : returnType.toSignature() + " ");
			}
//			buffer.append(returnType == null ? "" : returnType.toSignature() + " ");
		}

		buffer.append(callingConvention == null ? "" : callingConvention + " ");
		if (namespace != null) {
			buffer.append(namespace.toNamespace());
		}

		buffer.append(getDemangledName());
		if (isTypeCast()) {
			buffer.append(returnType == null ? "" : " " + returnType.toSignature() + " ");
		}

		if (template != null) {
			buffer.append(template.toTemplate());
		}

		if (specialMidfix != null) {
			buffer.append('[').append(specialMidfix).append(']');
		}

		// check for special case of 'conversion operator' where we only want to display '()' and
		// not (void)
//		if (name.endsWith("()")) {
//			if (name.equals("operator")) {
//				buffer.append("()");
//			}
//		}
//		else {
		if (templatedConstructorType != null) {
			buffer.append('<').append(templatedConstructorType).append('>');
		}

		Iterator<DemangledDataType> paramIterator = parameters.iterator();
		buffer.append('(');
		String pad = format ? pad(buffer.length()) : "";
		if (!paramIterator.hasNext()) {
			buffer.append("void");
		}

		while (paramIterator.hasNext()) {
			buffer.append(paramIterator.next().toSignature());
			if (paramIterator.hasNext()) {
				buffer.append(',');
				if (format) {
					buffer.append('\n');
				}
				buffer.append(pad);
			}
		}

		buffer.append(')');
		buffer.append(storageClass == null ? "" : " " + storageClass);
//		}

		if (returnType instanceof DemangledFunctionPointer) {
			DemangledFunctionPointer funcPtr = (DemangledFunctionPointer) returnType;
			String partialSig = funcPtr.toSignature(buffer.toString());
			buffer = new StringBuffer();
			buffer.append(specialPrefix == null ? "" : specialPrefix + " ");
			buffer.append(
				visibility == null || "global".equals(visibility) ? "" : visibility + " ");
			//if (virtual || super.isVirtual) {
			if (isVirtual) {
				buffer.append("virtual ");
			}
			buffer.append(partialSig);
		}
		else {
			if (specialSuffix != null) {
				buffer.append(specialSuffix);
			}
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

	public String getParameterString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append('(');
		Iterator<DemangledDataType> dditer = parameters.iterator();
		while (dditer.hasNext()) {
			buffer.append(dditer.next().toSignature());
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

	@Override
	public boolean applyTo(Program program, Address address, DemanglerOptions options,
			TaskMonitor monitor) throws Exception {

		if (isAlreadyDemangled(program, address)) {
			return true;
		}

		if (!super.applyTo(program, address, options, monitor)) {
			return false;
		}

		Function function = createFunction(program, address, options.doDisassembly(), monitor);
		if (function == null) {
			// no function whose signature we need to update
			// NOTE: this does not make much sense
			// renameExistingSymbol(program, address, symbolTable);
			// maybeCreateUndefined(program, address);
			return false;
		}

		//if existing function signature is user defined - add demangled label only
		boolean makePrimary = (function.getSignatureSource() != SourceType.USER_DEFINED);

		Symbol demangledSymbol = applyDemangledName(function.getEntryPoint(), makePrimary,
			false, program);
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
			bookmarkParameterMismatch(program, function.getEntryPoint(), args);
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

	private void bookmarkParameterMismatch(Program program, Address address,
			List<ParameterDefinitionImpl> args) {

		if (parameters.isEmpty()) {
			return;
		}

		int pointerSize = program.getDefaultPointerSize();
		BookmarkManager bookmarkManager = program.getBookmarkManager();
		for (int i = 0; i < args.size(); i++) {
			if (args.get(i).getLength() > pointerSize) {
				bookmarkManager.setBookmark(address, BookmarkType.ANALYSIS, "Demangler",
					"Couldn't Apply demangled signature - probably due to datatype that is too " +
						"large to fit in a parameter");
			}
		}

		bookmarkManager.setBookmark(address, BookmarkType.ANALYSIS, "Demangler",
			"Couldn't Apply demangled signature - bad parameter number match (" + args.size() +
				") in a function in a namespace");
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

	private DataType resolveReturnType(Program program, Function func, Structure classDataType) {
		// If something is returned as a Union, Structure, or Class return.
		//       It appears that is passed as an additional parameter.  Essentially, it accesses
		//       the stack assuming there is reserved space.
		if (returnType != null) {
			return returnType.getDataType(program.getDataTypeManager());
		}

		// If returnType is null check for constructor or destructor names
		if (THIS_CALL.equals(func.getCallingConventionName())) {
			String n = getName();
			if (n.equals("~" + namespace.getName()) || n.equals(namespace.getName())) {
				// constructor && destructor
				return VoidDataType.dataType;
			}
		}
		return null;
	}

	private Structure maybeUpdateCallingConventionAndCreateClass(Program program, Function func) {
		try {
			// If the calling convention is known, should use it!
			if (callingConvention != null) {
				if (program.getCompilerSpec().getCallingConvention(callingConvention) == null) {
					// warn that calling convention not found.  Datatypes are still good,
					// the real calling convention can be figured out later
					//   For example X64 can have __cdecl, __fastcall, __stdcall, that are accepted but ignored
					program.getBookmarkManager().setBookmark(func.getEntryPoint(),
						BookmarkType.ANALYSIS, "Demangler", "Warning calling convention \"" +
							callingConvention + "\" not defined in Compiler Spec (.cspec)");
				}
				else {
					func.setCallingConvention(callingConvention);
					if (THIS_CALL.equals(callingConvention)) {
						return createClassStructure(program, func);
					}
					return null;
				}
			}

			if (isThisCall(func)) {
				func.setCallingConvention(THIS_CALL);
				return createClassStructure(program, func);
			}
//          Leave the calling convention to someone else to figure out
//			else {
//				String defaultConvention = getDefaultCallingConvention(program);
//				if (defaultConvention != null) {
//					func.setCallingConvention(defaultConvention);
//				}
//			}
		}
		catch (InvalidInputException e) {
			e.printStackTrace();
		}
		return null;
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
		int existingParameterCount = func.getParameterCount();

		// If this function is not in a namespace, we don't care if the parameters mismatch,
		// just apply them.
		if (namespace == null || namespace.getName().startsWith("__")) {
			return false;
		}

		// If we don't know the parameters, and have already decided on This calling
		// convention. is not a problem.
		String callingConventionName = func.getCallingConventionName();
		if (existingParameterCount == 0 && THIS_CALL.equals(callingConventionName)) {
			return false;
		}

		// Default source types can be overridden
		if (func.getSignatureSource() == SourceType.DEFAULT) {
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

		// TODO: It STILL COULD be a this call, we just don't know!
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
		DemangledType ns = namespace;

		// if my immediate namespace is "std", then I am just a function in the std namespace.
		if (ns == null) {
			return false;
		}
		if (ns.getName().toLowerCase().equals(STD_NAMESPACE)) {
			return true;
		}
		return false;
	}

	static Function createFunction(Program prog, Address addr, boolean doDisassembly,
			TaskMonitor monitor) {
		Listing listing = prog.getListing();
		Function func = listing.getFunctionAt(addr);
		if (func != null) {
			return func;
		}

		if (addr.isExternalAddress()) {
			Symbol extSymbol = prog.getSymbolTable().getPrimarySymbol(addr);
			CreateExternalFunctionCmd cmd = new CreateExternalFunctionCmd(extSymbol);
			cmd.applyTo(prog);
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
			cmd.applyTo(prog, monitor);
		}
		return listing.getFunctionAt(addr);
	}
}
