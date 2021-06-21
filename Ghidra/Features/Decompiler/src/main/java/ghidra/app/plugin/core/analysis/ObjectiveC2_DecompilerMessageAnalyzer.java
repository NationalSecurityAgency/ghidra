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
package ghidra.app.plugin.core.analysis;

import java.util.*;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.parallel.*;
import ghidra.app.services.*;
import ghidra.app.util.bin.format.macho.SectionNames;
import ghidra.app.util.bin.format.objc2.ObjectiveC2_Constants;
import ghidra.app.util.bin.format.objectiveC.ObjectiveC1_Constants;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ObjectiveC2_DecompilerMessageAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Objective-C 2 Decompiler Message";
	private static final String DESCRIPTION =
		"An analyzer for extracting Objective-C 2.0 message information.";

	private final int MAX_RECURSION_DEPTH = 10;

	/* ************************************************************************** */
	/* ************************************************************************** */
	public ObjectiveC2_DecompilerMessageAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		// The Objective-C 2.0 analyzer should always run after the class
		// analyzer. And everything
		// else apparently.
		// It knows the deal!
		setPriority(new AnalysisPriority(10000000));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		monitor.initialize(set.getNumAddresses());

		AddressIterator iterator = set.getAddresses(true);

		ArrayList<Function> functions = new ArrayList<>();
		while (iterator.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);
			Address address = iterator.next();

			Function function = program.getListing().getFunctionAt(address);
			if (isFunctionInTextSection(program, function)) {
				functions.add(function);
			}
		}
		try {
			runDecompilerAnalysis(program, functions, monitor);
		}
		catch (Exception e) {
			// Oh well.
		}
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return ObjectiveC2_Constants.isObjectiveC2(program);
	}

	/* ************************************************************************** */
	/* ************************************************************************** */

	private void runDecompilerAnalysis(Program program, List<Function> functions,
			TaskMonitor monitor) throws InterruptedException, Exception {

		DecompileConfigurer configurer = decompiler -> setupDecompiler(program, decompiler);

		DecompilerCallback<Void> callback = new DecompilerCallback<Void>(program, configurer) {

			@Override
			public Void process(DecompileResults results, TaskMonitor m) throws Exception {

				inspectFunction(program, results, monitor);
				return null;
			}
		};

		try {
			ParallelDecompiler.decompileFunctions(callback, functions, monitor);
		}
		finally {
			callback.dispose();
		}
	}

	private void inspectFunction(Program program, DecompileResults results, TaskMonitor monitor) {
		String currentClassName = null;
		String currentMethodName = null;

		HighFunction highFunction = results.getHighFunction();
		if (highFunction == null) {
			return;
		}

		Function function = results.getFunction();
		Iterator<PcodeOpAST> pcodeOps = highFunction.getPcodeOps();
		while (pcodeOps.hasNext()) {
			if (monitor.isCancelled()) {
				return;
			}
			currentClassName = null;
			currentMethodName = null;
			PcodeOpAST op = pcodeOps.next();
			String mnemonic = op.getMnemonic();
			if (mnemonic == null || (!mnemonic.equals("CALL") && !mnemonic.equals("CALLIND"))) {
				continue;
			}
			Varnode[] inputs = op.getInputs();
			if (!isObjcCall(program, inputs[0], monitor)) {
				continue;
			}
			boolean isStret = isStretCall(program, inputs[0], monitor);
			for (int i = 1; i < inputs.length; i++) {
				String name;
				boolean isClass = isClass(i, isStret);
				boolean isMessage = isMessage(i, isStret);
				name = getNameForVarnode(program, function, inputs[i], isClass, isMessage, 0, 1,
					monitor);
				if (isClass) {
					currentClassName = name;
				}
				else if (isMessage) {
					currentMethodName = name;
				}
				if (currentClassName != null && currentMethodName != null) {
					break;
				}
			}

			if (currentClassName == null || currentMethodName == null) {
				continue;
			}

			List<String> parameters = new ArrayList<>();
			int paramStart = isStret ? 4 : 3;
			for (int i = paramStart; i < inputs.length; i++) {
				String paramValue =
					getNameForVarnode(program, function, inputs[i], false, false, 0, 1, monitor);
				parameters.add(getIvarNameFromQualifiedName(paramValue));
			}
			setCommentAndReference(program, currentClassName, currentMethodName, op, parameters);
		}

	}

	private void setCommentAndReference(Program program, String currentClassName,
			String currentMethodName, PcodeOpAST op, List<String> parameters) {
		Address objcCallAddress = op.getSeqnum().getTarget();
		objcCallAddress = getAddressInProgram(program, objcCallAddress.getOffset());
		Instruction instruction = program.getListing().getInstructionAt(objcCallAddress);

		String fullyQualifiedName = currentClassName;

		// If the target is an instance variable, we want to display the
		// variable name in the comment, but use the class type when
		// creating the reference.
		if (currentClassName.contains("::")) {
			currentClassName = getClassNameFromQualifiedName(fullyQualifiedName);
		}
		setReference(objcCallAddress, program, currentClassName, currentMethodName);

		if (instruction.getComment(CodeUnit.EOL_COMMENT) != null) {
			return;
		}

		currentClassName = getIvarNameFromQualifiedName(fullyQualifiedName);

		// Formatting based on whether or not the method takes parameters
		currentMethodName += currentMethodName.contains(":") ? "]" : " ]";
		String[] split = currentMethodName.split(":");
		StringBuilder builder = new StringBuilder();
		builder.append("[" + currentClassName + " " + split[0]);
		for (int i = 1; i < split.length; i++) {
			try {
				builder.append(":" + parameters.get(i - 1) + " ");
			}
			catch (Exception e) {
				// Decompiler found less params than the function should really
				// have.
				builder.append(":<<unknown>> ");
			}
			builder.append(split[i]);
		}
		builder.delete(builder.length() - 2, builder.length() - 1);
		instruction.setComment(CodeUnit.EOL_COMMENT, builder.toString());
	}

	private boolean isObjcCall(Program program, Varnode input, TaskMonitor monitor) {
		Address address = getAddressFromVarnode(program, input, 0, monitor);
		if (address == null) {
			return false;
		}
		Symbol symbol = getSymbolFromVarnode(program, input, monitor);
		return isObjcNameMatch(symbol);
	}

	private Address getAddressFromVarnode(Program program, Varnode input, int depth,
			TaskMonitor monitor) {
		if (monitor.isCancelled()) {
			return null;
		}
		if (input == null) {
			return null;
		}
		if (depth >= MAX_RECURSION_DEPTH) {
			return null;
		}
		if (!input.isAddress() && !input.isConstant()) {
			PcodeOp def = input.getDef();
			if (def == null) {
				return null;
			}
			Varnode[] inputs = def.getInputs();
			for (Varnode subInput : inputs) {
				if (monitor.isCancelled()) {
					return null;
				}
				Address address = getAddressFromVarnode(program, subInput, depth + 1, monitor);
				if (address == null) {
					continue;
				}
				address = getAddressInProgram(program, address.getOffset());
				if (address != null && program.getMemory().contains(address)) {
					return address;
				}
			}
		}
		return input.getAddress();
	}

	private Symbol getSymbolFromVarnode(Program program, Varnode input, TaskMonitor monitor) {
		Address address = getAddressFromVarnode(program, input, 0, monitor);
		if (address == null) {
			return null;
		}
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol symbol = symbolTable.getPrimarySymbol(address);
		return symbol;
	}

	private String getNameForVarnode(Program program, Function function, Varnode input,
			boolean isClass, boolean isMethod, int depth, int numInputs, TaskMonitor monitor) {
		try {
			if (depth >= MAX_RECURSION_DEPTH) {
				return "<<unknown>>";
			}
			String name = null;
			if (input == null) {
				return null;
			}
			if (input.isAddress() || input.isConstant()) {
				long offset = input.getOffset();
				name = getNameFromOffset(program, offset, input, isClass, isMethod);
			}
			PcodeOp def = input.getDef();
			if (def == null) {
				if (name == null) {
					name = getParamNameOrOffset(function, input, isClass, isMethod, numInputs);
				}
				return name;
			}
			else if (isSuper2Call(program, input) && !isMethod) {
				name = getSuperClassName(program, input, function);
				return name;
			}
			Varnode[] inputs = def.getInputs();

			if (isObjcCall(program, inputs[0], monitor)) {
				Symbol objcSymbol = getSymbolFromVarnode(program, inputs[0], monitor);
				int classIndex = 1;
				if (objcSymbol.getName().contains("stret")) {
					classIndex = 2;
				}
				if (inputs.length <= classIndex) {
					PcodeOp callDefinition = inputs[0].getDef();
					if (callDefinition == null) {
						return null;
					}
					inputs = new Varnode[] { callDefinition.getInput(classIndex) };
				}
				else {
					inputs = new Varnode[] { inputs[classIndex] };
				}
				numInputs = 1;
			}

			int index = getIndexOfAddress(inputs);
			if (index != -1) {
				name =
					getNameFromOffset(program, inputs[index].getOffset(), input, isClass, isMethod);
				if (name != null) {
					return name;
				}
			}
			for (Varnode subInput : inputs) {
				// If a name was found, just unwind the recursion. If it is just
				// a constant (ex. when determining parameters) keep looking
				// to see if we can find an actual name.
				if (name != null && !stringIsLong(name)) {
					break;
				}
				name = getNameForVarnode(program, function, subInput, isClass, isMethod, depth + 1,
					inputs.length, monitor);
			}
			return name;
		}
		catch (Exception e) {
			return null;
		}
	}

	private int getIndexOfAddress(Varnode[] inputs) {
		for (int i = 0; i < inputs.length; i++) {
			if (inputs[i] == null) {
				continue;
			}
			if (inputs[i].isAddress()) {
				return i;
			}
		}
		return -1;
	}

	private String getSuperClassName(Program program, Varnode input, Function function) {
		String name = null;
		SymbolTable symbolTable = program.getSymbolTable();
		Namespace namespace = function.getParentNamespace();
		SymbolIterator symbolIt = symbolTable.getSymbols(namespace.getName());
		while (symbolIt.hasNext()) {
			Symbol symbol = symbolIt.next();
			Address address = symbol.getAddress();
			MemoryBlock block = program.getMemory().getBlock(address);
			if (isObjcDataBlock(block)) {
				Data data = program.getListing().getDataAt(address);
				Data superClassData = data.getComponent(1);
				name = getNameFromData(program, input, true, false, address, superClassData);
			}
		}
		return name;
	}

	private String getParamNameOrOffset(Function function, Varnode input, boolean isClass,
			boolean isMethod, int numInputs) {
		String name = null;
		HighVariable highVar = input.getHigh();
		if (highVar != null) {
			name = highVar.getName();
			if (name != null && name.equals("param_1")) {
				if (numInputs == 1) {
					if (isClass) {
						Namespace namespace = function.getParentNamespace();
						if (namespace != null) {
							name = namespace.getName();
						}
					}
				}
				else {
					name = null;
				}
			}
		}
		if (name == null && !isClass && !isMethod) {
			name = "0x" + Long.toString(input.getOffset(), 16);
		}
		return name;
	}

	private boolean stringIsLong(String value) {
		if (value.startsWith("0x")) {
			value = value.substring(2);
		}
		try {
			Long.parseUnsignedLong(value, 16);
		}
		catch (NumberFormatException e) {
			return false;
		}
		return true;
	}

	private String getNameFromOffset(Program program, long offset, Varnode input, boolean isClass,
			boolean isMethod) {
		String name;
		Address address = getAddressInProgram(program, offset);
		if (address == null) {
			return null;
		}
		MemoryBlock block = program.getMemory().getBlock(address);
		if (block == null) {
			return null;
		}

		if (isIvarBlock(block) || isObjcConstBlock(block)) {
			name = getIvarName(program, address);
		}
		else if (isMessageRefsBlock(block)) {
			name = getFixupMethodName(program, address);
		}
		else if (isCFStringBlock(block)) {
			name = getCFString(program, address);
			if (name != null) {
				if (name.startsWith("\\")) {
					name = "\\" + name;
				}
				name = "\"" + name + "\"";
			}
		}
		else if (isDataBlock(block)) {
			name = getDataName(program, address);
			if (name != null) {
				if (name.startsWith("\\")) {
					name = "\\" + name;
				}
				name = "\"" + name + "\"";
			}
		}
		else {
			Data nameData = program.getListing().getDataAt(address);
			if (nameData == null) {
				Function function = program.getListing().getFunctionAt(address);
				if (function != null && !function.getName().contains("_objc_msgSend")) {
					DataType returnType = function.getReturnType();
					name = returnType.getName();
					return name;
				}
				return null;
			}
			name = getNameFromData(program, input, isClass, isMethod, address, nameData);
		}
		return name;
	}

	private String getIvarNameFromQualifiedName(String qualifiedName) {
		String iVarName = qualifiedName;
		if (qualifiedName == null) {
			return null;
		}
		if (qualifiedName.contains("::")) {
			String[] classParts = qualifiedName.split("::");
			iVarName = classParts[1];
		}
		return iVarName;
	}

	private String getClassNameFromQualifiedName(String qualifiedName) {
		String className = qualifiedName;
		if (qualifiedName.contains("::")) {
			String[] classParts = qualifiedName.split("::");
			className = classParts[1];
		}
		return className;
	}

	private String getNameFromData(Program program, Varnode input, boolean isClass,
			boolean isMethod, Address address, Data nameData) {
		long offset;
		String name;
		if (!nameData.isDefined()) {
			name = getLabelFromUndefinedData(program, address);
		}
		else {
			Object dataValue = nameData.getValue();
			if (dataValue instanceof String) {
				name = (String) dataValue;
				if (!isClass && !isMethod) {
					name = "\"" + name + "\"";
				}
			}
			else if (dataValue instanceof Address) {
				offset = ((Address) dataValue).getOffset();
				if (offset == address.getOffset()) {
					// Self-referencing pointer
					name = null;  
				}
				else {
					name = getNameFromOffset(program, offset, input, isClass, isMethod);
				}
			}
			else {
				name = getClassName(program, address);
				if (name == null) {
					name = getValueAtAddress(program, address);
				}
			}
		}
		return name;
	}

	private String getDataName(Program program, Address address) {
		// Either a pointer to a string, or a protocol structure
		String name = null;
		Data data = program.getListing().getDataAt(address);
		Address nameAddress = null;
		if (data.isPointer()) {
			Object value = data.getValue();
			nameAddress = (Address) value;
		}
		else {
			Data namePointerData = data.getComponent(1);
			if (namePointerData == null) {
				return null;
			}
			Object namePointerValue = namePointerData.getValue();
			nameAddress = (Address) namePointerValue;
		}
		Data nameData = program.getListing().getDataAt(nameAddress);
		Object nameValue = nameData.getValue();
		if (nameValue instanceof String) {
			name = (String) nameValue;
		}
		else if (isCFStringBlock(program.getMemory().getBlock(nameAddress))) {
			name = getCFString(program, nameAddress);
		}
		return name;
	}

	private String getValueAtAddress(Program program, Address address) {
		String value = null;
		Data data = program.getListing().getDataAt(address);
		Object dataValue = data.getValue();
		if (dataValue instanceof Scalar) {
			value = dataValue.toString();
		}
		return value;
	}

	private String getCFString(Program program, Address address) {
		String name = null;
		Data cfStringData = program.getListing().getDataAt(address);
		Data stringPointer = cfStringData.getComponent(2);
		Object pointerValue = stringPointer.getValue();
		Data stringData = program.getListing().getDataAt((Address) pointerValue);
		Object stringValue = stringData.getValue();
		if (stringValue instanceof String) {
			name = (String) stringValue;
		}
		return name;
	}

	private String getIvarName(Program program, Address address) {
		Listing listing = program.getListing();
		Data ivarOffset = listing.getDataAt(address);
		ReferenceIterator references = ivarOffset.getReferenceIteratorTo();

		while (references.hasNext()) {
			Reference reference = references.next();
			Address fromAddress = reference.getFromAddress();
			MemoryBlock block = program.getMemory().getBlock(fromAddress);
			if (!block.getName().equals(ObjectiveC2_Constants.OBJC2_CONST)) {
				continue;
			}
			Data ivarList = listing.getDataContaining(fromAddress);
			int numComponents = ivarList.getNumComponents();
			for (int i = 2; i < numComponents; i++) {
				Data ivarData = ivarList.getComponent(i);
				Address ivarAddress = ivarData.getAddress();
				if (ivarAddress.equals(fromAddress)) {
					Data typeDataPointer = ivarData.getComponent(2);
					Object typeAddress = typeDataPointer.getValue();
					String className = null;
					if (typeAddress instanceof Address) {
						Data typeData = listing.getDataAt((Address) typeAddress);
						className = getClassNameFromIvarData(typeData);
					}
					if (className == null) {
						className = "";
					}

					Data nameDataPointer = ivarData.getComponent(1);
					Object nameAddress = nameDataPointer.getValue();
					if (nameAddress instanceof Address) {
						Data nameData = listing.getDataAt((Address) nameAddress);
						String ivarName = (String) nameData.getValue();
						return className + "::" + ivarName;
					}
				}
			}
		}
		return null;
	}

	private String getClassNameFromIvarData(Data typeData) {
		Object typeValue = typeData.getValue();
		String type = null;
		if (typeValue instanceof String) {
			type = (String) typeValue;
			if (type.startsWith("@\"")) {
				type = type.substring(2, type.length() - 1);
			}
			else if (type.startsWith("_")) {
				type = type.substring(1);
			}
		}
		return type;
	}

	private String getFixupMethodName(Program program, Address address) {
		String name = null;
		Data fixupData = program.getListing().getDataAt(address);
		Data messageNamePointer = fixupData.getComponent(1);
		Object messageNameAddress = messageNamePointer.getValue();
		Data messageNameData = program.getListing().getDataAt((Address) messageNameAddress);
		name = (String) messageNameData.getValue();
		return name;
	}

	private Address getAddressInProgram(Program program, long offset) {
		Address address;
		try {
			address = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
		}
		catch (AddressOutOfBoundsException e) {
			address = null;
		}
		catch (Exception e) {
			address = null;
		}
		return address;
	}

	// Tries to lay down a reference to the function that is actually being
	// called
	private void setReference(Address fromAddress, Program program, String currentClassName,
			String currentMethodName) {
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol classSymbol = symbolTable.getClassSymbol(currentClassName, (Namespace) null);
		if (classSymbol == null) {
			return;
		}
		Namespace namespace = (Namespace) classSymbol.getObject();
		List<Symbol> functionSymbols = symbolTable.getSymbols(currentMethodName, namespace);
		if (functionSymbols.size() == 1) {
			Address toAddress = functionSymbols.get(0).getAddress();
			ReferenceManager referenceManager = program.getReferenceManager();
			Reference reference = referenceManager.addMemoryReference(fromAddress, toAddress,
				RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, 0);
			referenceManager.setPrimary(reference, true);
		}
	}

	private String getLabelFromUndefinedData(Program program, Address address) {
		Symbol[] symbols = program.getSymbolTable().getSymbols(address);
		if (symbols.length == 0) {
			return null;
		}
		for (Symbol symbol : symbols) {
			if (symbol.isPrimary()) {
				String symbolName = symbol.getName();
				if (symbolName.contains("_OBJC_CLASS_$_")) {
					symbolName = symbolName.substring("_OBJC_CLASS_$_".length());
				}
				else if (symbolName.contains("_objc_msgSend")) {
					return null;
				}
				return symbolName;
			}
		}
		return null;
	}

	private String getClassName(Program program, Address toAddress) {
		try {
			boolean is32Bit = false;

			int pointerSize = program.getAddressFactory().getDefaultAddressSpace().getPointerSize();
			if (pointerSize * 8 == 32) {
				is32Bit = true;
			}
			int nameIndex = is32Bit ? 4 : 3;

			Data classData = program.getListing().getDefinedDataAt(toAddress);

			Data classRwPointerData = classData.getComponent(4);
			Address classRwPointerAddress = (Address) classRwPointerData.getValue();

			Memory memory = program.getMemory();
			MemoryBlock block = memory.getBlock(classRwPointerAddress);

			if (!isObjcConstBlock(block)) {
				return null;
			}

			Data classRwData = program.getListing().getDefinedDataAt(classRwPointerAddress);
			Data classNamePointerData = classRwData.getComponent(nameIndex);

			Address classNameAddress = (Address) classNamePointerData.getValue();
			block = memory.getBlock(classNameAddress);

			if (!isCStringBlock(block) && !isClassNameBlock(block)) {
				return null;
			}

			Data classNameData = program.getListing().getDefinedDataAt(classNameAddress);
			String className = (String) classNameData.getValue();
			return className;
		}
		catch (Exception e) {
			// Too bad. Expecting a class but got something else, don't care.
			// System.out.println();
		}
		return null;
	}

	private boolean isFunctionInTextSection(Program program, Function function) {
		if (function == null) {
			return false;
		}
		Address address = function.getEntryPoint();
		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(address);
		if (block.getName().equals("__text")) {
			return true;
		}
		return false;
	}

	private boolean isClass(int index, boolean isStret) {
		boolean isClass;
		if (isStret) {
			isClass = index == 2;
		}
		else {
			isClass = index == 1;
		}
		return isClass;
	}

	private boolean isMessage(int index, boolean isStret) {
		boolean isMessage;
		if (isStret) {
			isMessage = index == 3;
		}
		else {
			isMessage = index == 2;
		}
		return isMessage;
	}

	private boolean isStretCall(Program program, Varnode input, TaskMonitor monitor) {
		Address address = getAddressFromVarnode(program, input, 0, monitor);
		if (address == null) {
			return false;
		}
		Symbol symbol = getSymbolFromVarnode(program, input, monitor);
		return symbol.getName().contains("stret");
	}

	private boolean isSuper2Call(Program program, Varnode input) {
		PcodeOp op = input.getLoneDescend();
		if (op != null && op.getOpcode() == PcodeOp.CALL) {
			Varnode calledAddress = op.getInput(0);
			long offset = calledAddress.getOffset();
			Address address = getAddressInProgram(program, offset);
			if (address == null) {
				return false;
			}
			Function function = program.getListing().getFunctionAt(address);
			if (function.getName().equals("_objc_msgSendSuper2")) {
				return true;
			}
		}
		return false;
	}

	private boolean isObjcNameMatch(Symbol symbol) {
		if (symbol == null) {
			return false;
		}
		String name = symbol.getName();
		return name.startsWith(ObjectiveC1_Constants.OBJC_MSG_SEND) ||
			name.equals(ObjectiveC1_Constants.READ_UNIX2003);
	}

	private boolean isMessageRefsBlock(MemoryBlock block) {
		return block.getName().equals(ObjectiveC2_Constants.OBJC2_MESSAGE_REFS);
	}

	private boolean isClassNameBlock(MemoryBlock block) {
		if (block != null) {
			if (block.getName().equals("__objc_classname")) {
				return true;
			}
		}
		return false;
	}

	private boolean isCStringBlock(MemoryBlock block) {
		if (block != null) {
			if (block.getName().equals(SectionNames.TEXT_CSTRING)) {
				return true;
			}
		}
		return false;
	}

	private boolean isCFStringBlock(MemoryBlock block) {
		if (block != null) {
			if (block.getName().equals("__cfstring")) {
				return true;
			}
		}
		return false;
	}

	private boolean isDataBlock(MemoryBlock block) {
		if (block != null) {
			if (block.getName().equals("__data")) {
				return true;
			}
		}
		return false;
	}

	private boolean isObjcDataBlock(MemoryBlock block) {
		if (block != null) {
			if (block.getName().equals("__objc_data")) {
				return true;
			}
		}
		return false;
	}

	private boolean isIvarBlock(MemoryBlock block) {
		if (block != null) {
			if (block.getName().equals("__objc_ivar")) {
				return true;
			}
		}
		return false;
	}

	private boolean isObjcConstBlock(MemoryBlock block) {
		if (block != null) {
			if (block.getName().equals(ObjectiveC2_Constants.OBJC2_CONST)) {
				return true;
			}
		}
		return false;
	}

	private void setupDecompiler(Program p, DecompInterface decompiler) {
		decompiler.toggleCCode(false);
		decompiler.toggleSyntaxTree(true);
		decompiler.setSimplificationStyle("decompile");
		DecompileOptions options = new DecompileOptions();
		options.grabFromProgram(p);
		options.setEliminateUnreachable(false);
		decompiler.setOptions(options);
	}
}
