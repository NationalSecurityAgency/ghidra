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

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.ObjectUtils;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.parallel.*;
import ghidra.app.services.*;
import ghidra.app.util.bin.format.macho.SectionNames;
import ghidra.app.util.bin.format.objc.ObjcUtils;
import ghidra.app.util.bin.format.objc.objc1.Objc1Constants;
import ghidra.app.util.bin.format.objc.objc2.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.app.util.opinion.MachoProgramBuilder;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;

/**
 * Analyzes {@code _objc_msgSend} information 
 */
public class ObjcMessageAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Objective-C Message Analyzer";
	private static final String DESCRIPTION = "Analyzes _objc_msgSend information.";

	private static final String OPTION_NAME_CALL_OVERRIDE_REFS =
		"Use CALL_OVERRIDE_UNCONDITIONAL references";
	private static final String OPTION_DESCRIPTION_CALL_OVERRIDE_REFS =
		"Applies CALL_OVERRIDE_UNCONDITIONAL references instead of UNCONDITIONAL_CALL references to _objc_msgSend calls. This makes the decompiler look nice.";

	private static final String OPTION_NAME_LOG_MESSAGE_FAILURES = "Log message fix failures";
	private static final String OPTION_DESCRIPTION_LOG_MESSAGE_FAILURES =
		"Log message fix failures during analysis (useful for debugging).";

	private final static String STUB_NAMESPACE = "objc_stub";
	private final int MAX_RECURSION_DEPTH = 10;

	private boolean useCallOverrides = true;
	private boolean logMessageFailures = false;
	private Objc2TypeMetadata typeMetadata;
	private DataTypes dataTypes;
	private Map<String, List<Objc2Class>> classMap;
	private Map<String, Integer> classExternalSymbolOffset = new HashMap<>();

	private record DataTypes(DataType ptr, DataType id, DataType sel, DataType classT,
			DataType messageRef, DataType messageRefPtr, DataType objcSuper,
			DataType objcSuperPtr) {}

	private record Message(String receiver, String selector, Function function, PcodeOpAST op,
			int varargParamIndex, Address addr) {}

	public ObjcMessageAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.DATA_ANALYSIS.before().before());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return Objc2Constants.isObjectiveC2(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		set = set.intersect(program.getMemory().getLoadedAndInitializedAddressSet());

		try {
			if (typeMetadata == null) {
				typeMetadata = new Objc2TypeMetadata(program, monitor, log);
				classMap = typeMetadata.getClasses()
						.stream()
						.filter(e -> e.getData() != null)
						.collect(Collectors.groupingBy(e -> e.getData().getName()));
			}
		}
		catch (IOException e) {
			log.appendMsg("Failed to parse Objective-C type metadata: " + e.getMessage());
			return false;
		}

		if (dataTypes == null) {
			dataTypes = getDataTypes(program, log);
			if (dataTypes == null) {
				return false;
			}
		}

		// Fix __objc_msgSend() function signatures
		if (!fixMsgSendSignatures(program, monitor, log)) {
			return false;
		}

		// Set up a standalone decompiler for later use
		DecompileConfigurer configurer = d -> setupDecompiler(program, d);
		DecompInterface decompiler = new DecompInterface();
		configurer.configure(decompiler);
		decompiler.openProgram(program);

		// Use parallel decompiler to override _objc_msgSend() calls to their proper destinations
		DecompilerCallback<Void> callback =
			new DecompilerCallback<>(program, configurer) {
				@Override
				public Void process(DecompileResults results, TaskMonitor m) throws Exception {
					fixMsgSendCalls(program, results.getHighFunction(), decompiler, log, monitor);
					return null;
				}
			};
		try {
			ParallelDecompiler.decompileFunctions(callback, getFunctionsInTextSection(program, set),
				monitor);
		}
		catch (Exception e) {
			if (e.getCause() instanceof CancelledException ce) {
				throw ce;
			}
			log.appendException(e);
		}
		finally {
			callback.dispose();
			decompiler.closeProgram();
		}
		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_CALL_OVERRIDE_REFS, OptionType.BOOLEAN_TYPE,
			useCallOverrides, null, OPTION_DESCRIPTION_CALL_OVERRIDE_REFS);
		options.registerOption(OPTION_NAME_LOG_MESSAGE_FAILURES, OptionType.BOOLEAN_TYPE,
			logMessageFailures, null, OPTION_DESCRIPTION_LOG_MESSAGE_FAILURES);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		useCallOverrides = options.getBoolean(OPTION_NAME_CALL_OVERRIDE_REFS, useCallOverrides);
		logMessageFailures =
			options.getBoolean(OPTION_NAME_LOG_MESSAGE_FAILURES, logMessageFailures);
	}

	@Override
	public void analysisEnded(Program program) {
		if (typeMetadata != null) {
			typeMetadata.close();
			typeMetadata = null;
		}
	}

	private DataTypes getDataTypes(Program program, MessageLog log) {
		// Get the data types that we'll need to use
		ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
		CategoryPath cat = Objc2Constants.CATEGORY_PATH;
		int ptrSize = program.getDefaultPointerSize();
		DataType ptr = new PointerDataType(null, program.getDefaultPointerSize());
		DataType id = dtm.getDataType(cat, "ID");
		DataType sel = dtm.getDataType(cat, "SEL");
		DataType classT = dtm.getDataType(cat, "class_t");
		DataType messageRef = dtm.getDataType(cat, "message_ref");
		if (messageRef == null) {
			messageRef = id;
		}
		if (ObjectUtils.anyNull(id, sel, messageRef, classT)) {
			log.appendMsg("ERROR: Required Objective-C data type not found in data type manager");
			log.appendMsg("Try adding libobjc.dylib");
			return null;
		}
		DataType messageRefPtr = new PointerDataType(messageRef, ptrSize);
		StructureDataType objcSuper = new StructureDataType(cat, "objc_super", 0);
		objcSuper.add(id, "receiver", null);
		objcSuper.add(new PointerDataType(classT, ptrSize), "super_class", null);
		DataType objcSuperPtr = new PointerDataType(objcSuper, program.getDefaultPointerSize());

		return new DataTypes(ptr, id, sel, classT, messageRef, messageRefPtr, objcSuper,
			objcSuperPtr);
	}

	private boolean fixMsgSendSignatures(Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		for (Function func : program.getFunctionManager().getFunctions(program.getMemory(), true)) {
			monitor.checkCancelled();

			String name = func.getName();
			Namespace global = program.getGlobalNamespace();
			boolean isStub = isObjcMsgSendStub(program, func.getEntryPoint());

			if (!name.startsWith(Objc1Constants.OBJC_MSG_SEND) && !isStub) {
				continue;
			}

			try {
				// Set up the parameter list
				List<Parameter> params = new ArrayList<>();
				switch (name) {
					case "_objc_msgSend":
						params.add(new ParameterImpl("self", dataTypes.id, program));
						params.add(new ParameterImpl("op", dataTypes.sel, program));
						break;
					case "_objc_msgSend_fixup":
						params.add(new ParameterImpl("self", dataTypes.id, program));
						params.add(
							new ParameterImpl("message_ref", dataTypes.messageRefPtr, program));
						break;
					case "_objc_msgSend_stret":
						params.add(new ParameterImpl("stretAddr", dataTypes.ptr, program));
						params.add(new ParameterImpl("self", dataTypes.id, program));
						params.add(new ParameterImpl("op", dataTypes.sel, program));
						break;
					case "_objc_msgSendSuper":
					case "_objc_msgSendSuper2":
						params.add(new ParameterImpl("super", dataTypes.objcSuperPtr, program));
						params.add(new ParameterImpl("op", dataTypes.sel, program));
						break;
					case "_objc_msgSendSuper_fixup":
					case "_objc_msgSendSuper2_fixup":
						params.add(new ParameterImpl("super", dataTypes.objcSuperPtr, program));
						params.add(
							new ParameterImpl("message_ref", dataTypes.messageRefPtr, program));
						break;
					case String s when isStub:
						params.add(new ParameterImpl("self", dataTypes.id, program));
						break;
					default:
						log.appendMsg("Unsupported _objc_msgSend variant: " + name);

				}

				// Set up the return value
				Variable returnVar = new ReturnParameterImpl(dataTypes.id, program);

				// Set up the calling convention
				String cc = CompilerSpec.CALLING_CONVENTION_unknown;
				if (isStub) {
					if (program.getDataTypeManager()
							.getCallingConvention(ObjcUtils.OBJC_MSGSEND_STUBS_CC) != null) {
						cc = ObjcUtils.OBJC_MSGSEND_STUBS_CC;
					}
				}

				// Update the namespace
				func.setParentNamespace(isStub ? getStubsNamespace(program) : global);

				// Update the function name
				String stubPrefix = Objc1Constants.OBJC_MSG_SEND + "$";
				if (isStub && name.startsWith(stubPrefix)) {
					func.setName(name.substring(stubPrefix.length()), SourceType.ANALYSIS);
				}

				// Update the function
				func.updateFunction(cc, returnVar, params,
					FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
				func.setVarArgs(true);
			}
			catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
				log.appendMsg("Failed to fix up function signature function for: " + func);
			}
		}

		return true;
	}

	private List<Message> findMessages(Program program, HighFunction highFunction,
			DecompInterface decompiler, TaskMonitor monitor) throws CancelledException {
		List<Message> messages = new ArrayList<>();
		Function function = highFunction.getFunction();
		for (PcodeOpAST op : CollectionUtils.asIterable(highFunction.getPcodeOps())) {
			monitor.checkCancelled();

			int opcode = op.getOpcode();
			if (opcode != PcodeOp.CALL && opcode != PcodeOp.CALLIND) {
				continue;
			}
			Varnode[] inputs = op.getInputs();
			Address callTarget = getAddressFromVarnode(program, inputs[0], 0, monitor);
			if (!isObjcMsgSendCall(program, inputs[0], callTarget, monitor)) {
				continue;
			}

			int stretParamShift = isStructReturnCall(program, inputs[0], monitor) ? 1 : 0;
			boolean isStub = isObjcMsgSendStub(program, callTarget);
			Varnode receiverParam = inputs[1 + stretParamShift];
			Varnode selectorParam = !isStub ? inputs[2 + stretParamShift] : null;
			String receiver =
				getNameForVarnode(program, function, receiverParam, true, false, 0, 1, monitor);
			String selector = isStub ? processStub(program, callTarget, decompiler, monitor)
					: getNameForVarnode(program, function, selectorParam, false, true, 0, 1,
						monitor);
			if (ObjectUtils.allNotNull(receiver, selector)) {
				messages.add(new Message(ObjcUtils.stripClassPrefix(receiver), selector, function,
					op, 3 + stretParamShift, callTarget));
			}
		}
		return messages;
	}

	private String processStub(Program program, Address stubAddr, DecompInterface decompiler,
			TaskMonitor monitor) throws CancelledException {
		Function func = program.getFunctionManager().getFunctionAt(stubAddr);
		DecompileResults results = decompiler.decompileFunction(func, 5, monitor);
		HighFunction highFunction = results.getHighFunction();
		if (highFunction == null) {
			return null;
		}
		List<Message> messages = findMessages(program, highFunction, decompiler, monitor);
		if (messages.isEmpty()) {
			return null;
		}
		String selector = messages.getFirst().selector;
		if (func.getName().startsWith("FUN_")) {
			try {
				func.setName(selector, SourceType.ANALYSIS);
			}
			catch (InvalidInputException | DuplicateNameException e) {
				// oh well, just cosmetic
			}
		}
		return messages.getFirst().selector;
	}

	private void fixMsgSendCalls(Program program, HighFunction highFunction,
			DecompInterface decompiler, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		if (highFunction == null) {
			return;
		}
		Function function = highFunction.getFunction();
		List<Message> messages = findMessages(program, highFunction, decompiler, monitor);
		for (Message msg : messages) {
			monitor.checkCancelled();
			List<String> parameters = new ArrayList<>();
			Varnode[] inputs = msg.op.getInputs();
			int paramStart = msg.varargParamIndex;
			for (int i = paramStart; i < inputs.length; i++) {
				String paramValue =
					getNameForVarnode(program, function, inputs[i], false, false, 0, 1, monitor);
				parameters.add(getIvarNameFromQualifiedName(paramValue));
			}
			updateExternalBlock(program, msg, log);
			setCommentAndReference(program, msg, parameters, log);
		}
	}
	
	private synchronized void updateExternalBlock(Program program, Message msg, MessageLog log) {
		Memory mem = program.getMemory();
		FunctionManager funcMgr = program.getFunctionManager();
		ExternalManager extMgr = program.getExternalManager();
		SymbolTable symbolTable = program.getSymbolTable();
		String currentClassName = msg.receiver;
		String currentMethodName = msg.selector;

		String objcClassName = ObjcUtils.OBJC_CLASS_SYMBOL_PREFIX + currentClassName;
		List<Symbol> objcClassSymbols = symbolTable.getGlobalSymbols(objcClassName);
		if (objcClassSymbols.isEmpty()) {
			objcClassName = ObjcUtils.OBJC_META_CLASS_SYMBOL_PREFIX + currentClassName;
			if (objcClassSymbols.isEmpty()) {
				if (logMessageFailures) {
					log.appendMsg("Couldn't find class symbol for %s".formatted(msg));
				}
				return;
			}
		}

		if (!mem.getBlock(objcClassSymbols.getFirst().getAddress()).isExternalBlock()) {
			return;
		}

		try {
			Symbol classSymbol = symbolTable.getClassSymbol(currentClassName, null);
			if (classSymbol == null) {
				classSymbol = symbolTable.createClass(null, currentClassName, SourceType.ANALYSIS)
						.getSymbol();
			}
			Namespace classNamespace = (Namespace) classSymbol.getObject();
			if (!symbolTable.getSymbols(currentMethodName, classNamespace).isEmpty()) {
				return;
			}
			int offset = classExternalSymbolOffset.getOrDefault(currentClassName, 1);
			int max = program.getExecutableFormat().equals(MachoLoader.MACH_O_NAME)
					? MachoProgramBuilder.UNDEFINED_SYMBOL_SPACING
					: program.getDefaultPointerSize();
			if (offset >= max) {
				log.appendMsg("No more space reserved in EXTERNAL block to create method: " + msg);
				return;
			}
			Address funcAddr = objcClassSymbols.getFirst().getAddress().add(offset);
			Function func = funcMgr.createFunction(currentMethodName, funcAddr,
				new AddressSet(funcAddr), SourceType.ANALYSIS);
			Symbol externalSymbol = symbolTable.getExternalSymbol(objcClassName);
			if (externalSymbol != null) {
				ExternalLocation loc = extMgr.addExtLocation(externalSymbol.getParentNamespace(),
					currentMethodName, null, SourceType.IMPORTED);
				func.setThunkedFunction(loc.createFunction());
			}
			List<Parameter> params = List.of(new ParameterImpl("self", dataTypes.id, program),
				new ParameterImpl("op", dataTypes.sel, program));
			Variable returnVar = new ReturnParameterImpl(dataTypes.id, program);
			func.updateFunction(CompilerSpec.CALLING_CONVENTION_cdecl, returnVar, params,
				FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
			func.setVarArgs(true);
			func.setParentNamespace(classNamespace);
			classExternalSymbolOffset.put(currentClassName, offset + 1);
		}
		catch (Exception e) {
			log.appendMsg("ERROR: Failed to update EXTERNAL block for %s.%s - %s"
					.formatted(currentClassName, currentMethodName, e.getMessage()));
		}
	}

	private Namespace getStubsNamespace(Program program) {
		SymbolTable symTable = program.getSymbolTable();
		Namespace global = program.getGlobalNamespace();
		Namespace namespace = symTable.getNamespace(STUB_NAMESPACE, global);
		if (namespace == null) {
			try {
				namespace = symTable.createNameSpace(global, STUB_NAMESPACE, SourceType.ANALYSIS);
			}
			catch (DuplicateNameException | InvalidInputException e) {
				return null;
			}
		}
		return namespace;
	}

	private void setCommentAndReference(Program program, Message msg, List<String> parameters,
			MessageLog log) {
		Address objcCallAddress = msg.op.getSeqnum().getTarget();
		objcCallAddress = getAddressInProgram(program, objcCallAddress.getOffset());
		Instruction instruction = program.getListing().getInstructionAt(objcCallAddress);

		String currentClassName = msg.receiver;
		String currentMethodName = msg.selector;
		String fullyQualifiedName = currentClassName;

		// If the target is an instance variable, we want to display the
		// variable name in the comment, but use the class type when
		// creating the reference.
		if (currentClassName.contains("::")) {
			currentClassName = getClassNameFromQualifiedName(fullyQualifiedName);
		}
		setReference(objcCallAddress, program, currentClassName, currentMethodName, log);

		if (instruction == null) {
			return;
		}
		if (instruction.getComment(CommentType.EOL) != null) {
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
		instruction.setComment(CommentType.EOL, builder.toString());
	}

	private boolean isObjcMsgSendCall(Program program, Varnode input, Address callTarget,
			TaskMonitor monitor) throws CancelledException {
		Symbol symbol = getSymbolFromVarnode(program, input, monitor);
		if (symbol == null) {
			return false;
		}
		String name = symbol.getName();
		if (name.startsWith(Objc1Constants.OBJC_MSG_SEND) ||
			name.equals(Objc1Constants.READ_UNIX2003) ||
			name.startsWith("thunk" + Objc1Constants.OBJC_MSG_SEND) ||
			name.startsWith("PTR_" + Objc1Constants.OBJC_MSG_SEND)) {
			return true;
		}
		return isObjcMsgSendStub(program, callTarget);
	}

	private boolean isObjcMsgSendStub(Program program, Address addr) {
		MemoryBlock block = program.getMemory().getBlock(addr);
		return block != null && block.getName().equals(Objc2Constants.OBJC2_STUBS);
	}

	private boolean isObjcAllocCall(Program program, Varnode input, TaskMonitor monitor)
			throws CancelledException {
		Symbol symbol = getSymbolFromVarnode(program, input, monitor);
		if (symbol == null) {
			return false;
		}
		String name = symbol.getName();
		return name.startsWith("_objc_alloc");
	}

	private Address getAddressFromVarnode(Program program, Varnode input, int depth,
			TaskMonitor monitor) throws CancelledException {
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
				monitor.checkCancelled();
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

	private Symbol getSymbolFromVarnode(Program program, Varnode input, TaskMonitor monitor)
			throws CancelledException {
		Address address = getAddressFromVarnode(program, input, 0, monitor);
		if (address == null) {
			return null;
		}
		SymbolTable symbolTable = program.getSymbolTable();
		return symbolTable.getPrimarySymbol(address);
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
			Address addr = getAddressFromVarnode(program, inputs[0], 0, monitor);
			if (isObjcMsgSendCall(program, inputs[0], addr, monitor)) {
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
			else if (isClass && isObjcAllocCall(program, inputs[0], monitor)) {
				int classIndex = 1;
				inputs = new Varnode[] { inputs[classIndex] };
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
						highVar.getDataType();
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
				name = getClassName2(program, address);
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
			if (!block.getName().equals(Objc2Constants.OBJC2_CONST)) {
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

	// Tries to lay down a reference to the function that is actually being called
	private void setReference(Address fromAddress, Program program, String currentClassName,
			String currentMethodName, MessageLog log) {
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol classSymbol = symbolTable.getClassSymbol(currentClassName, (Namespace) null);
		if (classSymbol == null) {
			return;
		}
		Namespace namespace = (Namespace) classSymbol.getObject();
		List<Symbol> functionSymbols = symbolTable.getSymbols(currentMethodName, namespace);
		if (functionSymbols.isEmpty()) {
			// Walk up the superclass chain to see if the method is inherited
			List<Objc2Class> classList = classMap.get(namespace.getName());
			if (classList.size() == 1) {
				Objc2Class superClass = classList.getFirst().getSuperClass();
				if (superClass != null) {
					Objc2ClassRW data = superClass.getData();
					if (data != null) {
						setReference(fromAddress, program, data.getName(), currentMethodName, log);
					}
				}
				return;
			}
		}

		if (functionSymbols.size() == 1) {
			ReferenceManager refMgr = program.getReferenceManager();
			FunctionManager funcMgr = program.getFunctionManager();
			Reference[] origRefs = refMgr.getReferencesFrom(fromAddress);
			Address originalToAddress = origRefs.length > 0
					? origRefs[0].getToAddress()
					: null;
			Address newToAddress = functionSymbols.get(0).getAddress();
			Reference reference = refMgr.addMemoryReference(fromAddress, newToAddress,
				useCallOverrides ? RefType.CALL_OVERRIDE_UNCONDITIONAL : RefType.UNCONDITIONAL_CALL,
				SourceType.ANALYSIS, 0);
			refMgr.setPrimary(reference, true);

			if (originalToAddress != null && isObjcMsgSendStub(program, originalToAddress)) {
				Function func = funcMgr.getFunctionAt(newToAddress);
				if (func != null) {
					try {
						FunctionDefinitionDataType signature =
							new FunctionDefinitionDataType(func, true);
						ParameterDefinition[] args = signature.getArguments();
						if (args.length >= 2 && args[1].getDataType().equals(dataTypes.sel)) {
							signature.setArguments(ArrayUtils.remove(args, 1));
						}
						signature.setCallingConvention(ObjcUtils.OBJC_MSGSEND_STUBS_CC);
						HighFunctionDBUtil.writeOverride(funcMgr.getFunctionContaining(fromAddress),
							fromAddress, signature);
					}
					catch (Exception e) {
						log.appendException(e);
					}
				}
			}
		}
	}

	private String getLabelFromUndefinedData(Program program, Address address) {
		Symbol primary = program.getSymbolTable().getPrimarySymbol(address);
		if (primary == null) {
			return null;
		}
		String symbolName = primary.getName();
		if (symbolName.contains("_OBJC_CLASS_$_")) {
			symbolName = symbolName.substring("_OBJC_CLASS_$_".length());
		}
		else if (symbolName.contains(Objc1Constants.OBJC_MSG_SEND)) {
			return null;
		}
		return symbolName;
	}

	private String getClassName2(Program program, Address toAddress) {
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

	private List<Function> getFunctionsInTextSection(Program program, AddressSetView set) {
		List<Function> ret = new ArrayList<>();
		Memory mem = program.getMemory();
		for (Function function : program.getFunctionManager().getFunctions(set, true)) {
			Address address = function.getEntryPoint();
			MemoryBlock block = mem.getBlock(address);
			if (block != null && block.getName().equals(SectionNames.TEXT)) {
				ret.add(function);
			}
			
		}
		return ret;
	}

	private boolean isStructReturnCall(Program program, Varnode input, TaskMonitor monitor)
			throws CancelledException {
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
			if (function.getName().startsWith("_objc_msgSendSuper2")) {
				return true;
			}
		}
		return false;
	}

	private boolean isMessageRefsBlock(MemoryBlock block) {
		return block.getName().equals(Objc2Constants.OBJC2_MESSAGE_REFS);
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
			if (block.getName().equals(SectionNames.DATA)) {
				return true;
			}
		}
		return false;
	}

	private boolean isObjcDataBlock(MemoryBlock block) {
		if (block != null) {

			if (block.getName().equals(Objc2Constants.OBJC2_DATA)) {
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
			if (block.getName().equals(Objc2Constants.OBJC2_CONST)) {
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
