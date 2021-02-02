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
package ghidra.javaclass.analyzers;

import java.util.*;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.cmd.refs.AssociateSymbolCmd;
import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.JavaLoader;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.options.Options;
import ghidra.javaclass.flags.MethodsInfoAccessFlags;
import ghidra.javaclass.format.*;
import ghidra.javaclass.format.attributes.*;
import ghidra.javaclass.format.constantpool.*;
import ghidra.program.database.ProgramCompilerSpec;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class JavaAnalyzer extends AbstractJavaAnalyzer implements AnalysisWorker {

	private MessageLog log;

	@Override
	public String getName() {
		return "Java Class Analyzer";
	}

	@Override
	public AnalyzerType getAnalysisType() {
		return AnalyzerType.BYTE_ANALYZER;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		try {
			return JavaClassUtil.isClassFile(program);
		}
		catch (Exception e) {
			//ignore 
		}
		return false;
	}

	@Override
	public String getDescription() {
		return "Analyzes Java .class files.";
	}

	@Override
	public AnalysisPriority getPriority() {
		return AnalysisPriority.FORMAT_ANALYSIS;
	}

	@Override
	public boolean canAnalyze(Program program) {
		try {
			return JavaClassUtil.isClassFile(program);
		}
		catch (Exception e) {
			// ignore
		}
		return false;
	}

	@Override
	public boolean isPrototype() {
		return false;
	}

	@Override
	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog messageLog) throws Exception {
		this.log = messageLog;
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
		//changed third param to true so that decompiler switch analysis runs during auto-analysis
		return manager.scheduleWorker(this, null, true, monitor);
	}

	@Override
	public boolean analysisWorkerCallback(Program program, Object workerContext,
			TaskMonitor monitor) throws Exception {

		Address address =
			program.getAddressFactory().getAddressSpace(JavaLoader.CONSTANT_POOL).getMinAddress();

		ByteProvider provider = new MemoryByteProvider(program.getMemory(), address);
		BinaryReader reader = new BinaryReader(provider, !program.getLanguage().isBigEndian());

		ClassFileJava classFile = new ClassFileJava(reader);

		DataType classFileDataType = classFile.toDataType();

		Data cpClassFileData = createData(program, address, classFileDataType);

		if (cpClassFileData == null) {
			log.appendMsg("Unable to create header data.");
		}

		Data constantPoolData = cpClassFileData.getComponent(4);

		markupConstantPoolAndReferences(program, classFile, constantPoolData, monitor);
		createProgramDataTypes(program, classFile, monitor, log);
		markupFields(program, classFile, monitor);
		markupMethods(program, classFile, monitor);
		disassembleMethods(program, classFile, monitor);
		processInstructions(program, constantPoolData, classFile, monitor);
		recordJavaVersionInfo(program, classFile);
		ProgramCompilerSpec.enableJavaLanguageDecompilation(program);
		return true;
	}

	private void disassembleMethods(Program program, ClassFileJava classFile, TaskMonitor monitor)
			throws MemoryAccessException, DuplicateNameException, InvalidInputException {
		MethodInfoJava[] methods = classFile.getMethods();
		for (int i = 0, max = methods.length; i < max; ++i) {
			Address index = JavaClassUtil.toLookupAddress(program, i);
			int offset = program.getMemory().getInt(index);
			Address blockStart =
				program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
			DisassembleCommand cmd = new DisassembleCommand(blockStart, null, true);

			cmd.applyTo(program, monitor);
			Function function = createFunction(program, blockStart);
			if (function == null) {
				continue;
			}
			setFunctionInfo(function, methods[i], classFile, program.getDataTypeManager());
		}
	}

	/**
	 * Create datatypes for all classes mentioned in the constant pool
	 * @param program program file
	 * @param classFile ClassFileJava associated with {@code program} 
	 * @param monitor for canceling analysis
	 * @param messageLog for logging messages
	 */
	private void createProgramDataTypes(Program program, ClassFileJava classFile,
			TaskMonitor monitor, MessageLog messageLog) {
		monitor.setMessage("JVM: processing class definitions");
		//iterate through the constant pool and add all referenced classes and interfaces
		AbstractConstantPoolInfoJava[] constantPool = classFile.getConstantPool();
		DataTypeManager dtm = program.getDataTypeManager();
		for (int i = 0, length = constantPool.length; i < length; ++i) {
			if (constantPool[i] instanceof ConstantPoolClassInfo) {
				addTypeForClassInfoElement(constantPool, i, dtm);
				continue;
			}
			if (constantPool[i] instanceof ConstantPoolNameAndTypeInfo) {
				addTypesForNameAndTypeInfo(constantPool, i, dtm);
				continue;
			}
		}
		return;
	}

	private void addTypesForNameAndTypeInfo(AbstractConstantPoolInfoJava[] constantPool, int i,
			DataTypeManager dtm) {
		ConstantPoolNameAndTypeInfo nameAndType = (ConstantPoolNameAndTypeInfo) constantPool[i];
		ConstantPoolUtf8Info utf8 =
			(ConstantPoolUtf8Info) constantPool[nameAndType.getDescriptorIndex()];
		String descriptor = utf8.getString();
		//method descriptor
		if (descriptor.contains("(")) {
			List<String> classNames = DescriptorDecoder.getTypeNameList(descriptor, true, false);
			for (String className : classNames) {
				if (isPrimitiveType(className)) {
					continue;
				}
				DescriptorDecoder.resolveClassForString(className, dtm, DWordDataType.dataType);
			}
		}
		//field descriptor
		else {
			String className = DescriptorDecoder.getTypeNameFromDescriptor(descriptor, true, false);
			if (isPrimitiveType(className)) {
				return;
			}
			DescriptorDecoder.resolveClassForString(className, dtm, DWordDataType.dataType);

		}
	}

	private boolean isPrimitiveType(String type) {
		switch (type) {
			case "boolean":
			case "byte":
			case "short":
			case "char":
			case "int":
			case "float":
			case "long":
			case "double":
			case "void":
				return true;
			default:
				return false;
		}
	}

	private void addTypeForClassInfoElement(AbstractConstantPoolInfoJava[] constantPool, int index,
			DataTypeManager dtm) {
		ConstantPoolClassInfo classInfo = (ConstantPoolClassInfo) constantPool[index];
		int nameIndex = classInfo.getNameIndex();
		ConstantPoolUtf8Info utf8Info = (ConstantPoolUtf8Info) constantPool[nameIndex];
		DescriptorDecoder.resolveClassForString(utf8Info.getString(), dtm, DWordDataType.dataType);
	}

	private void recordJavaVersionInfo(Program program, ClassFileJava classFile) {
		Options programInfo = program.getOptions(Program.PROGRAM_INFO);
		programInfo.setInt("Major Version", classFile.getMajorVersion());
		programInfo.setInt("Minor Version", classFile.getMinorVersion());
		String javaVersion;
		switch (classFile.getMajorVersion()) {
			case 45:
				javaVersion = "1.1";
				break;
			case 46:
				javaVersion = "1.2";
				break;
			case 47:
				javaVersion = "1.3";
				break;
			case 48:
				javaVersion = "1.4";
				break;
			case 49:
				javaVersion = "1.5";
				break;
			case 50:
				javaVersion = "1.6";
				break;
			case 51:
				javaVersion = "1.7";
				break;
			case 52:
				javaVersion = "1.8";
				break;
			case 53:
				javaVersion = "9";
				break;
			case 54:
				javaVersion = "10";
				break;
			case 55:
				javaVersion = "11";
				break;
			case 56:
				javaVersion = "12";
				break;
			case 57:
				javaVersion = "13";
				break;
			default:
				javaVersion = "Unknown";
				break;
		}
		programInfo.setString("Java Version", javaVersion);
	}

	private void markupConstantPoolAndReferences(Program program, ClassFileJava classFile,
			Data constantPoolData, TaskMonitor monitor) {
		AbstractConstantPoolInfoJava[] constantPool = classFile.getConstantPool();

		Map<Integer, Integer> indexMap = getIndexMap(constantPool);
		for (int i = 1; i < constantPool.length; i++) {
			if (monitor.isCancelled()) {
				return;
			}
			AbstractConstantPoolInfoJava constantPoolInfo = constantPool[i];
			BootstrapMethods[] bootstrapMethods =
				getBootStrapMethodAttribute(classFile, constantPool, indexMap);
			createConstantPoolReference(constantPoolData, constantPoolInfo, bootstrapMethods,
				indexMap, i);
		}
	}

	private BootstrapMethods[] getBootStrapMethodAttribute(ClassFileJava classFile,
			AbstractConstantPoolInfoJava[] constantPool, Map<Integer, Integer> indexMap) {
		AbstractAttributeInfo[] attributes = classFile.getAttributes();
		for (AbstractAttributeInfo attribute : attributes) {
			int nameIndex = attribute.getAttributeNameIndex();
			AbstractConstantPoolInfoJava poolEntry = classFile.getConstantPool()[nameIndex];
			if (poolEntry instanceof ConstantPoolUtf8Info) {
				String name = ((ConstantPoolUtf8Info) poolEntry).getString();
				if (name.equals("BootstrapMethods")) {
					return ((BootstrapMethodsAttribute) attribute).getBootstrapMethods();
				}
			}
		}
		return null;
	}

	private void createConstantPoolReference(Data constantPoolData,
			AbstractConstantPoolInfoJava constantPoolInfo, BootstrapMethods[] bootstrapMethods,
			Map<Integer, Integer> indexMap, int i) {

		if (constantPoolInfo instanceof ConstantPoolClassInfo ||
			constantPoolInfo instanceof ConstantPoolStringInfo ||
			constantPoolInfo instanceof ConstantPoolMethodTypeInfo) {
			Data data = constantPoolData.getComponent(indexMap.get(i));
			Data indexData = data.getComponent(1);
			Object indexValue = indexData.getValue();
			if (indexValue instanceof Scalar) {
				int index = (int) (((Scalar) indexValue).getValue() & 0xFFFF);
				Data referredData = constantPoolData.getComponent(indexMap.get(index));
				indexData.addValueReference(referredData.getAddress(), RefType.DATA);
			}

		}
		else if (constantPoolInfo instanceof ConstantPoolFieldReferenceInfo ||
			constantPoolInfo instanceof ConstantPoolMethodReferenceInfo ||
			constantPoolInfo instanceof ConstantPoolInterfaceMethodReferenceInfo ||
			constantPoolInfo instanceof ConstantPoolNameAndTypeInfo) {
			Data data = constantPoolData.getComponent(indexMap.get(i));
			Data indexData = data.getComponent(1);
			Object indexValue = indexData.getValue();
			if (indexValue instanceof Scalar) {
				int index = (int) (((Scalar) indexValue).getValue() & 0xFFFF);
				Data referredData = constantPoolData.getComponent(indexMap.get(index));
				indexData.addValueReference(referredData.getAddress(), RefType.DATA);
			}
			indexData = data.getComponent(2);
			indexValue = indexData.getValue();
			if (indexValue instanceof Scalar) {
				int index = (int) (((Scalar) indexValue).getValue() & 0xFFFF);
				Data referredData = constantPoolData.getComponent(indexMap.get(index));
				indexData.addValueReference(referredData.getAddress(), RefType.DATA);
			}
		}
		else if (constantPoolInfo instanceof ConstantPoolInvokeDynamicInfo) {
			Data data = constantPoolData.getComponent(indexMap.get(i));
			Data indexData = data.getComponent(1);
			Object indexValue = indexData.getValue();
			if (indexValue instanceof Scalar) {
				int index = (int) (((Scalar) indexValue).getValue() & 0xFFFF);
				BootstrapMethods bootstrapMethod = bootstrapMethods[index];
				index = bootstrapMethod.getBootstrapMethodsReference() & 0xFFFF;
				Data referredData = constantPoolData.getComponent(indexMap.get(index));
				indexData.addValueReference(referredData.getAddress(), RefType.DATA);
			}
			indexData = data.getComponent(2);
			indexValue = indexData.getValue();
			if (indexValue instanceof Scalar) {
				int index = (int) (((Scalar) indexValue).getValue() & 0xFFFF);
				Data referredData = constantPoolData.getComponent(indexMap.get(index));
				indexData.addValueReference(referredData.getAddress(), RefType.DATA);
			}
		}
		else if (constantPoolInfo instanceof ConstantPoolMethodHandleInfo) {
			Data data = constantPoolData.getComponent(indexMap.get(i));
			Data indexData = data.getComponent(2);
			Object indexValue = indexData.getValue();
			if (indexValue instanceof Scalar) {
				int index = (int) (((Scalar) indexValue).getValue() & 0xFFFF);
				Data referredData = constantPoolData.getComponent(indexMap.get(index));
				indexData.addValueReference(referredData.getAddress(), RefType.DATA);
			}
		}
	}

	private Map<Integer, Integer> getIndexMap(AbstractConstantPoolInfoJava[] constantPool) {
		Map<Integer, Integer> indexMap = new HashMap<Integer, Integer>();
		// offset starts at one since JVM constant pool indexing starts with 1...
		int offset = 1;
		for (int i = 1; i < constantPool.length; i++) {
			indexMap.put(i, i - offset);
			if (constantPool[i] instanceof ConstantPoolLongInfo ||
				constantPool[i] instanceof ConstantPoolDoubleInfo) {
				offset++;
			}
		}
		return indexMap;
	}

	private void processInstructions(Program program, Data constantPoolData,
			ClassFileJava classFile, TaskMonitor monitor) throws CancelledException {

		InstructionIterator instructionIt =
			program.getListing().getInstructions(toAddr(program, JavaLoader.CODE_OFFSET), true);
		AbstractConstantPoolInfoJava[] constantPool = classFile.getConstantPool();
		Map<Integer, Integer> indexMap = getIndexMap(constantPool);
		BootstrapMethods[] bootstrapMethods =
			getBootStrapMethodAttribute(classFile, constantPool, indexMap);

		for (Instruction instruction : instructionIt) {
			monitor.checkCanceled();

			if (!hasConstantPoolReference(instruction.getMnemonicString())) {
				continue;
			}

			if (instruction.getMnemonicString().equals("invokedynamic")) {
				addInvokeDynamicComments(program, constantPool, indexMap, bootstrapMethods,
					instruction);
			}

			int index = (int) (instruction.getScalar(0).getValue() & 0xFFFFFFFF);

			Data referredData = constantPoolData.getComponent(indexMap.get(index));
			instruction.addOperandReference(0, referredData.getAddress(), RefType.DATA,
				SourceType.ANALYSIS);
			CompoundCmd cmd = new CompoundCmd("Add constant pool reference");
			String constantPoolLabel = "CPOOL[" + index + "]";
			cmd.add(
				new AddLabelCmd(referredData.getAddress(), constantPoolLabel, SourceType.ANALYSIS));

			Reference ref = instruction.getOperandReferences(0)[0];
			cmd.add(new AssociateSymbolCmd(ref, constantPoolLabel));
			cmd.applyTo(program);
		}
	}

	private void addInvokeDynamicComments(Program program,
			AbstractConstantPoolInfoJava[] constantPool, Map<Integer, Integer> indexMap,
			BootstrapMethods[] bootstrapMethods, Instruction instruction) {
		StringBuffer sb = new StringBuffer("Bootstrap Method: \n");

		Address addr = instruction.getAddress();
		int index = (int) (instruction.getScalar(0).getValue() & 0xFFFFFFFF);
		ConstantPoolInvokeDynamicInfo dynamicInfo =
			(ConstantPoolInvokeDynamicInfo) constantPool[index];
		int bootstrapIndex = dynamicInfo.getBootstrapMethodAttrIndex();
		appendMethodHandleInfo(sb, constantPool,
			bootstrapMethods[bootstrapIndex].getBootstrapMethodsReference());

		sb.append("\n");

		int argNum = 0;
		for (int i = 0; i < bootstrapMethods[bootstrapIndex].getNumberOfBootstrapArguments(); i++) {
			sb.append("  static arg " + argNum++ + ": ");
			appendLoadableInfo(sb, constantPool,
				bootstrapMethods[bootstrapIndex].getBootstrapArgumentsEntry(i));
			if (argNum < bootstrapMethods[bootstrapIndex].getNumberOfBootstrapArguments()) {
				sb.append("\n");
			}
		}
		program.getListing().setComment(addr, CodeUnit.PLATE_COMMENT, sb.toString());
	}

	private void appendMethodHandleInfo(StringBuffer sb,
			AbstractConstantPoolInfoJava[] constantPool, int argIndex) {
		ConstantPoolMethodHandleInfo methodHandle =
			(ConstantPoolMethodHandleInfo) constantPool[argIndex];
		AbstractConstantPoolInfoJava handleRef = constantPool[methodHandle.getReferenceIndex()];

		if (handleRef instanceof ConstantPoolFieldReferenceInfo) {
			ConstantPoolFieldReferenceInfo fieldRef = (ConstantPoolFieldReferenceInfo) handleRef;
			ConstantPoolClassInfo classInfo =
				(ConstantPoolClassInfo) constantPool[fieldRef.getClassIndex()];
			ConstantPoolUtf8Info utf8 =
				(ConstantPoolUtf8Info) constantPool[classInfo.getNameIndex()];
			sb.append(utf8.getString());
			sb.append(".");
			ConstantPoolNameAndTypeInfo ntInfo =
				(ConstantPoolNameAndTypeInfo) constantPool[fieldRef.getNameAndTypeIndex()];
			utf8 = (ConstantPoolUtf8Info) constantPool[ntInfo.getNameIndex()];
			sb.append(utf8.getString());
		}
		if (handleRef instanceof ConstantPoolMethodReferenceInfo) {
			ConstantPoolMethodReferenceInfo methodRef = (ConstantPoolMethodReferenceInfo) handleRef;
			ConstantPoolClassInfo classRef =
				(ConstantPoolClassInfo) constantPool[methodRef.getClassIndex()];
			ConstantPoolUtf8Info utf8 =
				(ConstantPoolUtf8Info) constantPool[classRef.getNameIndex()];
			sb.append(utf8.getString() + ".");
			ConstantPoolNameAndTypeInfo nameAndType =
				(ConstantPoolNameAndTypeInfo) constantPool[methodRef.getNameAndTypeIndex()];
			utf8 = (ConstantPoolUtf8Info) constantPool[nameAndType.getNameIndex()];
			sb.append(utf8.getString());
		}
		if (handleRef instanceof ConstantPoolInterfaceMethodReferenceInfo) {
			ConstantPoolInterfaceMethodReferenceInfo mrInfo =
				(ConstantPoolInterfaceMethodReferenceInfo) handleRef;
			ConstantPoolClassInfo classRef =
				(ConstantPoolClassInfo) constantPool[mrInfo.getClassIndex()];
			ConstantPoolUtf8Info utf8 =
				(ConstantPoolUtf8Info) constantPool[classRef.getNameIndex()];
			sb.append(utf8.getString() + ".");
			ConstantPoolNameAndTypeInfo nameAndType =
				(ConstantPoolNameAndTypeInfo) constantPool[mrInfo.getNameAndTypeIndex()];
			utf8 = (ConstantPoolUtf8Info) constantPool[nameAndType.getNameIndex()];
			sb.append(utf8.getString());
		}
	}

	private void appendLoadableInfo(StringBuffer sb, AbstractConstantPoolInfoJava[] constantPool,
			int argIndex) {
		AbstractConstantPoolInfoJava cpoolInfo = constantPool[argIndex];
		if (cpoolInfo instanceof ConstantPoolIntegerInfo) {
			ConstantPoolIntegerInfo intInfo = (ConstantPoolIntegerInfo) cpoolInfo;
			sb.append(intInfo.getValue());
			return;
		}
		if (cpoolInfo instanceof ConstantPoolFloatInfo) {
			ConstantPoolFloatInfo floatInfo = (ConstantPoolFloatInfo) cpoolInfo;
			sb.append(floatInfo.getValue());
			return;
		}
		if (cpoolInfo instanceof ConstantPoolLongInfo) {
			ConstantPoolLongInfo longInfo = (ConstantPoolLongInfo) cpoolInfo;
			sb.append(longInfo.getValue());
			return;
		}
		if (cpoolInfo instanceof ConstantPoolDoubleInfo) {
			ConstantPoolDoubleInfo doubleInfo = (ConstantPoolDoubleInfo) cpoolInfo;
			sb.append(doubleInfo.getValue());
			return;
		}
		if (cpoolInfo instanceof ConstantPoolClassInfo) {
			ConstantPoolClassInfo classInfo = (ConstantPoolClassInfo) cpoolInfo;
			ConstantPoolUtf8Info className =
				(ConstantPoolUtf8Info) constantPool[classInfo.getNameIndex()];
			sb.append(className.getString());
			return;
		}
		if (cpoolInfo instanceof ConstantPoolStringInfo) {
			ConstantPoolStringInfo stringInfo = (ConstantPoolStringInfo) cpoolInfo;
			ConstantPoolUtf8Info utf8 =
				(ConstantPoolUtf8Info) constantPool[stringInfo.getStringIndex()];
			sb.append("\"");
			sb.append(utf8.getString());
			sb.append("\"");
			return;
		}
		if (cpoolInfo instanceof ConstantPoolMethodHandleInfo) {
			appendMethodHandleInfo(sb, constantPool, argIndex);
			return;
		}
		if (cpoolInfo instanceof ConstantPoolMethodTypeInfo) {
			ConstantPoolMethodTypeInfo mtInfo = (ConstantPoolMethodTypeInfo) cpoolInfo;
			ConstantPoolUtf8Info descriptor =
				(ConstantPoolUtf8Info) constantPool[mtInfo.getDescriptorIndex()];
			sb.append(descriptor.getString());
			return;
		}
		if (cpoolInfo instanceof ConstantPoolDynamicInfo) {
			ConstantPoolDynamicInfo dynamicInfo = (ConstantPoolDynamicInfo) cpoolInfo;
			ConstantPoolNameAndTypeInfo ntInfo =
				(ConstantPoolNameAndTypeInfo) constantPool[dynamicInfo.getNameAndTypeIndex()];
			ConstantPoolUtf8Info name = (ConstantPoolUtf8Info) constantPool[ntInfo.getNameIndex()];
			sb.append(name.getString());
			return;
		}
		Msg.showWarn(this, null, "Unsupported Constant Pool Type", cpoolInfo.getClass().getName());
		return;
	}

	private void markupFields(Program program, ClassFileJava classFile, TaskMonitor monitor) {
		AbstractConstantPoolInfoJava[] constantPool = classFile.getConstantPool();

		FieldInfoJava[] fields = classFile.getFields();
		for (FieldInfoJava fieldInfo : fields) {
			if (monitor.isCancelled()) {
				break;
			}

			ConstantPoolUtf8Info fieldName =
				(ConstantPoolUtf8Info) constantPool[fieldInfo.getNameIndex()];

			ConstantPoolUtf8Info fieldDescriptor =
				(ConstantPoolUtf8Info) constantPool[fieldInfo.getDescriptorIndex()];

			Address fieldAddress = toCpAddr(program, fieldInfo.getOffset());

			String comment = "FieldName = " + fieldName.getString() + "\n" + "FieldDescriptor = " +
				fieldDescriptor.getString() + "\n";

			setEolComment(program, fieldAddress, comment);
		}
	}

	private void markupMethods(Program program, ClassFileJava classFile, TaskMonitor monitor) {
		AbstractConstantPoolInfoJava[] constantPool = classFile.getConstantPool();

		MethodInfoJava[] methods = classFile.getMethods();
		for (MethodInfoJava methodInfo : methods) {
			if (monitor.isCancelled()) {
				break;
			}

			ConstantPoolUtf8Info methodName =
				(ConstantPoolUtf8Info) constantPool[methodInfo.getNameIndex()];

			ConstantPoolUtf8Info methodDescriptor =
				(ConstantPoolUtf8Info) constantPool[methodInfo.getDescriptorIndex()];

			Address methodAddress = toCpAddr(program, methodInfo.getOffset());

			StringBuffer buffer = new StringBuffer();
			buffer.append("MethodName = " + methodName.getString() + "\n");
			buffer.append("MethodDescriptor = " + methodDescriptor.getString() + "\n");

			CodeAttribute codeAttribute = methodInfo.getCodeAttribute();

			if (codeAttribute != null) { //code attribute is null when method is abstract
				LocalVariableTableAttribute localVariableTableAttribute =
					codeAttribute.getLocalVariableTableAttribute();
				if (localVariableTableAttribute != null) {
					LocalVariableJava[] localVariables =
						localVariableTableAttribute.getLocalVariables();
					long localVariableTableOffset = localVariableTableAttribute.getOffset();
					int offsetInTable = 8;
					for (LocalVariableJava localVariable : localVariables) {
						ConstantPoolUtf8Info descriptor =
							(ConstantPoolUtf8Info) constantPool[localVariable.getDescriptorIndex()];
						ConstantPoolUtf8Info name =
							(ConstantPoolUtf8Info) constantPool[localVariable.getNameIndex()];
						String comment = "local: name = " + name + " type = " + descriptor;
						buffer.append("\t" + comment + "\n");
						Address localVariableAddress =
							toCpAddr(program, localVariableTableOffset + offsetInTable);
						setEolComment(program, localVariableAddress, comment);
						offsetInTable += 10;
					}
				}
			}
			setEolComment(program, methodAddress, buffer.toString());
		}
	}

	@Override
	public String getWorkerName() {
		return getName();
	}

	private boolean setEolComment(Program program, Address address, String comment) {
		if (address.getAddressSpace() != program.getAddressFactory().getDefaultAddressSpace()) {
			return false;
		}
		SetCommentCmd cmd = new SetCommentCmd(address, CodeUnit.EOL_COMMENT, comment);
		return cmd.applyTo(program);
	}

	/**
	 * Sets the name, return type, and parameter types of a method using the information in the constant pool.
	 * Also overrides the signatures on all method invocations made within the method body.
	 * @param function - the function (method) 
	 * @param methodInfo information about the method from the constant pool
	 * @param classFile class file containing the method
	 * @param dtManager data type manager for program 
	 * @throws DuplicateNameException if there are duplicate name issues with function or parameter names
	 * @throws InvalidInputException if a function or parameter name is invalid
	 */
	private void setFunctionInfo(Function function, MethodInfoJava methodInfo,
			ClassFileJava classFile, DataTypeManager dtManager)
			throws DuplicateNameException, InvalidInputException {
		AbstractConstantPoolInfoJava[] constantPool = classFile.getConstantPool();
		String functionName =
			((ConstantPoolUtf8Info) constantPool[methodInfo.getNameIndex()]).getString();
		String descriptor =
			((ConstantPoolUtf8Info) constantPool[methodInfo.getDescriptorIndex()]).getString();
		//note: the name of a function in java is not necessarily unique, but the name together
		//with the descriptor is.  Hence we append the type names of the parameters and return to 
		//the function name to avoid an exception being thrown for duplicate names.
		List<String> typeNames = DescriptorDecoder.getTypeNameList(descriptor, true, true);
		StringBuilder sb = new StringBuilder();
		sb.append(functionName);
		for (String name : typeNames) {
			sb.append("_");
			sb.append(name);
		}

		function.setName(sb.toString(), SourceType.ANALYSIS);
		function.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);

		DataType returnType =
			DescriptorDecoder.getReturnTypeOfMethodDescriptor(descriptor, dtManager);
		function.setReturnType(returnType, SourceType.ANALYSIS);

		List<Variable> params = new ArrayList<>();
		//in order to set the parameters for the method, we need to know whether
		//there is an implicit 'this' parameter.  
		if (!methodInfo.isStatic()) {
			int thisIndex = classFile.getThisClass();
			ConstantPoolClassInfo thisClass = (ConstantPoolClassInfo) constantPool[thisIndex];
			int nameIndex = thisClass.getNameIndex();
			ConstantPoolUtf8Info thisNameInfo = (ConstantPoolUtf8Info) constantPool[nameIndex];
			DataType thisType = DescriptorDecoder.resolveClassForString(thisNameInfo.getString(),
				dtManager, DWordDataType.dataType);
			ParameterImpl thisParam = new ParameterImpl("this", thisType, function.getProgram());
			params.add(thisParam);
		}
		List<DataType> explicitParams = DescriptorDecoder.getDataTypeList(descriptor, dtManager);
		for (int i = 0, max = explicitParams.size(); i < max; ++i) {
			ParameterImpl currentParam = new ParameterImpl("param" + Integer.toString(i + 1),
				explicitParams.get(i), function.getProgram());
			params.add(currentParam);
		}
		function.replaceParameters(params, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
			SourceType.ANALYSIS);

		createAccessFlagComments(function, methodInfo, classFile);

	}

	private void createAccessFlagComments(Function function, MethodInfoJava methodInfo,
			ClassFileJava classFile) {

		int flags = methodInfo.getAccessFlags();

		StringBuffer sb = new StringBuffer();

		for (MethodsInfoAccessFlags f : MethodsInfoAccessFlags.values()) {
			if ((flags & f.getValue()) != 0) {
				sb.append("  " + f.name() + "\n");
			}
		}

		if (!StringUtils.isEmpty(sb)) {
			sb.insert(0, "Flags:\n");
		}

		sb.append("\n");
		sb.append(methodInfo.getMethodSignature(classFile));

		Listing listing = function.getProgram().getListing();
		Address entryPoint = function.getEntryPoint();

		listing.setComment(entryPoint, CodeUnit.PLATE_COMMENT, sb.toString());
	}

	private boolean hasConstantPoolReference(String mnemonic) {
		switch (mnemonic) {
			case ("anewarray"):
			case ("checkcast"):
			case ("getfield"):
			case ("getstatic"):
			case ("instanceof"):
			case ("invokedynamic"):
			case ("invokeinterface"):
			case ("invokespecial"):
			case ("invokestatic"):
			case ("invokevirtual"):
			case ("multianewarray"):
			case ("ldc"):
			case ("ldc_w"):
			case ("ldc2_w"):
			case ("new"):
			case ("putfield"):
			case ("putstatic"):
				return true;
			default:
				return false;
		}
	}

}
