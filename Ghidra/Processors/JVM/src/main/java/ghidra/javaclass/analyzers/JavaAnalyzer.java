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

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.javaclass.format.*;
import ghidra.javaclass.format.attributes.*;
import ghidra.javaclass.format.constantpool.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.BasicCompilerSpec;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
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
			program.getAddressFactory().getAddressSpace("constantPool").getMinAddress();

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
		labelOperands(program, classFile);
		recordJavaVersionInfo(program, classFile);
		BasicCompilerSpec.enableJavaLanguageDecompilation(program);
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
	 * @param program
	 * @param classFile
	 * @param monitor
	 * @param messageLog
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
				javaVersion = "1.9";
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
			short nameIndex = attribute.getAttributeNameIndex();
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

	private void labelOperands(Program program, ClassFileJava classFile) {
		InstructionIterator instructionIt =
			program.getListing().getInstructions(toAddr(program, 0x10000), true);
		while (instructionIt.hasNext()) {
			Instruction instruction = instructionIt.next();

			Scalar opValue = instruction.getScalar(0);
			if (opValue == null) {
				continue;
			}

			AbstractConstantPoolInfoJava[] constantPool = classFile.getConstantPool();
			int index = (int) (opValue.getValue() & 0xFFFFFFFF);
			String opMarkup = getOperandMarkup(program, constantPool, index);
			instruction.setComment(CodeUnit.EOL_COMMENT, opMarkup);
		}
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

	private String getOperandMarkup(Program program, AbstractConstantPoolInfoJava[] constantPool,
			int index) {
		if (index >= constantPool.length || index < 0) {
			// TODO: < 0 can happen with if<cond> branches backwards.  Goto's should be handled.
			return "";
		}
		AbstractConstantPoolInfoJava constantPoolInfo = constantPool[index];
		String opMarkup = "";
		//
		//			if (monitor.isCancelled()) {
		//				break;
		//			}

		if (constantPoolInfo != null) {
			switch (constantPoolInfo.getTag()) {
				case ConstantPoolTagsJava.CONSTANT_Class: {
					ConstantPoolClassInfo info = (ConstantPoolClassInfo) constantPoolInfo;
					ConstantPoolUtf8Info utf8 =
						(ConstantPoolUtf8Info) constantPool[info.getNameIndex()];
					opMarkup = utf8.getString().replaceAll("/", ".");
					break;
				}
				case ConstantPoolTagsJava.CONSTANT_Double: {
					ConstantPoolDoubleInfo info = (ConstantPoolDoubleInfo) constantPoolInfo;
					double value = info.getValue();
					opMarkup = Double.toString(value);
					break;
				}
				case ConstantPoolTagsJava.CONSTANT_Fieldref: {
					ConstantPoolFieldReferenceInfo info =
						(ConstantPoolFieldReferenceInfo) constantPoolInfo;

					ConstantPoolClassInfo classInfo =
						(ConstantPoolClassInfo) constantPool[info.getClassIndex()];

					ConstantPoolUtf8Info className =
						(ConstantPoolUtf8Info) constantPool[classInfo.getNameIndex()];

					ConstantPoolNameAndTypeInfo nameAndTypeInfo =
						(ConstantPoolNameAndTypeInfo) constantPool[info.getNameAndTypeIndex()];

					ConstantPoolUtf8Info fieldName =
						(ConstantPoolUtf8Info) constantPool[nameAndTypeInfo.getNameIndex()];
					ConstantPoolUtf8Info fieldDescriptor =
						(ConstantPoolUtf8Info) constantPool[nameAndTypeInfo.getDescriptorIndex()];

					opMarkup = className.getString().replaceAll("/", ".") + "." +
						fieldName.getString() + " : " + DescriptorDecoder.getTypeNameFromDescriptor(
							fieldDescriptor.getString(), true, true);
					break;
				}
				case ConstantPoolTagsJava.CONSTANT_Float: {
					ConstantPoolFloatInfo info = (ConstantPoolFloatInfo) constantPoolInfo;
					float value = info.getValue();
					opMarkup = Float.toString(value);
					break;
				}
				case ConstantPoolTagsJava.CONSTANT_Integer: {
					ConstantPoolIntegerInfo info = (ConstantPoolIntegerInfo) constantPoolInfo;
					int value = info.getValue();
					opMarkup = Integer.toString(value);
					break;
				}
				case ConstantPoolTagsJava.CONSTANT_InterfaceMethodref: {
					ConstantPoolInterfaceMethodReferenceInfo info =
						(ConstantPoolInterfaceMethodReferenceInfo) constantPoolInfo;

					ConstantPoolClassInfo classInfo =
						(ConstantPoolClassInfo) constantPool[info.getClassIndex()];

					ConstantPoolUtf8Info className =
						(ConstantPoolUtf8Info) constantPool[classInfo.getNameIndex()];

					ConstantPoolNameAndTypeInfo nameAndTypeInfo =
						(ConstantPoolNameAndTypeInfo) constantPool[info.getNameAndTypeIndex()];

					ConstantPoolUtf8Info interfaceName =
						(ConstantPoolUtf8Info) constantPool[nameAndTypeInfo.getNameIndex()];
					ConstantPoolUtf8Info interfaceDescriptor =
						(ConstantPoolUtf8Info) constantPool[nameAndTypeInfo.getDescriptorIndex()];

					String descriptor = interfaceDescriptor.getString();
					String params = getParameters(descriptor);
					String returnType =
						DescriptorDecoder.getReturnTypeOfMethodDescriptor(descriptor,
							program.getDataTypeManager()).getName();

					opMarkup = className.getString().replaceAll("/", ".") + "." +
						interfaceName.getString() + params + " : " + returnType;
					break;
				}
				case ConstantPoolTagsJava.CONSTANT_InvokeDynamic: {
					ConstantPoolInvokeDynamicInfo info =
						(ConstantPoolInvokeDynamicInfo) constantPoolInfo;

					ConstantPoolNameAndTypeInfo nameAndTypeInfo =
						(ConstantPoolNameAndTypeInfo) constantPool[info.getNameAndTypeIndex()];

					ConstantPoolUtf8Info name =
						(ConstantPoolUtf8Info) constantPool[nameAndTypeInfo.getNameIndex()];

					opMarkup = name.getString();
					break;
				}
				case ConstantPoolTagsJava.CONSTANT_Long: {
					ConstantPoolLongInfo info = (ConstantPoolLongInfo) constantPoolInfo;
					long value = info.getValue();
					opMarkup = Long.toString(value);
					break;
				}
				case ConstantPoolTagsJava.CONSTANT_MethodHandle: {
					ConstantPoolMethodHandleInfo info =
						(ConstantPoolMethodHandleInfo) constantPoolInfo;

					if (info.getReferenceKind() == MethodHandleBytecodeBehaviors.REF_getField ||
						info.getReferenceKind() == MethodHandleBytecodeBehaviors.REF_getStatic ||
						info.getReferenceKind() == MethodHandleBytecodeBehaviors.REF_putField ||
						info.getReferenceKind() == MethodHandleBytecodeBehaviors.REF_putStatic) {

						ConstantPoolFieldReferenceInfo field =
							(ConstantPoolFieldReferenceInfo) constantPool[info.getReferenceIndex()];
						ConstantPoolClassInfo classInfo =
							(ConstantPoolClassInfo) constantPool[field.getClassIndex()];
						ConstantPoolUtf8Info className =
							(ConstantPoolUtf8Info) constantPool[classInfo.getNameIndex()];
						ConstantPoolNameAndTypeInfo nameAndTypeInfo =
							(ConstantPoolNameAndTypeInfo) constantPool[field.getNameAndTypeIndex()];
						ConstantPoolUtf8Info fieldName =
							(ConstantPoolUtf8Info) constantPool[nameAndTypeInfo.getNameIndex()];

						ConstantPoolUtf8Info fieldInfo =
							(ConstantPoolUtf8Info) constantPool[nameAndTypeInfo.getDescriptorIndex()];

						String descriptor = fieldInfo.getString();
						String params = getParameters(descriptor);
						String returnType =
							DescriptorDecoder.getReturnTypeOfMethodDescriptor(descriptor,
								program.getDataTypeManager()).getName();

						opMarkup = className.getString().replaceAll("/", ".") + "." +
							fieldName.getString() + params + " : " + returnType;
					}
					else if (info.getReferenceKind() == MethodHandleBytecodeBehaviors.REF_invokeVirtual ||
						info.getReferenceKind() == MethodHandleBytecodeBehaviors.REF_invokeStatic ||
						info.getReferenceKind() == MethodHandleBytecodeBehaviors.REF_invokeSpecial ||
						info.getReferenceKind() == MethodHandleBytecodeBehaviors.REF_newInvokeSpecial) {

						ConstantPoolMethodReferenceInfo method =
							(ConstantPoolMethodReferenceInfo) constantPool[info.getReferenceIndex()];
						ConstantPoolClassInfo classInfo =
							(ConstantPoolClassInfo) constantPool[method.getClassIndex()];
						ConstantPoolUtf8Info className =
							(ConstantPoolUtf8Info) constantPool[classInfo.getNameIndex()];
						ConstantPoolNameAndTypeInfo nameAndTypeInfo =
							(ConstantPoolNameAndTypeInfo) constantPool[method.getNameAndTypeIndex()];
						ConstantPoolUtf8Info methodName =
							(ConstantPoolUtf8Info) constantPool[nameAndTypeInfo.getNameIndex()];

						ConstantPoolUtf8Info methodInfo =
							(ConstantPoolUtf8Info) constantPool[nameAndTypeInfo.getDescriptorIndex()];

						String descriptor = methodInfo.getString();
						String params = getParameters(descriptor);
						String returnType =
							DescriptorDecoder.getReturnTypeOfMethodDescriptor(descriptor,
								program.getDataTypeManager()).getName();

						opMarkup = className.getString().replaceAll("/", ".") + "." +
							methodName.getString() + params + " : " + returnType;
					}
					else if (info.getReferenceKind() == MethodHandleBytecodeBehaviors.REF_invokeInterface) {

						ConstantPoolInterfaceMethodReferenceInfo interfaceMethod =
							(ConstantPoolInterfaceMethodReferenceInfo) constantPool[info.getReferenceIndex()];
						ConstantPoolClassInfo classInfo =
							(ConstantPoolClassInfo) constantPool[interfaceMethod.getClassIndex()];
						ConstantPoolUtf8Info className =
							(ConstantPoolUtf8Info) constantPool[classInfo.getNameIndex()];
						ConstantPoolNameAndTypeInfo nameAndTypeInfo =
							(ConstantPoolNameAndTypeInfo) constantPool[interfaceMethod.getNameAndTypeIndex()];
						ConstantPoolUtf8Info interfaceMethodName =
							(ConstantPoolUtf8Info) constantPool[nameAndTypeInfo.getNameIndex()];

						ConstantPoolUtf8Info interfaceMethodInfo =
							(ConstantPoolUtf8Info) constantPool[nameAndTypeInfo.getDescriptorIndex()];

						String descriptor = interfaceMethodInfo.getString();
						String params = getParameters(descriptor);
						String returnType =
							DescriptorDecoder.getReturnTypeOfMethodDescriptor(descriptor,
								program.getDataTypeManager()).getName();

						opMarkup = className.getString().replaceAll("/", ".") + "." +
							interfaceMethodName.getString() + params + " : " + returnType;
					}

					break;
				}
				case ConstantPoolTagsJava.CONSTANT_Methodref: {
					ConstantPoolMethodReferenceInfo info =
						(ConstantPoolMethodReferenceInfo) constantPoolInfo;

					ConstantPoolClassInfo classInfo =
						(ConstantPoolClassInfo) constantPool[info.getClassIndex()];

					ConstantPoolUtf8Info className =
						(ConstantPoolUtf8Info) constantPool[classInfo.getNameIndex()];

					ConstantPoolNameAndTypeInfo nameAndTypeInfo =
						(ConstantPoolNameAndTypeInfo) constantPool[info.getNameAndTypeIndex()];

					ConstantPoolUtf8Info methodName =
						(ConstantPoolUtf8Info) constantPool[nameAndTypeInfo.getNameIndex()];
					ConstantPoolUtf8Info methodDescriptor =
						(ConstantPoolUtf8Info) constantPool[nameAndTypeInfo.getDescriptorIndex()];

					ConstantPoolUtf8Info methodInfo =
						(ConstantPoolUtf8Info) constantPool[nameAndTypeInfo.getDescriptorIndex()];

					String descriptor = methodInfo.getString();
					String params = getParameters(descriptor);
					String returnType =
						DescriptorDecoder.getReturnTypeOfMethodDescriptor(descriptor,
							program.getDataTypeManager()).getName();
					if (methodName.getString().equals("<init>")) {
						opMarkup = className.getString() + params;
					}
					else {
						opMarkup = className.getString().replaceAll("/", ".") + "." +
							methodName.getString() + params + " : " + returnType;
					}
					break;
				}
				case ConstantPoolTagsJava.CONSTANT_MethodType: {
					ConstantPoolMethodTypeInfo info = (ConstantPoolMethodTypeInfo) constantPoolInfo;
					ConstantPoolUtf8Info methodType =
						(ConstantPoolUtf8Info) constantPool[info.getDescriptorIndex()];
					opMarkup = methodType.getString();
					break;
				}
				case ConstantPoolTagsJava.CONSTANT_NameAndType: {
					ConstantPoolNameAndTypeInfo info =
						(ConstantPoolNameAndTypeInfo) constantPoolInfo;

					ConstantPoolUtf8Info fieldName =
						(ConstantPoolUtf8Info) constantPool[info.getNameIndex()];
					ConstantPoolUtf8Info fieldDescriptor =
						(ConstantPoolUtf8Info) constantPool[info.getDescriptorIndex()];

					opMarkup = fieldName.getString();
					break;
				}
				case ConstantPoolTagsJava.CONSTANT_String: {
					ConstantPoolStringInfo info = (ConstantPoolStringInfo) constantPoolInfo;
					ConstantPoolUtf8Info utf8 =
						(ConstantPoolUtf8Info) constantPool[info.getStringIndex()];
					opMarkup = utf8.toString();
					break;
				}
				case ConstantPoolTagsJava.CONSTANT_Utf8: {
					ConstantPoolUtf8Info utf8 = (ConstantPoolUtf8Info) constantPoolInfo;
					opMarkup = utf8.getString();
					break;
				}
			}
		}
		return opMarkup;
	}

	private String getParameters(String descriptor) {
		List<String> paramTypeNames = DescriptorDecoder.getTypeNameList(descriptor, true, true);
		StringBuilder sb = new StringBuilder();
		sb.append("(");
		//don't append the last element of the list, which is the return type
		for (int i = 0, max = paramTypeNames.size() - 1; i < max; ++i) {
			sb.append(paramTypeNames.get(i));
			if (i < max - 1) {
				sb.append(", ");
			}
		}
		sb.append(")");
		return sb.toString();
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
	 * @param methodDescriptor - the name of the memory block containing the function's code.  It is assumed that blockName
	 * is the concatenation of the method name and the descriptor
	 * @param constantPool
	 * @throws DuplicateNameException
	 * @throws InvalidInputException
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
	}
}
