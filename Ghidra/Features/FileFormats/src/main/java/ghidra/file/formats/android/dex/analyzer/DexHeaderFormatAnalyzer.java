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
package ghidra.file.formats.android.dex.analyzer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.file.formats.android.dex.format.*;
import ghidra.file.formats.android.dex.util.DexUtil;
import ghidra.program.database.ProgramCompilerSpec;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class DexHeaderFormatAnalyzer extends FileFormatAnalyzer {

	@Override
	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws Exception {

		Address startAddress = toAddr(program, 0x0);

		if (getDataAt(program, startAddress) != null) {
			log.appendMsg("data already exists.");
			return true;
		}

		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(startAddress);
		block.setRead(true);
		block.setWrite(false);
		block.setExecute(false);

		DexAnalysisState analysisState = DexAnalysisState.getState(program);
		DexHeader header = analysisState.getHeader();
		processHeader(program, header);

		createInitialFragments(program, header, monitor);

		ProgramCompilerSpec.enableJavaLanguageDecompilation(program);
		createNamespaces(program, header, monitor, log);
		processMap(program, header, monitor, log);
		processStrings(program, header, monitor, log);
		processTypes(program, header, monitor, log);
		processPrototypes(program, header, monitor, log);
		processFields(program, header, monitor, log);
		processMethods(program, header, monitor, log);
		processClassDefs(program, header, monitor, log);
		createProgramDataTypes(program, header, monitor, log);

		createMethods(program, header, monitor, log);

		monitor.setMessage("DEX: cleaning up tree");
		removeEmptyFragments(program);

		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		ByteProvider provider =
			new MemoryByteProvider(program.getMemory(), program.getMinAddress());
		return DexConstants.isDexFile(provider);
	}

	@Override
	public AnalyzerType getAnalysisType() {
		return AnalyzerType.BYTE_ANALYZER;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public String getDescription() {
		return "Android DEX Header Format";
	}

	@Override
	public String getName() {
		return "Android DEX Header Format";
	}

	@Override
	public AnalysisPriority getPriority() {
		return new AnalysisPriority(0);
	}

	@Override
	public boolean isPrototype() {
		return false;
	}

	private void createNamespaces(Program program, DexHeader header, TaskMonitor monitor,
			MessageLog log) throws Exception {
		monitor.setMessage("DEX: creating namespaces");
		monitor.setMaximum(header.getClassDefsIdsSize());
		monitor.setProgress(0);

		// NOTE:
		// MUST CREATE ALL OF THE CLASSES AND NAMESPACES FIRST
		// OTHERWISE GHIDRA CANNOT HANDLE OBFUSCATED PACKAGES NAMES
		// FOR EXAMPLE, "a.a.a.a" and "a.a.a" WHERE THE LAST A IS A METHOD
		for (ClassDefItem item : header.getClassDefs()) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);

			String className = DexUtil.convertTypeIndexToString(header, item.getClassIndex());
			Namespace classNameSpace =
				DexUtil.createNameSpaceFromMangledClassName(program, className);
			if (classNameSpace == null) {
				log.appendMsg("Failed to create namespace: " + className);
			}
		}
	}

	private void createMethods(Program program, DexHeader header, TaskMonitor monitor,
			MessageLog log) throws Exception {
		monitor.setMessage("DEX: creating methods");
		monitor.setMaximum(header.getClassDefsIdsSize());
		monitor.setProgress(0);
		for (ClassDefItem item : header.getClassDefs()) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);

			ClassDataItem classDataItem = item.getClassDataItem();
			if (classDataItem == null) {
				continue;
			}

			createMethods(program, header, item, classDataItem.getDirectMethods(), monitor, log);
			createMethods(program, header, item, classDataItem.getVirtualMethods(), monitor, log);
		}
	}

	private void createMethods(Program program, DexHeader header, ClassDefItem item,
			List<EncodedMethod> methods, TaskMonitor monitor, MessageLog log) throws Exception {
		String className = DexUtil.convertTypeIndexToString(header, item.getClassIndex());
		Namespace classNameSpace = DexUtil.createNameSpaceFromMangledClassName(program, className);
		if (classNameSpace == null) {
			log.appendMsg("No namespace: Skipping methods for " + className);
			return;
		}

		for (EncodedMethod encodedMethod : methods) {
			monitor.checkCanceled();

			MethodIDItem methodID = header.getMethods().get(encodedMethod.getMethodIndex());
			String methodName = DexUtil.convertToString(header, methodID.getNameIndex());

			if ((AccessFlags.ACC_CONSTRUCTOR & encodedMethod.getAccessFlags()) != 0) {
				methodName = classNameSpace.getName();
			}
			CodeItem codeItem = encodedMethod.getCodeItem();

			if (codeItem == null) {//external
//				Address externalAddress = toAddr( program, DexUtil.EXTERNAL_ADDRESS + ( 4 * methodIndex ) );
//				createMethodSymbol( program, externalAddress, methodName, classNameSpace );
//				createMethodComment( program, externalAddress, header, item, methodID, encodedMethod, codeItem, monitor );
//				createData( program, externalAddress, new PointerDataType( ) );
//				Function method = createFunction( program, externalAddress );
//				method.setCustomVariableStorage( true );
//
//				Address methodIndexAddress = toAddr( program, DexUtil.LOOKUP_ADDRESS + ( methodIndex * 4 ) );
//				Symbol primarySymbol = program.getSymbolTable().getPrimarySymbol( methodIndexAddress );
//				program.getReferenceManager().addExternalReference( methodIndexAddress, (Namespace) null, primarySymbol.getName( ), null, SourceType.ANALYSIS, 0, RefType.EXTERNAL_REF );
			}
			else {
				Address methodAddress =
					toAddr(program, DexUtil.METHOD_ADDRESS + encodedMethod.getCodeOffset());
				createMethodSymbol(program, methodAddress, methodName, classNameSpace, log);
				createMethodComment(program, methodAddress, header, item, methodID, encodedMethod,
					codeItem, monitor);
				disassembleMethod(program, header, className, encodedMethod.isStatic(),
					methodAddress, methodID, codeItem, monitor, log);
			}
		}
	}

	private Symbol createMethodSymbol(Program program, Address methodAddress, String methodName,
			Namespace classNameSpace, MessageLog log) {
		program.getSymbolTable().addExternalEntryPoint(methodAddress);
		try {
			return program.getSymbolTable()
					.createLabel(methodAddress, methodName, classNameSpace, SourceType.ANALYSIS);
		}
		catch (InvalidInputException e) {
			log.appendException(e);
			return null;
		}
	}

	private void createMethodComment(Program program, Address methodAddress, DexHeader header,
			ClassDefItem item, MethodIDItem methodID, EncodedMethod encodedMethod,
			CodeItem codeItem, TaskMonitor monitor) throws CancelledException {

		String methodSignature =
			DexUtil.convertPrototypeIndexToString(header, methodID.getProtoIndex());
		StringBuilder commentBuilder = new StringBuilder();
		commentBuilder.append(item.toString(header, -1, monitor) + "\n");
		commentBuilder.append("Method Signature: " + methodSignature + "\n");
		commentBuilder.append("Method Access Flags:\n");
		commentBuilder.append(AccessFlags.toString(encodedMethod.getAccessFlags()) + "\n");
		if (codeItem != null) {
			commentBuilder.append("Method Register Size: " + codeItem.getRegistersSize() + "\n");
			commentBuilder.append("Method Incoming Size: " + codeItem.getIncomingSize() + "\n");
			commentBuilder.append("Method Outgoing Size: " + codeItem.getOutgoingSize() + "\n");
			commentBuilder.append("Method Debug Info Offset: 0x" +
				Integer.toHexString(codeItem.getDebugInfoOffset()) + "\n");
		}
		commentBuilder
				.append("Method ID Offset: 0x" + Long.toHexString(methodID.getFileOffset()) + "\n");
		setPlateComment(program, methodAddress, commentBuilder.toString());
	}

	private void disassembleMethod(Program program, DexHeader header, String className,
			boolean isStatic, Address methodAddress, MethodIDItem methodID, CodeItem codeItem,
			TaskMonitor monitor, MessageLog log) throws CancelledException {

		Language language = program.getLanguage();

		DisassembleCommand dCommand = new DisassembleCommand(methodAddress, null, true);
		dCommand.applyTo(program);

		Function method = createFunction(program, methodAddress);
		if (method == null) {
			log.appendMsg("Failed to create method at " + methodAddress);
			return;
		}

		int registerIndex = codeItem.getRegistersSize() - codeItem.getIncomingSize();

		//TODO create local variables in between
		for (int i = 0; i < registerIndex; ++i) {
			DataType localDataType = null;//TODO
			Register localRegister = language.getRegister("v" + i);
			try {
				LocalVariableImpl local =
					new LocalVariableImpl("local_" + i, 0, localDataType, localRegister, program);
				method.addLocalVariable(local, SourceType.ANALYSIS);
			}
			catch (Exception e) {
				log.appendException(e);
			}
		}

		Variable returnVar = null;
		ArrayList<Variable> paramList = new ArrayList<>();

		int prototypeIndex = methodID.getProtoIndex() & 0xffff;
		PrototypesIDItem prototype = header.getPrototypes().get(prototypeIndex);

		try {
			String returnTypeString =
				DexUtil.convertTypeIndexToString(header, prototype.getReturnTypeIndex());
			DataType returnDataType =
				DexUtil.toDataType(program.getDataTypeManager(), returnTypeString);
			returnVar = new ReturnParameterImpl(returnDataType, program);

			if (!isStatic) {
				String classString =
					DexUtil.convertTypeIndexToString(header, methodID.getClassIndex());
				DataType thisDataType =
					DexUtil.toDataType(program.getDataTypeManager(), classString);
				String parameterName = "this";
				Variable param = new ParameterImpl(parameterName, thisDataType, program);
				paramList.add(param);
			}

			TypeList parameters = prototype.getParameters();
			if (parameters != null) {
				for (TypeItem parameterTypeItem : parameters.getItems()) {
					monitor.checkCanceled();
					String parameterTypeString =
						DexUtil.convertTypeIndexToString(header, parameterTypeItem.getType());
					DataType parameterDataType =
						DexUtil.toDataType(program.getDataTypeManager(), parameterTypeString);
					String parameterName =
						getParameterName(header, codeItem, paramList.size() - (isStatic ? 0 : 1));
					if (parameterName == null) {
						parameterName = "p" + paramList.size();
					}
					Variable param = new ParameterImpl(parameterName, parameterDataType, program);
					paramList.add(param);
				}
			}
			method.updateFunction("__stdcall", returnVar, paramList,
				FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
		}
		catch (InvalidInputException ex) {
			log.appendException(ex);
		}
		catch (DuplicateNameException ex) {
			log.appendException(ex);
		}
	}

	private String getParameterName(DexHeader header, CodeItem codeItem, int parameterOrdinal) {
		try {
			DebugInfoItem debugInfo = codeItem.getDebugInfo();
			int[] debugParameterNames = debugInfo.getParameterNames();
			List<StringIDItem> strings = header.getStrings();
			StringIDItem stringIDItem = strings.get(debugParameterNames[parameterOrdinal]);
			StringDataItem stringDataItem = stringIDItem.getStringDataItem();
			return stringDataItem.getString();
		}
		catch (Exception e) {
			// IndexOutOfBoundsException
		}
		return null;
	}

	private void processHeader(Program program, DexHeader header) throws Exception {
		Address headerAddress = toAddr(program, 0x0);
		DataType headerDataType = header.toDataType();
		createData(program, headerAddress, headerDataType);
		createFragment(program, "header", headerAddress,
			headerAddress.add(headerDataType.getLength()));
	}

	private void processClassDefs(Program program, DexHeader header, TaskMonitor monitor,
			MessageLog log) throws Exception {
		monitor.setMessage("DEX: processing class definitions");
		monitor.setMaximum(header.getClassDefsIdsSize());
		monitor.setProgress(0);

		Address address = toAddr(program, header.getClassDefsIdsOffset());

		int index = 0;

		for (ClassDefItem item : header.getClassDefs()) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);

			DataType dataType = item.toDataType();
			createData(program, address, dataType);
			createFragment(program, "classes", address, address.add(dataType.getLength()));
			createClassDefSymbol(program, header, item, address);

			processClassInterfaces(program, header, item, monitor);
			processClassAnnotations(program, item, monitor, log);
			processClassDataItem(program, header, item, monitor);
			processClassStaticValues(program, header, item, monitor);

			setPlateComment(program, address, item.toString(header, index, monitor));

			address = address.add(dataType.getLength());
			++index;
		}
	}

	private void createProgramDataTypes(Program program, DexHeader header, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		monitor.setMessage("DEX: creating program datatypes");
		monitor.setMaximum(header.getTypeIdsSize());
		monitor.setProgress(0);
		DataTypeManager dtm = program.getDataTypeManager();
		int curGroup = -1;
		CategoryPath handlePath = null;
		List<TypeIDItem> types = header.getTypes();
		for (int typeID = 0; typeID < header.getTypeIdsSize(); ++typeID) {
			TypeIDItem item = types.get(typeID);
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			String name = DexUtil.convertToString(header, item.getDescriptorIndex());
			String[] path = DexUtil.convertClassStringToPathArray(DexUtil.CATEGORY_PATH, name);
			if (path == null) {
				continue;
			}

			StringBuilder builder = new StringBuilder();
			for (int i = 0; i < path.length - 1; ++i) {
				builder.append(CategoryPath.DELIMITER_CHAR);
				builder.append(path[i]);
			}
			CategoryPath catPath = new CategoryPath(builder.toString());
			DataType dataType =
				new TypedefDataType(catPath, path[path.length - 1], DWordDataType.dataType);
			dataType = dtm.resolve(dataType, DataTypeConflictHandler.DEFAULT_HANDLER);

			// Create unchanging typedef to each class based on typeID, so we can find class type even if name changes
			if (typeID / 100 != curGroup) {
				curGroup = typeID / 100;
				builder = new StringBuilder();
				builder.append(DexUtil.HANDLE_PATH);
				builder.append("group").append(curGroup);
				handlePath = new CategoryPath(builder.toString());
			}
			DataType handleType = new TypedefDataType(handlePath, "type" + typeID, dataType);
			dtm.resolve(handleType, DataTypeConflictHandler.DEFAULT_HANDLER);
		}
	}

	private void createClassDefSymbol(Program program, DexHeader header, ClassDefItem item,
			Address address) {
		String className = DexUtil.convertTypeIndexToString(header, item.getClassIndex());
		SymbolTable symbolTable = program.getSymbolTable();
		try {
			Namespace nameSpace = DexUtil.createNameSpaceFromMangledClassName(program, className);
			if (nameSpace != null) {
				symbolTable.createLabel(address, DexUtil.CLASSDEF_NAME, nameSpace,
					SourceType.ANALYSIS);
			}
		}
		catch (Exception ex) {
			// Don't worry if we can't laydown this symbol
		}
	}

	private void processClassStaticValues(Program program, DexHeader header, ClassDefItem item,
			TaskMonitor monitor) throws DuplicateNameException, IOException, Exception {
		if (item.getStaticValuesOffset() > 0) {
			EncodedArrayItem staticValues = item.getStaticValues();
			Address staticAddress = toAddr(program, item.getStaticValuesOffset());
			DataType staticDataType = staticValues.toDataType();
			createData(program, staticAddress, staticDataType);
			createFragment(program, "class_static_values", staticAddress,
				staticAddress.add(staticDataType.getLength()));

			StringBuilder builder = new StringBuilder();
			builder.append("Class: " +
				DexUtil.convertTypeIndexToString(header, item.getClassIndex()) + "\n\n");
			builder.append("Static Values:" + "\n");
			for (byte b : staticValues.getArray().getValues()) {
				builder.append(Integer.toHexString(b & 0xff) + " ");
			}
			setPlateComment(program, staticAddress, builder.toString());
		}
	}

	private void processClassDataItem(Program program, DexHeader header, ClassDefItem item,
			TaskMonitor monitor) throws DuplicateNameException, IOException, Exception {
		if (item.getClassDataOffset() > 0) {
			ClassDataItem classDataItem = item.getClassDataItem();
			Address classDataAddress = toAddr(program, item.getClassDataOffset());
			DataType classDataDataType = classDataItem.toDataType();
			createData(program, classDataAddress, classDataDataType);
			createFragment(program, "class_data", classDataAddress,
				classDataAddress.add(classDataDataType.getLength()));

			StringBuilder builder = new StringBuilder();
			builder.append("Class: " +
				DexUtil.convertTypeIndexToString(header, item.getClassIndex()) + "\n\n");

			builder.append("Static Fields:   " + classDataItem.getStaticFieldsSize() + "\n");
			builder.append("Instance Fields: " + classDataItem.getInstanceFieldsSize() + "\n");
			builder.append("Direct Methods:  " + classDataItem.getDirectMethodsSize() + "\n");
			builder.append("Virtual Methods: " + classDataItem.getVirtualMethodsSize() + "\n");

			processEncodedFields(program, header, classDataItem.getStaticFields(), monitor);
			processEncodedFields(program, header, classDataItem.getInstancesFields(), monitor);
			processEncodedMethods(program, header, item, classDataItem.getDirectMethods(), monitor);
			processEncodedMethods(program, header, item, classDataItem.getVirtualMethods(),
				monitor);

			setPlateComment(program, classDataAddress, builder.toString());
		}
	}

	private void processEncodedFields(Program program, DexHeader header,
			List<EncodedField> instanceFields, TaskMonitor monitor) throws Exception {
		int index = 0;
		for (int i = 0; i < instanceFields.size(); ++i) {
			monitor.checkCanceled();

			EncodedField field = instanceFields.get(i);

			int diff = field.getFieldIndexDifference();
			if (i == 0) {
				index = diff;
			}
			else {
				index += diff;
			}

			FieldIDItem fieldID = header.getFields().get(index);

			StringBuilder builder = new StringBuilder();
			builder.append(DexUtil.convertToString(header, fieldID.getNameIndex()) + "\n");
			builder.append(AccessFlags.toString(field.getAccessFlags()) + "\n");
			builder.append("\n");

			Address address = toAddr(program, field.getFileOffset());
			DataType dataType = field.toDataType();
			createData(program, address, dataType);
			setPlateComment(program, address, builder.toString());
			createFragment(program, "encoded_fields", address, address.add(dataType.getLength()));
		}
	}

	private void processEncodedMethods(Program program, DexHeader header, ClassDefItem item,
			List<EncodedMethod> methods, TaskMonitor monitor) throws Exception {
		for (EncodedMethod method : methods) {
			monitor.checkCanceled();

			MethodIDItem methodID = header.getMethods().get(method.getMethodIndex());

			StringBuilder builder = new StringBuilder();
			builder.append(
				"Method Name: " + DexUtil.convertToString(header, methodID.getNameIndex()) + "\n");
			builder.append("Method Offset: 0x" + Long.toHexString(methodID.getFileOffset()) + "\n");
			builder.append("Method Flags:\n");
			builder.append(AccessFlags.toString(method.getAccessFlags()) + "\n");
			builder.append("Code Offset: 0x" + Integer.toHexString(method.getCodeOffset()) + "\n");
			builder.append("\n");

			Address address = toAddr(program, method.getFileOffset());
			DataType dataType = method.toDataType();
			createData(program, address, dataType);
			setPlateComment(program, address, builder.toString());
			createFragment(program, "encoded_methods", address, address.add(dataType.getLength()));

			processCodeItem(program, header, item, method, methodID);
		}
	}

	private void processCodeItem(Program program, DexHeader header, ClassDefItem item,
			EncodedMethod method, MethodIDItem methodID)
			throws DuplicateNameException, IOException, Exception {
		if (method.getCodeOffset() > 0) {
			Address codeAddress = toAddr(program, method.getCodeOffset());

			StringBuilder builder = new StringBuilder();
			builder.append(DexUtil.convertTypeIndexToString(header, item.getClassIndex()) + " " +
				DexUtil.convertToString(header, methodID.getNameIndex()) + "\n");
			setPlateComment(program, codeAddress, builder.toString());

			CodeItem codeItem = method.getCodeItem();
			DataType codeItemDataType = codeItem.toDataType();
			try {
				createData(program, codeAddress, codeItemDataType);

				int codeItemDataTypeLength = codeItemDataType.getLength();

				createFragment(program, "code_item", codeAddress,
					codeAddress.add(codeItemDataTypeLength));
				Address tempAddress = codeAddress.add(codeItemDataTypeLength);
				tempAddress = processCodeItemTrys(program, tempAddress, codeItem);
				processCodeItemHandlers(program, codeItem, tempAddress);
			}
			catch (Exception e) {
				//happens when "padding" member has been removed, so struct won't fit
				//just ignore it
			}

			if (codeItem.getDebugInfoOffset() > 0) {
				Address debugAddress = toAddr(program, codeItem.getDebugInfoOffset());
				DebugInfoItem debug = codeItem.getDebugInfo();
				DataType debugDataType = debug.toDataType();
				createData(program, debugAddress, debugDataType);
				createFragment(program, "debug_info", debugAddress,
					debugAddress.add(debugDataType.getLength()));
			}
		}
	}

	private void processCodeItemHandlers(Program program, CodeItem codeItem, Address tempAddress)
			throws DuplicateNameException, IOException, Exception {
		EncodedCatchHandlerList handlerList = codeItem.getHandlerList();
		if (handlerList == null) {
			return;
		}

		DataType handlerDataType = handlerList.toDataType();
		createData(program, tempAddress, handlerDataType);
		createFragment(program, "handlers", tempAddress,
			tempAddress.add(handlerDataType.getLength()));
		tempAddress = tempAddress.add(handlerDataType.getLength());

		for (EncodedCatchHandler handler : handlerList.getHandlers()) {
			DataType dataType = handler.toDataType();
			createData(program, tempAddress, dataType);
			createFragment(program, "handlers", tempAddress, tempAddress.add(dataType.getLength()));
			tempAddress = tempAddress.add(dataType.getLength());
		}
	}

	private Address processCodeItemTrys(Program program, Address codeAddress, CodeItem codeItem)
			throws DuplicateNameException, IOException, Exception {
		Address tempAddress = codeAddress;
		for (TryItem tryItem : codeItem.getTries()) {
			DataType dataType = tryItem.toDataType();
			createData(program, tempAddress, dataType);
			createFragment(program, "try", tempAddress, tempAddress.add(dataType.getLength()));
			tempAddress = tempAddress.add(dataType.getLength());
		}
		return tempAddress;
	}

	private void processClassAnnotations(Program program, ClassDefItem item, TaskMonitor monitor,
			MessageLog log)
			throws DuplicateNameException, IOException, Exception, CancelledException {
		if (item.getAnnotationsOffset() > 0) {
			AnnotationsDirectoryItem annotationsDirectoryItem = item.getAnnotationsDirectoryItem();
			Address annotationsAddress = toAddr(program, item.getAnnotationsOffset());
			DataType annotationsDataType = annotationsDirectoryItem.toDataType();
			createData(program, annotationsAddress, annotationsDataType);
			createFragment(program, "annotations", annotationsAddress,
				annotationsAddress.add(annotationsDataType.getLength()));

			if (annotationsDirectoryItem.getClassAnnotationsOffset() > 0) {
				Address classAddress =
					toAddr(program, annotationsDirectoryItem.getClassAnnotationsOffset());
				AnnotationSetItem setItem = annotationsDirectoryItem.getClassAnnotations();
				DataType setItemDataType = setItem.toDataType();
				createData(program, classAddress, setItemDataType);
				createFragment(program, "class_annotations", classAddress,
					classAddress.add(setItemDataType.getLength()));
				processAnnotationSetItem(program, setItem, monitor, log);
			}
			for (FieldAnnotation field : annotationsDirectoryItem.getFieldAnnotations()) {
				monitor.checkCanceled();
				Address fieldAddress = toAddr(program, field.getAnnotationsOffset());
				AnnotationSetItem setItem = field.getAnnotationSetItem();
				DataType setItemDataType = setItem.toDataType();
				createData(program, fieldAddress, setItemDataType);
				createFragment(program, "annotation_fields", fieldAddress,
					fieldAddress.add(setItemDataType.getLength()));
				processAnnotationSetItem(program, setItem, monitor, log);
			}
			for (MethodAnnotation method : annotationsDirectoryItem.getMethodAnnotations()) {
				monitor.checkCanceled();
				Address methodAddress = toAddr(program, method.getAnnotationsOffset());
				AnnotationSetItem setItem = method.getAnnotationSetItem();
				DataType setItemDataType = setItem.toDataType();
				createData(program, methodAddress, setItemDataType);
				createFragment(program, "annotation_methods", methodAddress,
					methodAddress.add(setItemDataType.getLength()));
				processAnnotationSetItem(program, setItem, monitor, log);
			}
			for (ParameterAnnotation parameter : annotationsDirectoryItem
					.getParameterAnnotations()) {
				monitor.checkCanceled();
				Address parameterAddress = toAddr(program, parameter.getAnnotationsOffset());
				AnnotationSetReferenceList annotationSetReferenceList =
					parameter.getAnnotationSetReferenceList();
				DataType listDataType = annotationSetReferenceList.toDataType();
				createData(program, parameterAddress, listDataType);
				createFragment(program, "annotation_parameters", parameterAddress,
					parameterAddress.add(listDataType.getLength()));

				for (AnnotationSetReferenceItem refItem : annotationSetReferenceList.getItems()) {
					AnnotationItem annotationItem = refItem.getItem();
					if (annotationItem != null) {
						int annotationsItemOffset = refItem.getAnnotationsOffset();
						Address annotationItemAddress = toAddr(program, annotationsItemOffset);
						DataType annotationItemDataType = annotationItem.toDataType();
						createData(program, annotationItemAddress, annotationItemDataType);
						createFragment(program, "annotation_item", annotationItemAddress,
							annotationItemAddress.add(annotationItemDataType.getLength()));
					}
				}
			}
		}
	}

	private void processClassInterfaces(Program program, DexHeader header, ClassDefItem item,
			TaskMonitor monitor) throws Exception {
		if (item.getInterfacesOffset() > 0) {
			TypeList interfaces = item.getInterfaces();
			Address interfaceAddress = toAddr(program, item.getInterfacesOffset());
			DataType interfaceDataType = interfaces.toDataType();
			createData(program, interfaceAddress, interfaceDataType);
			createFragment(program, "interfaces", interfaceAddress,
				interfaceAddress.add(interfaceDataType.getLength()));

			StringBuilder builder = new StringBuilder();
			builder.append("Class: " +
				DexUtil.convertTypeIndexToString(header, item.getClassIndex()) + "\n\n");
			builder.append("Implements:" + "\n");
			for (TypeItem interfaceItem : interfaces.getItems()) {
				monitor.checkCanceled();
				builder.append("\t" +
					DexUtil.convertTypeIndexToString(header, interfaceItem.getType()) + "\n");
			}
			setPlateComment(program, interfaceAddress, builder.toString());
		}
	}

	private void processAnnotationSetItem(Program program, AnnotationSetItem setItem,
			TaskMonitor monitor, MessageLog log) {
		try {
			for (AnnotationOffsetItem offsetItem : setItem.getItems()) {
				monitor.checkCanceled();
				Address aAddress = toAddr(program, offsetItem.getAnnotationsOffset());
				AnnotationItem aItem = offsetItem.getItem();
				DataType aDataType = aItem.toDataType();
				createData(program, aAddress, aDataType);
				createFragment(program, "annotation_items", aAddress,
					aAddress.add(aDataType.getLength()));
			}
		}
		catch (Exception e) {
			log.appendException(e);
		}
	}

	private void processMethods(Program program, DexHeader header, TaskMonitor monitor,
			MessageLog log) throws Exception {
		monitor.setMessage("DEX: processing methods");
		monitor.setMaximum(header.getMethodIdsSize());
		monitor.setProgress(0);
		Address address = toAddr(program, header.getMethodIdsOffset());
		int methodIndex = 0;
		for (MethodIDItem item : header.getMethods()) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);

			DataType dataType = item.toDataType();
			createData(program, address, dataType);
			createFragment(program, "methods", address, address.add(dataType.getLength()));

			StringBuilder builder = new StringBuilder();
			builder.append("Method Index: 0x" + Integer.toHexString(methodIndex) + "\n");
			builder.append(
				"Class: " + DexUtil.convertTypeIndexToString(header, item.getClassIndex()) + "\n");
			builder.append("Prototype: " +
				DexUtil.convertPrototypeIndexToString(header, item.getProtoIndex()) + "\n");
			builder.append("Name: " + DexUtil.convertToString(header, item.getNameIndex()) + "\n");

			setPlateComment(program, address, builder.toString());

			Address methodIndexAddress = DexUtil.toLookupAddress(program, methodIndex);

			if (program.getMemory().getInt(methodIndexAddress) == -1) {
				// Add placeholder symbol for external functions
				String methodName = DexUtil.convertToString(header, item.getNameIndex());
				String className = DexUtil.convertTypeIndexToString(header, item.getClassIndex());
				Namespace classNameSpace =
					DexUtil.createNameSpaceFromMangledClassName(program, className);
				if (classNameSpace != null) {
					Address externalAddress = DexUtil.toLookupAddress(program, methodIndex);
					Symbol methodSymbol = createMethodSymbol(program, externalAddress, methodName,
						classNameSpace, log);
					if (methodSymbol != null) {
						String externalName = methodSymbol.getName(true);
						program.getReferenceManager()
								.addExternalReference(methodIndexAddress, "EXTERNAL.dex",
									externalName, null, SourceType.ANALYSIS, 0, RefType.DATA);
					}
				}
			}
			createData(program, methodIndexAddress, new PointerDataType());

			++methodIndex;

			address = address.add(dataType.getLength());
		}
	}

	private void processFields(Program program, DexHeader header, TaskMonitor monitor,
			MessageLog log) throws Exception {
		monitor.setMessage("DEX: processing fields");
		monitor.setMaximum(header.getFieldIdsSize());
		monitor.setProgress(0);
		Address address = toAddr(program, header.getFieldIdsOffset());
		int index = 0;
		for (FieldIDItem item : header.getFields()) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			DataType dataType = item.toDataType();
			createData(program, address, dataType);
			createFragment(program, "fields", address, address.add(dataType.getLength()));

			StringBuilder builder = new StringBuilder();
			builder.append("Field Index: 0x" + Integer.toHexString(index) + "\n");
			builder.append(
				"Class: " + DexUtil.convertTypeIndexToString(header, item.getClassIndex()) + "\n");
			builder.append(
				"Type: " + DexUtil.convertTypeIndexToString(header, item.getTypeIndex()) + "\n");
			builder.append("Name: " + DexUtil.convertToString(header, item.getNameIndex()) + "\n");
			setPlateComment(program, address, builder.toString());

			++index;

			address = address.add(dataType.getLength());
		}
	}

	private void processPrototypes(Program program, DexHeader header, TaskMonitor monitor,
			MessageLog log) throws Exception {
		monitor.setMessage("DEX: processing prototypes");
		monitor.setMaximum(header.getProtoIdsSize());
		monitor.setProgress(0);
		Address address = toAddr(program, header.getProtoIdsOffset());
		int index = 0;
		for (PrototypesIDItem item : header.getPrototypes()) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			DataType dataType = item.toDataType();
			createData(program, address, dataType);
			createFragment(program, "prototypes", address, address.add(dataType.getLength()));

			StringBuilder builder = new StringBuilder();
			builder.append("Prototype Index: 0x" + Integer.toHexString(index) + "\n");
			builder.append(
				"Shorty: " + DexUtil.convertToString(header, item.getShortyIndex()) + "\n");
			builder.append("Return Type: " +
				DexUtil.convertTypeIndexToString(header, item.getReturnTypeIndex()) + "\n");

			if (item.getParametersOffset() > 0) {
				builder.append("Parameters: " + "\n");
				TypeList parameters = item.getParameters();
				for (TypeItem parameter : parameters.getItems()) {
					monitor.checkCanceled();
					builder.append(
						DexUtil.convertTypeIndexToString(header, parameter.getType()) + " ");
				}

				DataType parametersDT = parameters.toDataType();
				Address parametersAddress = toAddr(program, item.getParametersOffset());
				createData(program, parametersAddress, parametersDT);
			}

			setPlateComment(program, address, builder.toString());

			++index;

			address = address.add(dataType.getLength());
		}
	}

	private void processTypes(Program program, DexHeader header, TaskMonitor monitor,
			MessageLog log) throws Exception {
		monitor.setMessage("DEX: processing types");
		monitor.setMaximum(header.getTypeIdsSize());
		monitor.setProgress(0);
		Address address = toAddr(program, header.getTypeIdsOffset());
		int index = 0;
		for (TypeIDItem item : header.getTypes()) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			DataType dataType = item.toDataType();
			createData(program, address, dataType);
			createFragment(program, "types", address, address.add(dataType.getLength()));

			StringBuilder builder = new StringBuilder();
			builder.append("Type Index: 0x" + Integer.toHexString(index) + "\n");
			builder.append(
				"\t" + "->" + DexUtil.convertToString(header, item.getDescriptorIndex()));
			setPlateComment(program, address, builder.toString());
			++index;

			address = address.add(dataType.getLength());
		}
	}

	private void processMap(Program program, DexHeader header, TaskMonitor monitor, MessageLog log)
			throws Exception {
		MapList mapList = header.getMapList();
		if (mapList == null) {
			return;
		}
		monitor.setMessage("DEX: processing map");
		monitor.setMaximum(mapList.getSize());
		monitor.setProgress(0);
		Address mapListAddress = toAddr(program, header.getMapOffset());
		DataType mapListDataType = mapList.toDataType();
		createData(program, mapListAddress, mapListDataType);
		createFragment(program, "map", mapListAddress,
			mapListAddress.add(mapListDataType.getLength()));
		StringBuilder builder = new StringBuilder();
		for (MapItem item : header.getMapList().getItems()) {
			monitor.checkCanceled();
			builder.append(MapItemTypeCodes.toString(item.getType()) + "\n");
		}
		setPlateComment(program, mapListAddress, builder.toString());
	}

	private void createInitialFragments(Program program, DexHeader header, TaskMonitor monitor)
			throws Exception {
		monitor.setMessage("DEX: creating fragments");

		if (header.getDataSize() > 0) {
			Address start = toAddr(program, header.getDataOffset());
			Address end = start.add(header.getDataSize());
			createFragment(program, "data", start, end);
		}
	}

	private void processStrings(Program program, DexHeader header, TaskMonitor monitor,
			MessageLog log) throws Exception {
		monitor.setMessage("DEX: processing strings");
		monitor.setMaximum(header.getStringIdsSize());
		monitor.setProgress(0);
		Address address = toAddr(program, header.getStringIdsOffset());
		int index = 0;
		for (StringIDItem item : header.getStrings()) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);

			// markup string data items
			Address stringDataAddress = toAddr(program, item.getStringDataOffset());
			StringDataItem stringDataItem = item.getStringDataItem();

			String string = stringDataItem.getString();

			try {
				DataType stringDataType = stringDataItem.toDataType();
				createData(program, stringDataAddress, stringDataType);
				setPlateComment(program, stringDataAddress,
					Integer.toHexString(index) + "\n\n" + string);
				createFragment(program, "string_data", stringDataAddress,
					stringDataAddress.add(stringDataType.getLength()));

				createStringSymbol(program, stringDataAddress, string, "strings");
			}
			catch (DuplicateNameException e) {
				log.appendException(e); // Report the exception but keep going
			}
			catch (InvalidInputException e) {
				log.appendException(e);
			}

			// markup string Id items
			DataType dataType = item.toDataType();
			try {
				createData(program, address, dataType);
				createFragment(program, "strings", address, address.add(dataType.getLength()));
				setPlateComment(program, address,
					"String Index: 0x" + Integer.toHexString(index) + "\n\n" + string);
				createStringSymbol(program, address, string, "string_data");
			}
			catch (DuplicateNameException e) {
				log.appendException(e); // Report the exception but keep going
			}
			catch (InvalidInputException e) {
				log.appendException(e);
			}
			++index;

			address = address.add(dataType.getLength());
		}
	}

	private void createStringSymbol(Program program, Address address, String string,
			String namespace) {
		SymbolTable symbolTable = program.getSymbolTable();
		if (string.length() > 0) {
			Namespace nameSpace = DexUtil.getOrCreateNameSpace(program, namespace);
			String symbolName = SymbolUtilities.replaceInvalidChars(string, true);
			if (symbolName.length() > SymbolUtilities.MAX_SYMBOL_NAME_LENGTH) {
				symbolName = symbolName.substring(0, SymbolUtilities.MAX_SYMBOL_NAME_LENGTH - 20);
			}
			try {
				symbolTable.createLabel(address, symbolName, nameSpace, SourceType.ANALYSIS);
			}
			catch (InvalidInputException e) {
				// TODO Symbol name matches possible default symbol name: BYTE_0
			}
		}
	}

}
