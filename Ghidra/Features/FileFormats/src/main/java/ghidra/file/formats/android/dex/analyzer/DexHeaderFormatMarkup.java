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
import ghidra.app.util.importer.MessageLog;
import ghidra.file.formats.android.cdex.CDexCodeItem;
import ghidra.file.formats.android.dex.format.*;
import ghidra.file.formats.android.dex.util.DexUtil;
import ghidra.program.database.ProgramCompilerSpec;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class DexHeaderFormatMarkup {

	private DexHeaderFormatAnalyzer analyzer;
	private Program program;
	private Address baseAddress;
	private FlatProgramAPI api;
	private DexHeaderFragmentManager fragmentManager;

	public DexHeaderFormatMarkup(DexHeaderFormatAnalyzer analyzer, Program program,
			Address baseAddress) {
		this.analyzer = analyzer;
		this.program = program;
		this.baseAddress = baseAddress;
		this.api = new FlatProgramAPI(program);
		this.fragmentManager =
			new DexHeaderFragmentManager(program, baseAddress, api, analyzer.isCreateFragments());
	}

	public boolean markup(TaskMonitor monitor, MessageLog log) throws Exception {

		if (api.getDataAt(baseAddress) != null) {
			log.appendMsg("data already exists.");
			return true;
		}

		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(baseAddress);
		block.setRead(true);
		block.setWrite(false);
		block.setExecute(false);

		DexAnalysisState analysisState = DexAnalysisState.getState(program, baseAddress);
		DexHeader header = analysisState.getHeader();
		processHeader(header);

		fragmentManager.createInitialFragments(header, monitor);

		ProgramCompilerSpec.enableJavaLanguageDecompilation(program);
		createNamespaces(header, monitor, log);
		processMap(header, monitor, log);
		processStrings(header, monitor, log);
		processTypes(header, monitor, log);
		processPrototypes(header, monitor, log);
		processFields(header, monitor, log);
		processMethods(header, monitor, log);
		processClassDefs(header, monitor, log);
		createProgramDataTypes(header, monitor, log);

		createMethods(header, monitor, log);

		fragmentManager.createFragments(monitor, log);

		monitor.setMessage("DEX: cleaning up tree");
		analyzer.removeEmptyFragments(program);

		return true;
	}

	private void createNamespaces(DexHeader header, TaskMonitor monitor, MessageLog log)
			throws Exception {

		monitor.setMessage("DEX: creating namespaces");
		monitor.setMaximum(header.getClassDefsIdsSize());
		monitor.setProgress(0);

		// NOTE:
		// MUST CREATE ALL OF THE CLASSES AND NAMESPACES FIRST
		// OTHERWISE GHIDRA CANNOT HANDLE OBFUSCATED PACKAGES NAMES
		// FOR EXAMPLE, "a.a.a.a" and "a.a.a" WHERE THE LAST A IS A METHOD
		for (ClassDefItem item : header.getClassDefs()) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);

			String className = DexUtil.convertTypeIndexToString(header, item.getClassIndex());
			Namespace classNameSpace =
				DexUtil.createNameSpaceFromMangledClassName(program, className);
			if (classNameSpace == null) {
				log.appendMsg("Failed to create namespace: " + className);
			}
		}
	}

	private void createMethods(DexHeader header, TaskMonitor monitor, MessageLog log)
			throws Exception {

		monitor.setMessage("DEX: creating methods");
		monitor.setMaximum(header.getClassDefsIdsSize());
		monitor.setProgress(0);
		for (ClassDefItem item : header.getClassDefs()) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);

			ClassDataItem classDataItem = item.getClassDataItem();
			if (classDataItem == null) {
				continue;
			}

			createMethods(header, item, classDataItem.getDirectMethods(), monitor, log);
			createMethods(header, item, classDataItem.getVirtualMethods(), monitor, log);
		}
	}

	private void createMethods(DexHeader header, ClassDefItem item, List<EncodedMethod> methods,
			TaskMonitor monitor, MessageLog log) throws Exception {

		String className = DexUtil.convertTypeIndexToString(header, item.getClassIndex());
		Namespace classNameSpace = DexUtil.createNameSpaceFromMangledClassName(program, className);
		if (classNameSpace == null) {
			log.appendMsg("No namespace: Skipping methods for " + className);
			return;
		}

		for (int i = 0; i < methods.size(); ++i) {
			monitor.checkCancelled();

			EncodedMethod encodedMethod = methods.get(i);

			MethodIDItem methodID = header.getMethods().get(encodedMethod.getMethodIndex());
			String methodName = DexUtil.convertToString(header, methodID.getNameIndex());

			if ((AccessFlags.ACC_CONSTRUCTOR & encodedMethod.getAccessFlags()) != 0) {
				methodName = classNameSpace.getName();
			}
			CodeItem codeItem = encodedMethod.getCodeItem();

			if (codeItem == null) {//external
//				Address externalAddress = baseAddress.add( DexUtil.EXTERNAL_ADDRESS + ( 4 * methodIndex ) );
//				createMethodSymbol( program, externalAddress, methodName, classNameSpace );
//				createMethodComment( program, externalAddress, header, item, methodID, encodedMethod, codeItem, monitor );
//				createData( program, externalAddress, new PointerDataType( ) );
//				Function method = createFunction( program, externalAddress );
//				method.setCustomVariableStorage( true );
//
//				Address methodIndexAddress = baseAddress.add( DexUtil.LOOKUP_ADDRESS + ( methodIndex * 4 ) );
//				Symbol primarySymbol = program.getSymbolTable().getPrimarySymbol( methodIndexAddress );
//				program.getReferenceManager().addExternalReference( methodIndexAddress, (Namespace) null, primarySymbol.getName( ), null, SourceType.ANALYSIS, 0, RefType.EXTERNAL_REF );
			}
			else {
				Address methodAddress =
					baseAddress.add(DexUtil.METHOD_ADDRESS + encodedMethod.getCodeOffset());
				createMethodSymbol(methodAddress, methodName, classNameSpace, log);
				createMethodComment(methodAddress, header, item, methodID, encodedMethod, codeItem,
					monitor);
				disassembleMethod(header, className, encodedMethod.isStatic(), methodAddress,
					methodID, codeItem, monitor, log);
			}
		}
	}

	private Symbol createMethodSymbol(Address methodAddress, String methodName,
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

	private void createMethodComment(Address methodAddress, DexHeader header, ClassDefItem item,
			MethodIDItem methodID, EncodedMethod encodedMethod, CodeItem codeItem,
			TaskMonitor monitor) throws CancelledException {

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
		api.setPlateComment(methodAddress, commentBuilder.toString());
	}

	private void disassembleMethod(DexHeader header, String className, boolean isStatic,
			Address methodAddress, MethodIDItem methodID, CodeItem codeItem, TaskMonitor monitor,
			MessageLog log) throws CancelledException {

		Language language = program.getLanguage();

		DisassembleCommand dCommand = new DisassembleCommand(methodAddress, null, true);
		dCommand.applyTo(program);

		Function method = api.createFunction(methodAddress, null);
		if (method == null) {//maybe function already created? ...due to compiler optimizations
			if (api.getFunctionAt(methodAddress) != null) {
				log.appendMsg("Duplicate method at " + methodAddress);
				return;
			}
		}
		if (method == null) {
			log.appendMsg("Failed to create method at " + methodAddress);
			return;
		}

		int registerIndex = codeItem.getRegistersSize() - codeItem.getIncomingSize();

		for (int i = 0; i < registerIndex; ++i) {
			DataType localDataType = null;//default to UndefinedDataType of appropriate size
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

		Variable returnVar = null;//default to UndefinedDataType of appropriate size
		List<Variable> paramList = new ArrayList<>();

		int prototypeIndex = Short.toUnsignedInt(methodID.getProtoIndex());
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
					monitor.checkCancelled();
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
			// ignore IndexOutOfBoundsException
		}
		return null;
	}

	private void processHeader(DexHeader header) throws Exception {
		Address headerAddress = baseAddress.add(0x0);
		DataType headerDataType = header.toDataType();
		api.createData(headerAddress, headerDataType);
		fragmentManager.createHeaderFragment(headerAddress, headerDataType);
	}

	private void processClassDefs(DexHeader header, TaskMonitor monitor, MessageLog log)
			throws Exception {

		monitor.setMessage("DEX: processing class definitions");
		monitor.setMaximum(header.getClassDefsIdsSize());
		monitor.setProgress(0);

		Address address = baseAddress.add(header.getClassDefsIdsOffset());

		int index = 0;

		for (ClassDefItem item : header.getClassDefs()) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);

			DataType dataType = item.toDataType();
			api.createData(address, dataType);
			fragmentManager.classesAddressSet.add(address, address.add(dataType.getLength() - 1));
			createClassDefSymbol(header, item, address);

			processClassInterfaces(header, item, monitor);
			processClassAnnotations(header, item, monitor, log);
			processClassDataItem(header, item, monitor, log);
			processClassStaticValues(header, item, monitor);

			api.setPlateComment(address, item.toString(header, index, monitor));

			address = address.add(dataType.getLength());
			++index;
		}
	}

	private void createProgramDataTypes(DexHeader header, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		monitor.setMessage("DEX: creating program datatypes");
		monitor.setMaximum(header.getTypeIdsSize());
		monitor.setProgress(0);
		DataTypeManager dtm = program.getDataTypeManager();
		int curGroup = -1;
		CategoryPath handlePath = null;
		List<TypeIDItem> types = header.getTypes();
		for (int typeID = 0; typeID < header.getTypeIdsSize(); ++typeID) {
			if (typeID > types.size() - 1) {
				continue;//not in scope... CDEX issue
			}
			TypeIDItem item = types.get(typeID);
			monitor.checkCancelled();
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

	private void createClassDefSymbol(DexHeader header, ClassDefItem item, Address address) {
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

	private void processClassStaticValues(DexHeader header, ClassDefItem item, TaskMonitor monitor)
			throws DuplicateNameException, IOException, Exception {

		if (item.getStaticValuesOffset() > 0) {
			EncodedArrayItem staticValues = item.getStaticValues();
			if (staticValues == null) {
				return;
			}
			Address staticAddress =
				baseAddress.add(DexUtil.adjustOffset(item.getStaticValuesOffset(), header));
			DataType staticDataType = staticValues.toDataType();
			api.createData(staticAddress, staticDataType);
			fragmentManager.classStaticValuesAddressSet.add(staticAddress,
				staticAddress.add(staticDataType.getLength() - 1));

			StringBuilder builder = new StringBuilder();
			builder.append("Class: " +
				DexUtil.convertTypeIndexToString(header, item.getClassIndex()) + "\n\n");
			builder.append("Static Values:" + "\n");
			builder.append(
				NumericUtilities.convertBytesToString(staticValues.getArray().getValues(), " "));
			api.setPlateComment(staticAddress, builder.toString());
		}
	}

	private void processClassDataItem(DexHeader header, ClassDefItem item, TaskMonitor monitor,
			MessageLog log) throws DuplicateNameException, IOException, Exception {

		if (item.getClassDataOffset() > 0) {
			ClassDataItem classDataItem = item.getClassDataItem();
			if (classDataItem == null) {
				return;
			}
			Address classDataAddress =
				baseAddress.add(DexUtil.adjustOffset(item.getClassDataOffset(), header));
			DataType classDataDataType = classDataItem.toDataType();
			try {
				api.createData(classDataAddress, classDataDataType);
			}
			catch (Exception e) {
				log.appendMsg("Unable to create class data item at " + classDataAddress);
				return;
			}
			fragmentManager.classDataAddressSet.add(classDataAddress,
				classDataAddress.add(classDataDataType.getLength() - 1));

			StringBuilder builder = new StringBuilder();
			builder.append("Class: " +
				DexUtil.convertTypeIndexToString(header, item.getClassIndex()) + "\n\n");

			builder.append("Static Fields:   " + classDataItem.getStaticFieldsSize() + "\n");
			builder.append("Instance Fields: " + classDataItem.getInstanceFieldsSize() + "\n");
			builder.append("Direct Methods:  " + classDataItem.getDirectMethodsSize() + "\n");
			builder.append("Virtual Methods: " + classDataItem.getVirtualMethodsSize() + "\n");

			processEncodedFields(header, classDataItem.getStaticFields(), monitor);
			processEncodedFields(header, classDataItem.getInstancesFields(), monitor);
			processEncodedMethods(header, item, classDataItem.getDirectMethods(), monitor);
			processEncodedMethods(header, item, classDataItem.getVirtualMethods(), monitor);

			api.setPlateComment(classDataAddress, builder.toString());
		}
	}

	private void processEncodedFields(DexHeader header, List<EncodedField> instanceFields,
			TaskMonitor monitor) throws Exception {

		int index = 0;
		for (int i = 0; i < instanceFields.size(); ++i) {
			monitor.checkCancelled();

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

			Address address = baseAddress.add(field.getFileOffset());
			DataType dataType = field.toDataType();
			api.createData(address, dataType);
			api.setPlateComment(address, builder.toString());
			fragmentManager.encodedFieldsAddressSet.add(address,
				address.add(dataType.getLength() - 1));
		}
	}

	private void processEncodedMethods(DexHeader header, ClassDefItem item,
			List<EncodedMethod> methods, TaskMonitor monitor) throws Exception {

		for (int i = 0; i < methods.size(); ++i) {
			monitor.checkCancelled();

			EncodedMethod method = methods.get(i);

			MethodIDItem methodID = header.getMethods().get(method.getMethodIndex());

			StringBuilder builder = new StringBuilder();
			builder.append(
				"Method Name: " + DexUtil.convertToString(header, methodID.getNameIndex()) + "\n");
			builder.append("Method Offset: 0x" + Long.toHexString(methodID.getFileOffset()) + "\n");
			builder.append("Method Flags:\n");
			builder.append(AccessFlags.toString(method.getAccessFlags()) + "\n");
			builder.append("Code Offset: 0x" + Integer.toHexString(method.getCodeOffset()) + "\n");
			builder.append("\n");

			Address address = baseAddress.add(method.getFileOffset());
			DataType dataType = method.toDataType();
			api.createData(address, dataType);
			api.setPlateComment(address, builder.toString());
			fragmentManager.encodedMethodsAddressSet.add(address,
				address.add(dataType.getLength() - 1));

			processCodeItem(header, item, method, methodID);
		}
	}

	private void processCodeItem(DexHeader header, ClassDefItem item, EncodedMethod method,
			MethodIDItem methodID) throws DuplicateNameException, IOException, Exception {

		if (method.getCodeOffset() > 0) {
			Address codeAddress =
				baseAddress.add(DexUtil.adjustOffset(method.getCodeOffset(), header));

			CodeItem codeItem = method.getCodeItem();

			StringBuilder builder = new StringBuilder();
			builder.append(DexUtil.convertTypeIndexToString(header, item.getClassIndex()) + " " +
				DexUtil.convertToString(header, methodID.getNameIndex()) + "\n");

			if (codeItem != null) {
				builder.append("\n");
				builder.append("Instruction Bytes: 0x" +
					Integer.toHexString(codeItem.getInstructionBytes().length) + "\n");
				builder.append(
					"Registers Size: 0x" + Integer.toHexString(codeItem.getRegistersSize()) + "\n");
				builder.append(
					"Incoming Size: 0x" + Integer.toHexString(codeItem.getIncomingSize()) + "\n");
				builder.append(
					"Outgoing Size: 0x" + Integer.toHexString(codeItem.getOutgoingSize()) + "\n");
				builder.append(
					"Tries Size: 0x" + Integer.toHexString(codeItem.getTriesSize()) + "\n");
			}

			if (codeItem instanceof CDexCodeItem) {
				CDexCodeItem cdexCodeItem = (CDexCodeItem) codeItem;
				builder.append("\n" + (cdexCodeItem.hasPreHeader() ? "PREHEADER" : ""));
			}

			api.setPlateComment(codeAddress, builder.toString());

			if (codeItem != null) {//external
				DataType codeItemDataType = codeItem.toDataType();
				try {
					api.createData(codeAddress, codeItemDataType);

					int codeItemDataTypeLength = codeItemDataType.getLength();

					fragmentManager.codeItemAddressSet.add(codeAddress,
						codeAddress.add(codeItemDataTypeLength - 1));

					Address tempAddress = codeAddress.add(codeItemDataTypeLength);
					tempAddress = processCodeItemTrys(tempAddress, codeItem);
					processCodeItemHandlers(codeItem, tempAddress);
				}
				catch (Exception e) {
					//happens when "padding" member has been removed, so struct won't fit
					//just ignore it
				}

				if (codeItem.getDebugInfoOffset() > 0) {
					Address debugAddress = baseAddress.add(codeItem.getDebugInfoOffset());
					DebugInfoItem debug = codeItem.getDebugInfo();
					DataType debugDataType = debug.toDataType();
					api.createData(debugAddress, debugDataType);
					fragmentManager.debugInfoAddressSet.add(debugAddress,
						debugAddress.add(debugDataType.getLength() - 1));
				}
			}
		}
	}

	private void processCodeItemHandlers(CodeItem codeItem, Address tempAddress)
			throws DuplicateNameException, IOException, Exception {

		EncodedCatchHandlerList handlerList = codeItem.getHandlerList();
		if (handlerList == null) {
			return;
		}

		DataType handlerDataType = handlerList.toDataType();
		api.createData(tempAddress, handlerDataType);
		fragmentManager.handlersAddressSet.add(tempAddress,
			tempAddress.add(handlerDataType.getLength() - 1));
		tempAddress = tempAddress.add(handlerDataType.getLength());

		for (EncodedCatchHandler handler : handlerList.getHandlers()) {
			DataType dataType = handler.toDataType();
			api.createData(tempAddress, dataType);
			fragmentManager.handlersAddressSet.add(tempAddress,
				tempAddress.add(dataType.getLength() - 1));
			tempAddress = tempAddress.add(dataType.getLength());
		}
	}

	private Address processCodeItemTrys(Address codeAddress, CodeItem codeItem)
			throws DuplicateNameException, IOException, Exception {

		Address tempAddress = codeAddress;
		for (TryItem tryItem : codeItem.getTries()) {
			DataType dataType = tryItem.toDataType();
			api.createData(tempAddress, dataType);
			fragmentManager.tryAddressSet.add(tempAddress,
				tempAddress.add(dataType.getLength() - 1));
			tempAddress = tempAddress.add(dataType.getLength());
		}
		return tempAddress;
	}

	private void processClassAnnotations(DexHeader header, ClassDefItem item, TaskMonitor monitor,
			MessageLog log)
			throws DuplicateNameException, IOException, Exception, CancelledException {

		if (item.getAnnotationsOffset() > 0) {
			AnnotationsDirectoryItem annotationsDirectoryItem = item.getAnnotationsDirectoryItem();
			if (annotationsDirectoryItem == null) {
				return;
			}
			Address annotationsAddress =
				baseAddress.add(DexUtil.adjustOffset(item.getAnnotationsOffset(), header));
			DataType annotationsDataType = annotationsDirectoryItem.toDataType();
			api.createData(annotationsAddress, annotationsDataType);
			fragmentManager.annotationsAddressSet.add(annotationsAddress,
				annotationsAddress.add(annotationsDataType.getLength() - 1));

			if (annotationsDirectoryItem.getClassAnnotationsOffset() > 0) {
				Address classAddress = baseAddress.add(DexUtil.adjustOffset(
					annotationsDirectoryItem.getClassAnnotationsOffset(), header));
				AnnotationSetItem setItem = annotationsDirectoryItem.getClassAnnotations();
				DataType setItemDataType = setItem.toDataType();
				api.createData(classAddress, setItemDataType);
				fragmentManager.classAnnotationsAddressSet.add(classAddress,
					classAddress.add(setItemDataType.getLength() - 1));
				processAnnotationSetItem(setItem, monitor, log);
			}
			for (FieldAnnotationsItem field : annotationsDirectoryItem.getFieldAnnotations()) {
				monitor.checkCancelled();
				Address fieldAddress =
					baseAddress.add(DexUtil.adjustOffset(field.getAnnotationsOffset(), header));
				AnnotationSetItem setItem = field.getAnnotationSetItem();
				DataType setItemDataType = setItem.toDataType();
				api.createData(fieldAddress, setItemDataType);
				fragmentManager.annotationFieldsAddressSet.add(fieldAddress,
					fieldAddress.add(setItemDataType.getLength() - 1));
				processAnnotationSetItem(setItem, monitor, log);
			}
			for (MethodAnnotationsItem method : annotationsDirectoryItem.getMethodAnnotations()) {
				monitor.checkCancelled();
				Address methodAddress =
					baseAddress.add(DexUtil.adjustOffset(method.getAnnotationsOffset(), header));
				AnnotationSetItem setItem = method.getAnnotationSetItem();
				DataType setItemDataType = setItem.toDataType();
				api.createData(methodAddress, setItemDataType);
				fragmentManager.annotationMethodsAddressSet.add(methodAddress,
					methodAddress.add(setItemDataType.getLength() - 1));
				processAnnotationSetItem(setItem, monitor, log);
			}
			for (ParameterAnnotationsItem parameter : annotationsDirectoryItem
					.getParameterAnnotations()) {
				monitor.checkCancelled();
				Address parameterAddress =
					baseAddress.add(DexUtil.adjustOffset(parameter.getAnnotationsOffset(), header));
				AnnotationSetReferenceList annotationSetReferenceList =
					parameter.getAnnotationSetReferenceList();
				DataType listDataType = annotationSetReferenceList.toDataType();
				api.createData(parameterAddress, listDataType);
				fragmentManager.annotationParametersAddressSet.add(parameterAddress,
					parameterAddress.add(listDataType.getLength() - 1));

				for (AnnotationSetReferenceItem refItem : annotationSetReferenceList.getItems()) {
					AnnotationItem annotationItem = refItem.getItem();
					if (annotationItem != null) {
						int annotationsItemOffset = refItem.getAnnotationsOffset();
						Address annotationItemAddress =
							baseAddress.add(DexUtil.adjustOffset(annotationsItemOffset, header));
						DataType annotationItemDataType = annotationItem.toDataType();
						api.createData(annotationItemAddress, annotationItemDataType);
						fragmentManager.annotationItemAddressSet.add(annotationItemAddress,
							annotationItemAddress.add(annotationItemDataType.getLength() - 1));
					}
				}
			}
		}
	}

	private void processClassInterfaces(DexHeader header, ClassDefItem item, TaskMonitor monitor)
			throws Exception {

		if (item.getInterfacesOffset() > 0) {
			TypeList interfaces = item.getInterfaces();
			if (interfaces == null) {
				return;
			}
			Address interfaceAddress =
				baseAddress.add(DexUtil.adjustOffset(item.getInterfacesOffset(), header));
			DataType interfaceDataType = interfaces.toDataType();
			api.createData(interfaceAddress, interfaceDataType);
			fragmentManager.interfacesAddressSet.add(interfaceAddress,
				interfaceAddress.add(interfaceDataType.getLength() - 1));

			StringBuilder builder = new StringBuilder();
			builder.append("Class: " +
				DexUtil.convertTypeIndexToString(header, item.getClassIndex()) + "\n\n");
			builder.append("Implements:" + "\n");
			for (TypeItem interfaceItem : interfaces.getItems()) {
				monitor.checkCancelled();
				builder.append("\t" +
					DexUtil.convertTypeIndexToString(header, interfaceItem.getType()) + "\n");
			}
			api.setPlateComment(interfaceAddress, builder.toString());
		}
	}

	private void processAnnotationSetItem(AnnotationSetItem setItem, TaskMonitor monitor,
			MessageLog log) {
		try {
//			for (AnnotationOffsetItem offsetItem : setItem.getItems()) {
//				monitor.checkCancelled();
//				Address aAddress = baseAddress.add( offsetItem.getAnnotationsOffset() );
//				AnnotationItem aItem = offsetItem.getItem();
//				DataType aDataType = aItem.toDataType();
//				api.createData( aAddress, aDataType);
//				fragmentManager.annotationItemAddressSet.add(address, address.add( aDataType.getLength()-1));
//			}
		}
		catch (Exception e) {
			log.appendException(e);
		}
	}

	private void processMethods(DexHeader header, TaskMonitor monitor, MessageLog log)
			throws Exception {

		monitor.setMessage("DEX: processing methods");
		monitor.setMaximum(header.getMethodIdsSize());
		monitor.setProgress(0);
		Address address = baseAddress.add(header.getMethodIdsOffset());
		int methodIndex = 0;
		for (MethodIDItem item : header.getMethods()) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);

			DataType dataType = item.toDataType();
			api.createData(address, dataType);
			fragmentManager.methodsAddressSet.add(address, address.add(dataType.getLength() - 1));

			StringBuilder builder = new StringBuilder();
			builder.append("Method Index: 0x" + Integer.toHexString(methodIndex) + "\n");
			builder.append(
				"Class: " + DexUtil.convertTypeIndexToString(header, item.getClassIndex()) + "\n");
			builder.append("Prototype: " +
				DexUtil.convertPrototypeIndexToString(header, item.getProtoIndex()) + "\n");
			builder.append("Name: " + DexUtil.convertToString(header, item.getNameIndex()) + "\n");

			api.setPlateComment(address, builder.toString());

			++methodIndex;

			address = address.add(dataType.getLength());
		}
	}

	private void processFields(DexHeader header, TaskMonitor monitor, MessageLog log)
			throws Exception {

		monitor.setMessage("DEX: processing fields");
		monitor.setMaximum(header.getFieldIdsSize());
		monitor.setProgress(0);
		Address address = baseAddress.add(header.getFieldIdsOffset());
		int index = 0;
		for (FieldIDItem item : header.getFields()) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			DataType dataType = item.toDataType();
			api.createData(address, dataType);
			fragmentManager.fieldsAddressSet.add(address, address.add(dataType.getLength() - 1));

			StringBuilder builder = new StringBuilder();
			builder.append("Field Index: 0x" + Integer.toHexString(index) + "\n");
			builder.append(
				"Class: " + DexUtil.convertTypeIndexToString(header, item.getClassIndex()) + "\n");
			builder.append(
				"Type: " + DexUtil.convertTypeIndexToString(header, item.getTypeIndex()) + "\n");
			builder.append("Name: " + DexUtil.convertToString(header, item.getNameIndex()) + "\n");
			api.setPlateComment(address, builder.toString());

			++index;

			address = address.add(dataType.getLength());
		}
	}

	private void processPrototypes(DexHeader header, TaskMonitor monitor, MessageLog log)
			throws Exception {

		monitor.setMessage("DEX: processing prototypes");
		monitor.setMaximum(header.getProtoIdsSize());
		monitor.setProgress(0);
		Address address = baseAddress.add(header.getProtoIdsOffset());
		int index = 0;
		for (PrototypesIDItem item : header.getPrototypes()) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			DataType dataType = item.toDataType();
			Data data = api.createData(address, dataType);
			fragmentManager.prototypesAddressSet.add(address,
				address.add(dataType.getLength() - 1));

			StringBuilder builder = new StringBuilder();
			builder.append("Prototype Index: 0x" + Integer.toHexString(index) + "\n");
			builder.append(
				"Shorty: " + DexUtil.convertToString(header, item.getShortyIndex()) + "\n");
			builder.append("Return Type: " +
				DexUtil.convertTypeIndexToString(header, item.getReturnTypeIndex()) + "\n");

			if (item.getParametersOffset() > 0) {
				builder.append("Parameters: " + "\n");
				TypeList parameters = item.getParameters();
				if (parameters != null) {
					for (TypeItem parameter : parameters.getItems()) {
						monitor.checkCancelled();
						builder.append(
							DexUtil.convertTypeIndexToString(header, parameter.getType()) + " ");
					}

					DataType parametersDT = parameters.toDataType();

					Address parametersAddress =
						baseAddress.add(DexUtil.adjustOffset(item.getParametersOffset(), header));

					api.createData(parametersAddress, parametersDT);

					builder.append("\nParameters Address: " + parametersAddress);
					builder.append("\n");

					// add reference to the "parametersOffset" field
					api.createMemoryReference(data.getComponent(2), parametersAddress,
						RefType.DATA);
				}
			}

			api.setPlateComment(address, builder.toString());

			++index;

			address = address.add(dataType.getLength());
		}
	}

	private void processTypes(DexHeader header, TaskMonitor monitor, MessageLog log)
			throws Exception {

		monitor.setMessage("DEX: processing types");
		monitor.setMaximum(header.getTypeIdsSize());
		monitor.setProgress(0);
		Address address = baseAddress.add(header.getTypeIdsOffset());
		int index = 0;
		for (TypeIDItem item : header.getTypes()) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			DataType dataType = item.toDataType();
			api.createData(address, dataType);
			fragmentManager.typesAddressSet.add(address, address.add(dataType.getLength() - 1));

			StringBuilder builder = new StringBuilder();
			builder.append("Type Index: 0x" + Integer.toHexString(index) + "\n");
			builder.append(
				"\t" + "->" + DexUtil.convertToString(header, item.getDescriptorIndex()));
			api.setPlateComment(address, builder.toString());
			++index;

			address = address.add(dataType.getLength());
		}
	}

	private void processMap(DexHeader header, TaskMonitor monitor, MessageLog log)
			throws Exception {

		MapList mapList = header.getMapList();
		if (mapList == null) {
			return;
		}
		monitor.setMessage("DEX: processing map");
		monitor.setMaximum(mapList.getSize());
		monitor.setProgress(0);
		Address mapListAddress =
			baseAddress.add(DexUtil.adjustOffset(header.getMapOffset(), header));
		DataType mapListDataType = mapList.toDataType();
		api.createData(mapListAddress, mapListDataType);
		fragmentManager.mapAddressSet.add(mapListAddress,
			mapListAddress.add(mapListDataType.getLength() - 1));
		StringBuilder builder = new StringBuilder();
		for (MapItem item : header.getMapList().getItems()) {
			monitor.checkCancelled();
			builder.append(MapItemTypeCodes.toString(item.getType()) + "\n");
		}
		api.setPlateComment(mapListAddress, builder.toString());
	}

	private void processStrings(DexHeader header, TaskMonitor monitor, MessageLog log)
			throws Exception {

		monitor.setMessage("DEX: processing strings");
		monitor.setMaximum(header.getStringIdsSize());
		monitor.setProgress(0);
		Address address = baseAddress.add(header.getStringIdsOffset());
		int index = 0;

		for (StringIDItem item : header.getStrings()) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);

			// markup string data items
			Address stringDataAddress =
				baseAddress.add(DexUtil.adjustOffset(item.getStringDataOffset(), header));

			if (!program.getMemory().contains(stringDataAddress)) {
				continue;
			}
			StringDataItem stringDataItem = item.getStringDataItem();

			if (stringDataItem == null) {
				log.appendMsg("Invalid string detected at " + stringDataAddress);
				continue;
			}

			String string = stringDataItem.getString();
			DataType stringDataType = stringDataItem.toDataType();
			api.createData(stringDataAddress, stringDataType);
			api.setPlateComment(stringDataAddress,
				Integer.toHexString(index) + "\n" + string.trim());
			fragmentManager.stringDataAddressSet.add(stringDataAddress,
				stringDataAddress.add(stringDataType.getLength() - 1));

			createStringSymbol(stringDataAddress, string, "strings");

			// markup string Id items
			DataType dataType = item.toDataType();

			Data data = api.createData(address, dataType);
			fragmentManager.stringsDataSet.add(address, address.add(dataType.getLength() - 1));

			api.setPlateComment(address, "String Index: 0x" + Integer.toHexString(index) +
				"\nString: " + string.trim() + "\nString Data Address: " + stringDataAddress);
			createStringSymbol(address, string, "string_data");

			api.createMemoryReference(data, stringDataAddress, RefType.DATA);

			++index;

			address = address.add(dataType.getLength());
		}
	}

	private void createStringSymbol(Address address, String string, String namespace) {
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
