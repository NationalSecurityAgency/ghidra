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
package ghidra.file.formats.android.oat;

import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.formats.android.dex.format.*;
import ghidra.file.formats.android.dex.util.DexUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public final class OatDexFileUtilities {

	/**
	 * Table size is determined by the DexHeader's "classDefsIdsSize" field.
	 * @param caller the caller class
	 * @param address the address to perform markup
	 * @param dexHeader the dex header
	 * @param oatHeader the oat header
	 * @param program the program to markup
	 * @param monitor the task monitor for canceling
	 * @param log the message log for logging messages
	 */
	static void markupLookupTableData(Class<?> caller, Address address, DexHeader dexHeader,
			OatHeader oatHeader, Program program, TaskMonitor monitor, MessageLog log) {

		if (dexHeader == null) {
			log.appendMsg(
				caller.getSimpleName() + "- markupLookupTableData() - no dex header, skipping...");
			return;
		}

		monitor.setMessage("OAT - Processing Lookup Table Data...");
		monitor.setMaximum(dexHeader.getClassDefsIdsSize());
		monitor.setProgress(0);

		Symbol oatDataSymbol = OatUtilities.getOatDataSymbol(program);
		DataType dword = new DWordDataType();
		try {
			for (int i = 0; i < dexHeader.getClassDefsIdsSize(); ++i) {
				program.getListing().createData(address, dword);
				int value = program.getMemory().getInt(address);
				Address destinationAddress = oatDataSymbol.getAddress().add(value);

				program.getReferenceManager()
						.addMemoryReference(address, destinationAddress, RefType.DATA,
							SourceType.ANALYSIS, 0);
				address = address.add(dword.getLength());

				ClassDefItem classDefItem = dexHeader.getClassDefs().get(i);
				String className =
					DexUtil.convertTypeIndexToString(dexHeader, classDefItem.getClassIndex());
				Namespace classNameSpace =
					DexUtil.createNameSpaceFromMangledClassName(program, className);

				ByteProvider oatClassHeaderProvider =
					new MemoryByteProvider(program.getMemory(), destinationAddress);
				BinaryReader oatClassHeaderReader =
					new BinaryReader(oatClassHeaderProvider, !program.getLanguage().isBigEndian());

				OatClass oatClassHeader = new OatClass(oatClassHeaderReader,
					classDefItem.getClassDataItem(), oatHeader.getVersion());

				markupMethod(oatHeader, oatClassHeader, dexHeader, classDefItem, program,
					oatDataSymbol, classNameSpace, log, monitor);

				markupClassHeaderData(program, oatDataSymbol, destinationAddress, oatHeader,
					oatClassHeader, log, monitor);

				monitor.setProgress(i);
			}
		}
		catch (Exception e) {
			log.appendException(e);
		}
	}

	static void markupMethod(OatHeader oatHeader, OatClass oatClassHeader, DexHeader dexHeader,
			ClassDefItem classDefItem, Program program, Symbol oatDataSymbol,
			Namespace classNameSpace, MessageLog log, TaskMonitor monitor)
			throws CancelledException, InvalidInputException {

		if (classDefItem.getClassDataOffset() == 0) {
			return;
		}

		SymbolTable symbolTable = program.getSymbolTable();

		List<EncodedMethod> allMethods =
			OatUtilities.getAllMethods(classDefItem.getClassDataItem());

		if (oatClassHeader.getType() == OatClassType.kOatClassAllCompiled.ordinal()) {
			for (int j = 0; j < oatClassHeader.getMethodOffsets().size(); ++j) {
				monitor.checkCanceled();

				OatMethodOffsets methodOffset = oatClassHeader.getMethodOffsets().get(j);
				if (methodOffset.getCodeOffset() == 0) {
					continue;//TODO what does 0 mean?
				}
				Address toAddr = oatDataSymbol.getAddress().add(methodOffset.getCodeOffset());
				toAddr = OatUtilities.adjustForThumbAsNeeded(oatHeader, program, toAddr, log);

				EncodedMethod encodedMethod = allMethods.get(j);

				MethodIDItem methodID = dexHeader.getMethods().get(encodedMethod.getMethodIndex());

				String methodName = DexUtil.convertToString(dexHeader, methodID.getNameIndex());

				symbolTable.createLabel(toAddr, methodName, classNameSpace, SourceType.ANALYSIS);
			}
		}
		else if (oatClassHeader.getType() == OatClassType.kOatClassSomeCompiled.ordinal()) {
			int offset = 0;
			for (int j = 0; j < allMethods.size(); ++j) {
				monitor.checkCanceled();
				if (oatClassHeader.isMethodNative(j)) {
					OatMethodOffsets methodOffset = oatClassHeader.getMethodOffsets().get(offset++);
					if (methodOffset.getCodeOffset() == 0) {
						continue;//TODO what does 0 mean?
					}
					Address toAddr = oatDataSymbol.getAddress().add(methodOffset.getCodeOffset());
					toAddr = OatUtilities.adjustForThumbAsNeeded(oatHeader, program, toAddr, log);

					EncodedMethod encodedMethod = allMethods.get(j);
					MethodIDItem methodID =
						dexHeader.getMethods().get(encodedMethod.getMethodIndex());

					String methodName = DexUtil.convertToString(dexHeader, methodID.getNameIndex());

					symbolTable.createLabel(toAddr, methodName, classNameSpace,
						SourceType.ANALYSIS);
				}
			}
		}
		else if (oatClassHeader.getType() == OatClassType.kOatClassNoneCompiled.ordinal()) {
			// do nothing... all methods are still dalvik
		}
		else if (oatClassHeader.getType() == OatClassType.kOatClassMax.ordinal()) {
			throw new RuntimeException("invalid state!!");
		}
	}

	static void markupClassHeaderData(Program program, Symbol oatDataSymbol, Address address,
			OatHeader oatHeader, OatClass oatClassHeader, MessageLog log, TaskMonitor monitor)
			throws Exception {

		SymbolTable symbolTable = program.getSymbolTable();
		ReferenceManager referenceManager = program.getReferenceManager();
		Listing listing = program.getListing();

		Data oatClassHeaderData = listing.createData(address, oatClassHeader.toDataType());
		for (int j = 0; j < oatClassHeaderData.getNumComponents(); ++j) {
			monitor.checkCanceled();
			Data component = oatClassHeaderData.getComponent(j);
			if (component.getFieldName().startsWith("methodOffsets_")) {
				Data methodOffsetData = component.getComponent(0);
				Scalar scalar = methodOffsetData.getScalar(0);
				if (scalar.getUnsignedValue() == 0) {
					continue;//TODO what does 0 mean?
				}
				Address toAddr = oatDataSymbol.getAddress().add(scalar.getUnsignedValue());
				toAddr = OatUtilities.adjustForThumbAsNeeded(oatHeader, program, toAddr, log);
				referenceManager.addMemoryReference(component.getMinAddress(), toAddr, RefType.READ,
					SourceType.ANALYSIS, 0);
				symbolTable.addExternalEntryPoint(toAddr);

				// Lays down quick header in listing right before the method
				Address quickHeaderAddress = toAddr.subtract(OatQuickMethodHeaderFactory
						.getOatQuickMethodHeaderSize(oatHeader.getVersion()));
				if (listing.isUndefined(quickHeaderAddress, quickHeaderAddress)) {
					ByteProvider oqmhProvider =
						new MemoryByteProvider(program.getMemory(), quickHeaderAddress);
					BinaryReader oqmhReader =
						new BinaryReader(oqmhProvider, !program.getLanguage().isBigEndian());
					OatQuickMethodHeader quickHeader = OatQuickMethodHeaderFactory
							.getOatQuickMethodHeader(oqmhReader, oatHeader.getVersion());
					DataType dataType = quickHeader.toDataType();
					try {
						listing.createData(quickHeaderAddress, dataType);
					}
					catch (CodeUnitInsertionException e) {
						log.appendMsg(e.getMessage());
					}
				}
			}
		}
	}

	static int getNextPowerOfTwo(int value) {
		int highestBit = Integer.highestOneBit(value);
		value = (highestBit == value ? value : highestBit << 1);
		return Math.min(value, 0x100000);//clip at 0x100000 (this will be array size of pointers)
	}

	static void markupOatClassOffsetsPointer(Class<?> caller, Address address, DexHeader dexHeader,
			OatHeader oatHeader, Program program, TaskMonitor monitor, MessageLog log) {

		if (dexHeader == null) {
			log.appendMsg(caller.getSimpleName() +
				" - markupOatClassOffsetsPointer() - no dex header, skipping...");
			return;
		}

		monitor.setMessage("Processing Oat Class Offset Pointers...");

		int size = dexHeader.getClassDefsIdsSize();

		size *= 2;

		size = getNextPowerOfTwo(size);

		DataType dword = new DWordDataType();

		// size *= dword.getLength( );

		ArrayDataType array = new ArrayDataType(dword, size, dword.getLength());
		try {
			program.getListing().createData(address, array);
		}
		catch (Exception e) {
			log.appendException(e);
		}
	}

}
