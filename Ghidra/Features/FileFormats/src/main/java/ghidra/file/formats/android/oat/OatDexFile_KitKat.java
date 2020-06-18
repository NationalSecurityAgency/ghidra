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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.formats.android.dex.DexHeaderFactory;
import ghidra.file.formats.android.dex.format.*;
import ghidra.file.formats.android.dex.util.DexUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * 
 * https://android.googlesource.com/platform/art/+/refs/heads/kitkat-release/runtime/oat_file.h#191
 */
class OatDexFile_KitKat extends OatDexFile {

	protected int dex_file_location_size_;
	protected String dex_file_location_;
	protected int dex_file_location_checksum_;
	protected int dex_file_pointer_;
	protected int[] oat_class_offsets_pointer_;

	private DexHeader dexHeader;

	OatDexFile_KitKat(BinaryReader reader) throws IOException {
		dex_file_location_size_ = reader.readNextInt();
		dex_file_location_ = reader.readNextAsciiString(dex_file_location_size_);
		dex_file_location_checksum_ = reader.readNextInt();
		dex_file_pointer_ = reader.readNextInt();

		ByteProvider provider = reader.getByteProvider();
		ByteProvider tmpProvider = new ByteProviderWrapper(provider, dex_file_pointer_,
			provider.length() - dex_file_pointer_);
		BinaryReader tmpReader = new BinaryReader(tmpProvider, reader.isLittleEndian());
		dexHeader = DexHeaderFactory.getDexHeader(tmpReader);

		int size = dexHeader.getClassDefs().size();//read number of classes...
		if (size == 0) {
			oat_class_offsets_pointer_ = new int[0];
		}
		else {
			oat_class_offsets_pointer_ = reader.readNextIntArray(size);
		}
	}

	@Override
	public String getDexFileLocation() {
		return dex_file_location_;
	}

	@Override
	public int getDexFileChecksum() {
		return dex_file_location_checksum_;
	}

	@Override
	public int getDexFileOffset() {
		return dex_file_pointer_;
	}

	@Override
	public DexHeader getDexHeader() {
		return dexHeader;
	}

	@Override
	public boolean isDexHeaderExternal() {
		return false;
	}

	@Override
	public void markup(OatHeader oatHeader, Program program, TaskMonitor monitor, MessageLog log)
			throws Exception {
		Symbol oatDataSymbol = OatUtilities.getOatDataSymbol(program);
		Address address = oatDataSymbol.getAddress();

		Listing listing = program.getListing();
		ReferenceManager referenceManager = program.getReferenceManager();
		SymbolTable symbolTable = program.getSymbolTable();
		Memory memory = program.getMemory();

		Data oatHeaderData = listing.getDefinedDataAt(address);
		if (oatHeaderData == null ||
			!oatHeaderData.getDataType().getName().startsWith("OatHeader")) {
			return;
		}

		List<Data> oatDexFileHeaderDataList = getOatDexFileHeaderData(oatHeaderData, monitor);
		monitor.setProgress(0);
		monitor.setMaximum(oatDexFileHeaderDataList.size());
		for (Data data : oatDexFileHeaderDataList) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);

			for (int i = 0; i < data.getNumComponents(); ++i) {
				monitor.checkCanceled();
				monitor.setMaximum(data.getNumComponents());
				monitor.setProgress(i);

				Data componentI = data.getComponent(i);

				if (componentI.getFieldName().startsWith("dex_file_pointer_")) {
					Scalar scalar = componentI.getScalar(0);
					Address toAddr = oatDataSymbol.getAddress().add(scalar.getUnsignedValue());
					referenceManager.addMemoryReference(componentI.getMinAddress(), toAddr,
						RefType.DATA, SourceType.ANALYSIS, 0);
				}
				if (componentI.getFieldName().startsWith("dexClassOffsets")) {
					Data dexClassOffsetsData = getDexClassOffsetsData(data, monitor);
					markupDexClassOffset(oatHeader, program, oatDataSymbol, dexClassOffsetsData,
						monitor, log);
				}
			}
		}

		for (int i = 0; i < oat_class_offsets_pointer_.length; ++i) {
			monitor.checkCanceled();
			monitor.setMaximum(oat_class_offsets_pointer_.length);
			monitor.setProgress(i);

			ClassDefItem classDefItem = dexHeader.getClassDefs().get(i);

			String className =
				DexUtil.convertTypeIndexToString(dexHeader, classDefItem.getClassIndex());
			Namespace classNameSpace =
				DexUtil.createNameSpaceFromMangledClassName(program, className);

			Address offsetAddress = oatDataSymbol.getAddress().add(oat_class_offsets_pointer_[i]);

			symbolTable.createLabel(offsetAddress, className, SourceType.ANALYSIS);

			ByteProvider oatClassHeaderProvider = new MemoryByteProvider(memory, offsetAddress);
			BinaryReader oatClassHeaderReader =
				new BinaryReader(oatClassHeaderProvider, !program.getLanguage().isBigEndian());

			OatClass oatClassHeader = new OatClass(oatClassHeaderReader,
				classDefItem.getClassDataItem(), oatHeader.getVersion());

			markupMethod(oatHeader, oatClassHeader, dexHeader, classDefItem, program, symbolTable,
				oatDataSymbol, classNameSpace, log, monitor);

			markupClassHeaderData(program, oatDataSymbol, offsetAddress, oatHeader, oatClassHeader,
				log, monitor);
		}
	}

	private void markupDexClassOffset(OatHeader oatHeader, Program program, Symbol oatDataSymbol,
			Data dexClassOffsetsData, TaskMonitor monitor, MessageLog log)
			throws Exception, CancelledException {

		ReferenceManager referenceManager = program.getReferenceManager();
		SymbolTable symbolTable = program.getSymbolTable();

		for (int j = 0; j < dexClassOffsetsData.getNumComponents(); ++j) {
			monitor.checkCanceled();
			Data component = dexClassOffsetsData.getComponent(j);
			if (component.getFieldName().startsWith("oat_class_offsets_pointer")) {
				Scalar scalar = component.getScalar(0);
				Address toAddr = oatDataSymbol.getAddress().add(scalar.getUnsignedValue());
				toAddr = OatUtilities.adjustForThumbAsNeeded(oatHeader, program, toAddr, log);
				referenceManager.addMemoryReference(component.getMinAddress(), toAddr, RefType.DATA,
					SourceType.ANALYSIS, 0);
				symbolTable.addExternalEntryPoint(toAddr);
			}
		}
	}

	private void markupMethod(OatHeader oatHeader, OatClass oatClassHeader, DexHeader dexHeader,
			ClassDefItem classDefItem, Program program, SymbolTable symbolTable,
			Symbol oatDataSymbol, Namespace classNameSpace, MessageLog log, TaskMonitor monitor)
			throws CancelledException, InvalidInputException {

		if (classDefItem.getClassDataOffset() == 0) {
			return;
		}
		List<EncodedMethod> allMethods =
			OatUtilities.getAllMethods(classDefItem.getClassDataItem());

		if (oatClassHeader.getType() == OatClassType.kOatClassAllCompiled.ordinal()) {
			for (int j = 0; j < oatClassHeader.getMethodOffsets().size(); ++j) {
				monitor.checkCanceled();
				monitor.setMaximum(oatClassHeader.getMethodOffsets().size());
				monitor.setProgress(j);

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
				monitor.setMaximum(allMethods.size());
				monitor.setProgress(j);

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

	private void markupClassHeaderData(Program program, Symbol oatDataSymbol, Address address,
			OatHeader oatHeader, OatClass oatClassHeader, MessageLog log, TaskMonitor monitor)
			throws Exception {

		SymbolTable symbolTable = program.getSymbolTable();
		ReferenceManager referenceManager = program.getReferenceManager();
		Listing listing = program.getListing();

		Data oatClassHeaderData = listing.createData(address, oatClassHeader.toDataType());
		for (int j = 0; j < oatClassHeaderData.getNumComponents(); ++j) {
			monitor.checkCanceled();
			monitor.setMaximum(oatClassHeaderData.getNumComponents());
			monitor.setProgress(j);

			Data component = oatClassHeaderData.getComponent(j);
			if (component.getFieldName().startsWith("methodOffsets_")) {
				Data methodOffsetData = component.getComponent(0);
				Scalar scalar = methodOffsetData.getScalar(0);
				if (scalar.getUnsignedValue() == 0) {
					continue;//TODO what does 0 mean?
				}
				Address toAddr = oatDataSymbol.getAddress().add(scalar.getUnsignedValue());
				toAddr = OatUtilities.adjustForThumbAsNeeded(oatHeader, program, toAddr, log);
				referenceManager.addMemoryReference(methodOffsetData.getMinAddress(), toAddr,
					RefType.DATA, SourceType.ANALYSIS, 0);
				symbolTable.addExternalEntryPoint(toAddr);

				Address quickHeaderAddress = toAddr.subtract(OatQuickMethodHeaderFactory
						.getOatQuickMethodHeaderSize(oatHeader.getVersion()));
				if (listing.isUndefined(quickHeaderAddress, quickHeaderAddress)) {
					ByteProvider oqmhProvider =
						new MemoryByteProvider(program.getMemory(), quickHeaderAddress);
					BinaryReader quickReader =
						new BinaryReader(oqmhProvider, !program.getLanguage().isBigEndian());
					OatQuickMethodHeader quickHeader = OatQuickMethodHeaderFactory
							.getOatQuickMethodHeader(quickReader, oatHeader.getVersion());
					DataType dataType = quickHeader.toDataType();
					try {
						listing.createData(quickHeaderAddress, dataType);
					}
					catch (CodeUnitInsertionException e) {
						log.appendMsg(e.getMessage());
					}
				}

//				Address oqmhAddress = toAddr.subtract( OatQuickMethodHeader001to064.SIZE );
//				if ( listing.isUndefined( oqmhAddress, oqmhAddress ) ) {
//					ByteProvider oqmhProvider = new MemoryByteProvider( program.getMemory( ), oqmhAddress );
//					BinaryReader oqmhReader = new BinaryReader( oqmhProvider, !program.getLanguage( ).isBigEndian( ) );
//					OatQuickMethodHeader oqmh = new OatQuickMethodHeader001to064( oqmhReader );
//					DataType dataType = oqmh.toDataType( );
//					try { 
//						listing.createData( oqmhAddress, dataType );
//					}
//					catch ( CodeUnitInsertionException e ) {
//						log.appendMsg( e.getMessage( ) );
//					}
//				}
			}
		}
	}

	private List<Data> getOatDexFileHeaderData(Data oatHeaderData, TaskMonitor monitor)
			throws Exception {
		List<Data> list = new ArrayList<Data>();
		for (int i = 0; i < oatHeaderData.getNumComponents(); ++i) {
			monitor.checkCanceled();
			monitor.setMaximum(oatHeaderData.getNumComponents());
			monitor.setProgress(i);

			Data componentI = oatHeaderData.getComponent(i);
			if (componentI.getFieldName().startsWith(OatDexFile.PREFIX)) {
				list.add(componentI);
			}
		}
		return list;
	}

	private Data getDexClassOffsetsData(Data oatDexFileHeaderData, TaskMonitor monitor)
			throws Exception {
		for (int i = 0; i < oatDexFileHeaderData.getNumComponents(); ++i) {
			monitor.checkCanceled();
			monitor.setMaximum(oatDexFileHeaderData.getNumComponents());
			monitor.setProgress(i);

			Data componentI = oatDexFileHeaderData.getComponent(i);
			if (componentI.getFieldName().startsWith("dexClassOffsets")) {
				return componentI;
			}
		}
		throw new RuntimeException("Can't find dexClassOffsets");
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String className = StructConverterUtil.parseName(OatDexFile_KitKat.class);
		Structure structure =
			new StructureDataType(className + "_" + oat_class_offsets_pointer_.length, 0);
		structure.add(DWORD, "dex_file_location_size_", null);
		structure.add(STRING, dex_file_location_size_, "dex_file_location_", null);
		structure.add(DWORD, "dex_file_location_checksum_", null);
		structure.add(DWORD, "dex_file_pointer_", null);

		Structure dexClassOffsetsStructure =
			new StructureDataType("dexClassOffsets_" + oat_class_offsets_pointer_.length, 0);
		for (int i = 0; i < oat_class_offsets_pointer_.length; ++i) {
			dexClassOffsetsStructure.add(DWORD, "oat_class_offsets_pointer_" + i, null);
		}
		dexClassOffsetsStructure.setCategoryPath(new CategoryPath("/oat"));

		structure.add(dexClassOffsetsStructure, "dexClassOffsets", null);

		structure.setCategoryPath(new CategoryPath("/oat"));
		return structure;
	}

}
