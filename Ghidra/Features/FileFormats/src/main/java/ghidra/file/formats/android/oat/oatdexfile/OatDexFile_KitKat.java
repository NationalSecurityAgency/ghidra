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
package ghidra.file.formats.android.oat.oatdexfile;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.formats.android.dex.DexHeaderFactory;
import ghidra.file.formats.android.dex.format.ClassDefItem;
import ghidra.file.formats.android.dex.format.DexHeader;
import ghidra.file.formats.android.dex.util.DexUtil;
import ghidra.file.formats.android.oat.OatHeader;
import ghidra.file.formats.android.oat.OatUtilities;
import ghidra.file.formats.android.oat.oatclass.OatClass;
import ghidra.file.formats.android.oat.oatclass.OatClassFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/kitkat-release/runtime/oat_file.h#191">kitkat-release/runtime/oat_file.h</a>
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
			monitor.checkCancelled();
			monitor.incrementProgress(1);

			for (int i = 0; i < data.getNumComponents(); ++i) {
				monitor.checkCancelled();
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
			monitor.checkCancelled();
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

			OatClass oatClassHeader = OatClassFactory.getOatClass(oatClassHeaderReader,
				classDefItem.getClassDataItem(), oatHeader.getVersion());

			OatDexFileUtilities.markupMethod(oatHeader, oatClassHeader, dexHeader, classDefItem,
				program, oatDataSymbol, classNameSpace, log, monitor);

			OatDexFileUtilities.markupClassHeaderData(program, oatDataSymbol, offsetAddress,
				oatHeader, oatClassHeader,
				log, monitor);
		}
	}

	private void markupDexClassOffset(OatHeader oatHeader, Program program, Symbol oatDataSymbol,
			Data dexClassOffsetsData, TaskMonitor monitor, MessageLog log)
			throws Exception, CancelledException {

		ReferenceManager referenceManager = program.getReferenceManager();
		SymbolTable symbolTable = program.getSymbolTable();

		for (int j = 0; j < dexClassOffsetsData.getNumComponents(); ++j) {
			monitor.checkCancelled();
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

	private List<Data> getOatDexFileHeaderData(Data oatHeaderData, TaskMonitor monitor)
			throws Exception {
		List<Data> list = new ArrayList<Data>();
		for (int i = 0; i < oatHeaderData.getNumComponents(); ++i) {
			monitor.checkCancelled();
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
			monitor.checkCancelled();
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
		Structure structure = new StructureDataType(OatDexFile_KitKat.class.getSimpleName() +
			"_" + oat_class_offsets_pointer_.length, 0);
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
