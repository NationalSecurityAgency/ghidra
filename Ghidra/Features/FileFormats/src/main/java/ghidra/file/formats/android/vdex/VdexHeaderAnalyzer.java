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
package ghidra.file.formats.android.vdex;

import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.file.formats.android.dex.format.DexHeader;
import ghidra.file.formats.android.oat.OatConstants;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class VdexHeaderAnalyzer extends FileFormatAnalyzer {

	private final static DataType BYTE = new ByteDataType();

	@Override
	public String getName() {
		return "Android VDEX Header Format";
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public String getDescription() {
		return "Annotates the Android VDEX data in this program.";
	}

	@Override
	public boolean canAnalyze(Program program) {
		return VdexConstants.isVDEX(program)
		//HACK:
		//Make analyzer appear after VDEX is merged with OAT program
		//Currently, analyzers will not recognize the new VDEX block being added
			|| OatConstants.isOAT(program);
	}

	@Override
	public boolean isPrototype() {
		return true;
	}

	@Override
	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws Exception {
		Address address = VdexConstants.findVDEX(program);
		if (address == null) {
			log.appendMsg(getClass().getSimpleName() + " - no vdex header found, skipping");
			return true;
		}
		ByteProvider provider = new MemoryByteProvider(program.getMemory(), address);
		BinaryReader reader = new BinaryReader(provider, !program.getLanguage().isBigEndian());
		try {
			VdexHeader vdexHeader = VdexFactory.getVdexHeader(reader);
			vdexHeader.parse(reader, monitor);

			DataType vdexHeaderDataType = vdexHeader.toDataType();
			createData(program, address, vdexHeaderDataType);
			address = address.add(vdexHeaderDataType.getLength());

			if (!vdexHeader.isDexHeaderEmbeddedInDataType()) {
				for (int i = 0; i < vdexHeader.getDexHeaderList().size(); ++i) {
					monitor.checkCanceled();

					program.getListing()
							.setComment(address, CodeUnit.PLATE_COMMENT,
								"quicken info table entry");
					createData(program, address, new DWordDataType());
					address = address.add(4);

					DexHeader dexHeader = vdexHeader.getDexHeaderList().get(i);
					DataType dexHeaderDataType = dexHeader.toDataType();
					createData(program, address, dexHeaderDataType);

					int size = dexHeader.getFileSize() - dexHeaderDataType.getLength();
					DataType array = new ArrayDataType(BYTE, size, BYTE.getLength());
					createData(program, address.add(dexHeaderDataType.getLength()), array);

					address = address.add(dexHeader.getFileSize());
				}
			}

			address = createDexSharedDataSize(program, address, vdexHeader);

			address = createVerifierDepsSize(program, address, vdexHeader);

			address = createQuickeningInfoSize(program, address, vdexHeader);

			return true;
		}
		catch (UnsupportedVdexVersionException e) {
			log.appendMsg(e.getMessage());
		}
		catch (Exception e) {
			log.appendException(e);
		}
		return false;
	}

	private Address createDexSharedDataSize(Program program, Address address, VdexHeader vdexHeader)
			throws Exception {
		DexSectionHeader_002 sectionHeader = vdexHeader.getDexSectionHeader_002();
		if (sectionHeader != null) {
			int dexSharedDataSize = sectionHeader.getDexSharedDataSize();
			String comment = "dex_shared_data_size_ : 0x" + Integer.toHexString(dexSharedDataSize);
			program.getListing().setComment(address, CodeUnit.PLATE_COMMENT, comment);
			DataType array = new ArrayDataType(BYTE, dexSharedDataSize, BYTE.getLength());
			createData(program, address, array);
			address = address.add(dexSharedDataSize);
		}
		return address;
	}

	private Address createVerifierDepsSize(Program program, Address address, VdexHeader vdexHeader)
			throws Exception {
		if (vdexHeader.getVerifierDepsVersion() != VdexConstants.VERSION_10_RELEASE) {
			return address;
		}

		String comment =
			"verifier_deps_size_ : 0x" + Integer.toHexString(vdexHeader.getVerifierDepsSize());
		program.getListing().setComment(address, CodeUnit.PLATE_COMMENT, comment);

		int remainderSize = vdexHeader.getVerifierDepsSize();

		ByteProvider provider = new MemoryByteProvider(program.getMemory(), address);
		BinaryReader reader = new BinaryReader(provider, !program.getLanguage().isBigEndian());
		VdexStringTable stringTable = new VdexStringTable(reader);
		if (stringTable.getStringCount() > 0) {
			createData(program, address, stringTable.toDataType());
			address = address.add(stringTable.getSize());
			remainderSize -= stringTable.getSize();
		}
		if (address.add(remainderSize).compareTo(program.getMaxAddress()) > 0) {
			remainderSize = (int) program.getMaxAddress().subtract(address);
		}
		if (remainderSize > 0) {
			DataType array = new ArrayDataType(BYTE, remainderSize, BYTE.getLength());
			createData(program, address, array);
			address = address.add(remainderSize);
		}
		return address;
	}

	private Address createQuickeningInfoSize(Program program, Address address,
			VdexHeader vdexHeader) throws Exception {
		int quickeningInfoSize = vdexHeader.getQuickeningInfoSize();

		DexSectionHeader_002 sectionHeader = vdexHeader.getDexSectionHeader_002();
		if (sectionHeader != null) {
			quickeningInfoSize = sectionHeader.getQuickeningInfoSize();
		}

		if (quickeningInfoSize == 0) {
			return address;
		}

		String comment = "quickening_info_size_ : 0x" + Integer.toHexString(quickeningInfoSize);
		program.getListing().setComment(address, CodeUnit.PLATE_COMMENT, comment);

		address = address.add(quickeningInfoSize);

		return address;
	}
}
