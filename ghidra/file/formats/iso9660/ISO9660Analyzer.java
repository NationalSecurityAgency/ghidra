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
package ghidra.file.formats.iso9660;

import java.io.IOException;
import java.util.*;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.data.CreateStringCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class ISO9660Analyzer extends AbstractAnalyzer {

	private enum Offset {
		Offset1, //0x8001
		Offset2, //0x8801
		Offset3, //0x9001 
		NotFound
	}

	public ISO9660Analyzer() {
		super("ISO9660 File Format Annotation", "Annotates an ISO9660 File Format",
			AnalyzerType.BYTE_ANALYZER);
		super.setPrototype();

	}

	@Override
	public boolean canAnalyze(Program program) {

		Offset result = checkSignatures(program);
		if (result.equals(Offset.NotFound)) {
			return false;
		}
		return true;

	}

	private Offset checkSignatures(Program program) {
		int magicLen = ISO9660Constants.MAGIC_BYTES.length;
		byte[] signatureArray = new byte[magicLen];

		try {
			Options options = program.getOptions("Program Information");
			String format = options.getString("Executable Format", null);
			if (!BinaryLoader.BINARY_NAME.equals(format)) {
				return Offset.NotFound;
			}

			MemoryBlock[] blocks = program.getMemory().getBlocks();
			if (blocks.length != 1) {
				return Offset.NotFound;
			}

			AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
			if (!(blocks[0].getStart().getAddressSpace().equals(addressSpace))) {
				return Offset.NotFound;
			}

			long blockSize = blocks[0].getSize();

			//block must start at zero
			if (blocks[0].getStart().getOffset() != 0L) {
				return Offset.NotFound;
			}

			//is the block initialized
			if (!blocks[0].isInitialized()) {
				return Offset.NotFound;
			}

			ByteProvider provider = new MemoryByteProvider(program.getMemory(), addressSpace);
			BinaryReader reader = new BinaryReader(provider, true);

			//Make sure that the current programs max offset is at least big enough to check
			//for the ISO's max address location of a signature
			if (blockSize < ISO9660Constants.MIN_ISO_LENGTH1) {
				return Offset.NotFound;
			}

			//Check first possible signature location
			reader.setPointerIndex(ISO9660Constants.SIGNATURE_OFFSET1_0x8001);
			signatureArray = reader.readNextByteArray(magicLen);
			if (Arrays.equals(signatureArray, ISO9660Constants.MAGIC_BYTES)) {
				//Where to start the reader during mark up
				return Offset.Offset1;
			}

			if (blockSize < ISO9660Constants.MIN_ISO_LENGTH2) {
				return Offset.NotFound;
			}

			//Check second possible signature location
			reader.setPointerIndex(ISO9660Constants.SIGNATURE_OFFSET2_0x8801);
			signatureArray = reader.readNextByteArray(magicLen);
			if (Arrays.equals(signatureArray, ISO9660Constants.MAGIC_BYTES)) {
				//Where to start the reader during mark up
				return Offset.Offset2;
			}

			if (blockSize < ISO9660Constants.MIN_ISO_LENGTH3) {
				return Offset.NotFound;
			}
			//Check third possible signature location
			reader.setPointerIndex(ISO9660Constants.SIGNATURE_OFFSET3_0x9001);
			signatureArray = reader.readNextByteArray(magicLen);
			if (Arrays.equals(signatureArray, ISO9660Constants.MAGIC_BYTES)) {
				//Where to start the reader during mark up
				return Offset.Offset3;
			}

		}
		catch (Exception e) {
			Msg.error(this, "Error when checking for ISO9660 file signatures", e);
		}

		//Signature is not found at any of the three possible address locations
		return Offset.NotFound;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		ByteProvider provider = new MemoryByteProvider(program.getMemory(),
			program.getAddressFactory().getDefaultAddressSpace());
		BinaryReader reader = new BinaryReader(provider, true);
		try {

			Offset signatureOffset = checkSignatures(program);
			setPointerOffset(signatureOffset, reader);

			monitor.setMessage("Processing ISO9660 Header");

			//Get the full header (contains all volume descriptors)
			ISO9660Header isoHeader = new ISO9660Header(reader);

			//Get the list of volumes from the header
			List<ISO9660BaseVolume> volumes = isoHeader.getVolumeDescriptorSet();

			//Set the overall plate comment at the top of this file
			setPlateComment(program, toAddress(program, 0), isoHeader.toString());

			//Create a new module for the volume descriptor fragments
			ProgramModule descriptorModule =
				program.getListing().getDefaultRootModule().createModule("Volume Descriptors");

			//For each volume, set the volumes plate comment and data at the address it exists
			setDescriptorData(program, volumes, descriptorModule);

			processPathTables(isoHeader, reader, program);

			//Create an alignment over the null characters from start to the first volume
			int offset = getOffsetValue(signatureOffset);
			program.getListing().createData(toAddress(program, 0), new AlignmentDataType(),
				offset - 1);

			ISO9660VolumeDescriptor pvd = isoHeader.getPrimaryVolumeDescriptor();
			ISO9660Directory entryDir = isoHeader.getPrimaryDirectory();

			int logicalBlockSize = pvd.getLogicalBlockSizeLE();

			List<ISO9660Directory> dirList =
				createDirectoryList(reader, entryDir, logicalBlockSize);

			createDirectories(reader, program, dirList, logicalBlockSize);

		}
		catch (Exception e) {
			log.appendException(e);
			return false;
		}
		return true;

	}

	private void setPointerOffset(Offset offset, BinaryReader reader) {
		if (offset.equals(Offset.Offset1)) {
			reader.setPointerIndex(ISO9660Constants.SIGNATURE_OFFSET1_0x8001 - 1);
		}
		else if (offset.equals(Offset.Offset2)) {
			reader.setPointerIndex(ISO9660Constants.SIGNATURE_OFFSET2_0x8801 - 1);
		}
		else {
			reader.setPointerIndex(ISO9660Constants.SIGNATURE_OFFSET3_0x9001 - 1);
		}
	}

	private int getOffsetValue(Offset offsetEnum) {

		if (offsetEnum.equals(Offset.Offset1)) {
			return ISO9660Constants.SIGNATURE_OFFSET1_0x8001;
		}
		else if (offsetEnum.equals(Offset.Offset2)) {
			return ISO9660Constants.SIGNATURE_OFFSET2_0x8801;
		}
		else {
			return ISO9660Constants.SIGNATURE_OFFSET3_0x9001;
		}
	}

	private void setDescriptorData(Program program, List<ISO9660BaseVolume> volumes,
			ProgramModule descriptorModule) throws DuplicateNameException, IOException, Exception {

		for (ISO9660BaseVolume descriptor : volumes) {

			long volumeIndex = descriptor.getVolumeIndex();
			DataType descriptorDataType = descriptor.toDataType();
			Address volumeAddress = toAddress(program, volumeIndex);
			Data descriptorData =
				createData(program, toAddress(program, volumeIndex), descriptorDataType);

			setPlateComment(program, volumeAddress, descriptor.toString());

			//Add fragment to module
			createFragment(program, descriptorModule, descriptorDataType.getName(),
				descriptorData.getMinAddress(), descriptorData.getMaxAddress().next());
		}
	}

	/*
	 * Process the normal and supplementary path tables in the binary
	 */
	private void processPathTables(ISO9660Header isoHeader, BinaryReader reader, Program program)
			throws DuplicateNameException {

		//Create module to add path table fragments to
		ProgramModule pathTableModule =
			program.getListing().getDefaultRootModule().createModule("Path Tables");

		try {

			//Get the tables which hold the index and size pairs of path tables
			//for little-endian values
			HashMap<Integer, Short> typeLTable = isoHeader.getTypeLIndexSizeTable();
			createPathTableData(reader, program, pathTableModule, typeLTable, true);

			//Get the tables which hold the index and size pairs of path tables
			//for big-endian values
			HashMap<Integer, Short> typeMTable = isoHeader.getTypeMIndexSizeTable();
			createPathTableData(reader, program, pathTableModule, typeMTable, false);

			//Get the tables which hold the index and size of supplementary path tables
			//for little-endian values
			HashMap<Integer, Short> supplTypeLTable = isoHeader.getSupplTypeLIndexSizeTable();
			createPathTableData(reader, program, pathTableModule, supplTypeLTable, true);

			//Get the tables which hold the index and size of supplementary path tables
			//for big-endian values
			HashMap<Integer, Short> supplTypeMTable = isoHeader.getSupplTypeMIndexSizeTable();
			createPathTableData(reader, program, pathTableModule, supplTypeMTable, false);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	/*
	 * From a given parent directory create each child directory
	 * under that parent directory and add them to a list
	 */
	private List<ISO9660Directory> createDirectoryList(BinaryReader reader,
			ISO9660Directory parentDir, long blockSize) throws IOException {

		List<ISO9660Directory> directoryList = new ArrayList<>();
		ISO9660Directory childDir = null;

		//Get location from parent into child directory
		long dirIndex = parentDir.getLocationOfExtentLE() * blockSize;
		long endIndex = dirIndex + parentDir.getDataLengthLE();

		//while there is still more data in the current directory level
		while (dirIndex < endIndex) {
			reader.setPointerIndex(dirIndex);

			//If the next byte is not zero then create the directory
			if (reader.peekNextByte() != 0) {
				childDir = new ISO9660Directory(reader, parentDir);
				directoryList.add(childDir);
			}

			//Otherwise there is a gap in the data so keep looking forward
			//while still under the end index and create directory when data is
			//reached
			else {
				while (reader.peekNextByte() == 0) {
					//keep reading if all zeros until non zero is met or
					//end index reached
					if (reader.getPointerIndex() < endIndex) {
						reader.readNextByte();
					}
					else {
						break;
					}
				}

				//Create the data once the reader finds the next position
				//and not reached end index
				if (reader.getPointerIndex() < endIndex) {
					childDir = new ISO9660Directory(reader, parentDir);
					dirIndex = childDir.getVolumeIndex();
					directoryList.add(childDir);
				}
			}

			dirIndex += childDir.getDirectoryRecordLength();
		}

		return directoryList;
	}

	/*
	* Recurses though each level of a directory structure
	* in a depth-first manner
	* and creates each directory also marking them in the binary
	*/
	private void createDirectories(BinaryReader reader, Program program,
			List<ISO9660Directory> directoryList, long blockSize)
			throws DuplicateNameException, Exception {

		Address volumeAddress;

		//If the directory size is over two then there are actual
		//new directories in that level. The first two are always
		//the 'self' directory and the parent directory
		if (directoryList.size() > 2) {
			ISO9660Directory selfDir = null;
			ISO9660Directory parentDir = null;

			// The 'self' describing directory entry
			selfDir = directoryList.remove(0);
			volumeAddress = toAddress(program, selfDir.getVolumeIndex());
			createDataAndPlateComment(program, selfDir, volumeAddress);

			// The parent directory
			parentDir = directoryList.remove(0);
			volumeAddress = toAddress(program, parentDir.getVolumeIndex());
			createDataAndPlateComment(program, parentDir, volumeAddress);

			//For everything else not a self or parent directory
			for (ISO9660Directory dir : directoryList) {

				//If this directory is not pointing to a file
				//Create the directory data
				if (selfDir.isDirectoryFlagSet()) {
					volumeAddress = toAddress(program, dir.getVolumeIndex());
					setPlateComment(program, volumeAddress, dir.toString());
					DataType volumeDataType = dir.toDataType();
					createData(program, volumeAddress, volumeDataType);

					//If the directory is a new level of directories
					//recurse down into the next level
					if (dir.isDirectoryFlagSet()) {
						List<ISO9660Directory> dirs;
						dirs = createDirectoryList(reader, dir, blockSize);
						createDirectories(reader, program, dirs, blockSize);
					}
				}
			}
		}

		return;
	}

	private void createDataAndPlateComment(Program program, ISO9660Directory dir,
			Address volumeAddress) throws DuplicateNameException, IOException, Exception {

		setPlateComment(program, volumeAddress, dir.toString());
		createData(program, volumeAddress, dir.toDataType());
	}

	/*
	 * Creates path table plate comments and lays mark up data down on the binary
	 */
	private void createPathTableData(BinaryReader reader, Program program, ProgramModule module,
			HashMap<Integer, Short> pathTableMap, boolean littleEndian) throws Exception {

		//Enumeration over the indexes of the path tables in the table

		Set<Integer> pathTableIndexes = pathTableMap.keySet();
		Iterator<Integer> pathIter = pathTableIndexes.iterator();

		while (pathIter.hasNext()) {

			//Index of current path table
			int pathTableIndex = pathIter.next();

			//Logical block size of current path table
			short logicalBlockSize = pathTableMap.get(pathTableIndex);

			//Calculate address from logical index
			int pathAddress = logicalBlockSize * pathTableIndex;

			//Move reader to the path table address
			reader.setPointerIndex(pathAddress);

			ISO9660PathTable pathTable = new ISO9660PathTable(reader, littleEndian);
			DataType pathTableDataType = pathTable.toDataType();

			Address volumeAddress = toAddress(program, pathTable.getVolumeIndex());

			setPlateComment(program, volumeAddress, pathTable.toString());
			Data pathTableData = createData(program, volumeAddress, pathTableDataType);
			createFragment(program, module, pathTableDataType.getName(),
				pathTableData.getMinAddress(), pathTableData.getMaxAddress().next());
		}
	}

	/*
	 * Marks up the binary with data
	 */
	private Data createData(Program program, Address address, DataType datatype) throws Exception {
		if (datatype instanceof StringDataType) {
			CreateStringCmd cmd = new CreateStringCmd(address);
			if (!cmd.applyTo(program)) {
				throw new RuntimeException(cmd.getStatusMsg());
			}
		}
		else {
			CreateDataCmd cmd = new CreateDataCmd(address, datatype);
			if (!cmd.applyTo(program)) {
				throw new RuntimeException(cmd.getStatusMsg());
			}
		}
		return program.getListing().getDefinedDataAt(address);
	}

	private Address toAddress(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private boolean setPlateComment(Program program, Address address, String comment) {
		SetCommentCmd cmd = new SetCommentCmd(address, CodeUnit.PLATE_COMMENT, comment);
		return cmd.applyTo(program);
	}

	private ProgramFragment createFragment(Program program, ProgramModule module,
			String fragmentName, Address start, Address end) throws Exception {

		ProgramFragment fragment = getFragment(module, fragmentName);
		if (fragment == null) {
			fragment = module.createFragment(fragmentName);
		}
		fragment.move(start, end.subtract(1));
		return fragment;
	}

	private ProgramFragment getFragment(ProgramModule module, String fragmentName) {
		Group[] groups = module.getChildren();
		if (groups != null) {
			for (Group group : groups) {
				if (group.getName().equals(fragmentName) && group instanceof ProgramFragment) {
					return (ProgramFragment) group;
				}
			}
		}

		return null;
	}

}
