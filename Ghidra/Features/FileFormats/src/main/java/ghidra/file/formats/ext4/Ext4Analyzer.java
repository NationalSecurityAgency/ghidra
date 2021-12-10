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
package ghidra.file.formats.ext4;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class Ext4Analyzer extends FileFormatAnalyzer {
	
	private int blockSize;

	@Override
	public String getName() {
		return "Ext4 Analyzer";
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public String getDescription() {
		return "Annotates Ext4 file systems.";
	}

	@Override
	public boolean canAnalyze(Program program) {
		ByteProvider provider = new MemoryByteProvider( program.getMemory(), program.getAddressFactory().getDefaultAddressSpace());
		BinaryReader reader = new BinaryReader(provider, true);
		int start = getSuperBlockStart(reader);
		if( start == -1 ) {
			return false;
		}
		
		reader.setPointerIndex(start + 0x38);
		short magic = -1;
		try {
			magic = reader.readNextShort();
		} catch (IOException e ) {
			// ignore
		}
		if( magic != (short)0xef53 ) {
			return false;
		}
		return true;
	}

	@Override
	public boolean isPrototype() {
		return false;
	}

	@Override
	public boolean analyze(Program program, AddressSetView set,
			TaskMonitor monitor, MessageLog log) throws Exception {
		ByteProvider provider = new MemoryByteProvider( program.getMemory(), program.getAddressFactory().getDefaultAddressSpace());
		BinaryReader reader = new BinaryReader(provider, true);
		int start = getSuperBlockStart(reader);
		int groupStart = 0;
		reader.setPointerIndex(start);
		Ext4SuperBlock superBlock = new Ext4SuperBlock(reader);
		createData(program, toAddr(program, start), superBlock.toDataType());
		

		boolean is64Bit = (superBlock.getS_desc_size() > 32) && ((superBlock.getS_feature_incompat() & 0x80) > 0);
		long numBytes = program.getMaxAddress().getOffset() - program.getMinAddress().getOffset() + 1;
		int groupSize = calculateGroupSize( superBlock );
		int numGroups = (int)numBytes / groupSize;
		if( numBytes % groupSize != 0) {
			numGroups++;
		}
		
		long groupDescOffset = groupStart + blockSize;
		Address groupDescAddress = toAddr(program, groupDescOffset);
		reader.setPointerIndex(groupDescOffset);
		Ext4GroupDescriptor groupDescriptors[] = new Ext4GroupDescriptor[numGroups];
		monitor.setMessage("Creating group descriptors...");
		monitor.setMaximum(numGroups);
		for( int i = 0; i < numGroups; i++ ) {
			monitor.checkCanceled();
			groupDescriptors[i] = new Ext4GroupDescriptor(reader, is64Bit);
			DataType groupDescDataType = groupDescriptors[i].toDataType();
			createData(program, groupDescAddress, groupDescDataType);
			groupDescAddress = groupDescAddress.add(groupDescDataType.getLength());	
			monitor.incrementProgress(1);
		}
		
		boolean isSparseSuper = (superBlock.getS_feature_ro_compat() & 1) != 0;
		createSuperBlockCopies(program, reader, groupSize, numGroups, is64Bit, isSparseSuper, monitor);
		
		createInodeTables(program, reader, superBlock, groupDescriptors, is64Bit, monitor);
		
//		test(program, reader);
		return true;
	}
	
	private void createInodeTables(Program program, BinaryReader reader, Ext4SuperBlock superBlock,
			Ext4GroupDescriptor[] groupDescriptors, boolean is64Bit, TaskMonitor monitor) throws DuplicateNameException, Exception {
		
		int inodeCount = superBlock.getS_inodes_count();
		Ext4Inode inodes[] = new Ext4Inode[inodeCount];

		for( int i = 0; i < groupDescriptors.length; i++ ) {
			monitor.checkCanceled();
			long inodeTableBlockOffset = groupDescriptors[i].getBg_inode_table_lo() & 0xffffffffL;
			if( is64Bit ) {
				inodeTableBlockOffset = (groupDescriptors[i].getBg_inode_table_hi() << 32) | inodeTableBlockOffset;
			}
			long offset = inodeTableBlockOffset * blockSize;
			reader.setPointerIndex(offset);
			Address address = null;
			try {
				address = toAddr(program, offset);
			} catch (Exception e ) {
				throw new IOException("offset " + offset + " not in program.");
			}
			
			int inodesPerGroup = superBlock.getS_inodes_per_group();
			monitor.setMessage("Creating inode table " + i + " of " + (groupDescriptors.length - 1) + "...");
			monitor.setMaximum(inodesPerGroup);
			monitor.setProgress(0);
			for( int j = 0; j < inodesPerGroup; j++ ) {
				if( i == 0 && j == 0) {
					//inode 0 does not exist
					continue;
				}
				monitor.checkCanceled();
				Ext4Inode inode = new Ext4Inode(reader);
				DataType dataType = inode.toDataType();
				createData(program, address, dataType);
				program.getListing().setComment(address, CodeUnit.EOL_COMMENT, "0x" + (Integer.toHexString(inodesPerGroup * i + j )));
				address = address.add(superBlock.getS_inode_size());
				reader.setPointerIndex(address.getOffset());
				monitor.incrementProgress(1);
				inodes[inodesPerGroup * i + j] = inode;
			}
		}
		processInodes( program, reader, superBlock, inodes, monitor);
	}

	private void processInodes(Program program, BinaryReader reader,
			Ext4SuperBlock superBlock, Ext4Inode[] inodes, TaskMonitor monitor) throws Exception {
		//first 0xa inodes are reserved (0 doesn't exist)
		for( int i = 0x1; i < inodes.length; i++ ) {
			monitor.checkCanceled();
			Ext4Inode inode = inodes[i];
			short mode = inode.getI_mode();
			if( (mode & Ext4Constants.S_IFDIR) != 0 ) {
				processDirectory(program, reader, superBlock, inode, monitor);
			} else if( (mode & Ext4Constants.S_IFREG) != 0 ) {
				processFile(program, reader, superBlock, inode, monitor);
			} 
		}
	}

	private void processFile(Program program, BinaryReader reader,
			Ext4SuperBlock superBlock, Ext4Inode inode, TaskMonitor monitor) {
		// TODO?
	}

	private void processDirectory(Program program, BinaryReader reader,
			Ext4SuperBlock superBlock, Ext4Inode inode, TaskMonitor monitor) throws Exception {
		if( (inode.getI_flags() & Ext4Constants.EXT4_INDEX_FL) != 0 ) {
			processHashTreeDirectory(program, reader, superBlock, inode, monitor);
		}
		boolean isDirEntry2 = (superBlock.getS_feature_incompat() & Ext4Constants.INCOMPAT_FILETYPE) != 0;
		// if uses extents
		if( (inode.getI_flags() & Ext4Constants.EXT4_EXTENTS_FL) != 0 ) {
//			Ext4IBlock i_block = inode.getI_block();
//			Ext4ExtentHeader header = i_block.getHeader();
//			if( header.getEh_depth() == 0 ) {
//				short numEntries = header.getEh_entries();
//				List<Ext4Extent> entries = i_block.getExtentEntries();
//				for( int i = 0; i < numEntries; i++ ) {
//					Ext4Extent extent = entries.get(i);
//					long offset = extent.getExtentStartBlockNumber() * blockSize;
//					reader.setPointerIndex(offset);
//					Address address = toAddr(program, offset);
//					if( isDirEntry2 ) {
//						while( (reader.getPointerIndex() - offset) < (extent.getEe_len() * blockSize)) {
//							Ext4DirEntry2 dirEnt2 = Ext4DirEntry2.read(reader);
//							DataType dataType = dirEnt2.toDataType();
//							createData(program, address, dataType);
//							address = address.add(dataType.getLength());
//						}
//					}
//				}
//					
//			} 
		}
		
	}

	private void processHashTreeDirectory(Program program, BinaryReader reader,
			Ext4SuperBlock superBlock, Ext4Inode inode, TaskMonitor monitor) {
		// TODO?
	}

	private void createSuperBlockCopies(Program program, BinaryReader reader,
			int groupSize, int numGroups, boolean is64Bit, boolean isSparseSuper, TaskMonitor monitor) throws DuplicateNameException, IOException, Exception {
		monitor.setMessage("Creating super block and group descriptor copies...");
		monitor.setMaximum(numGroups);
		for( int i = 1; i < numGroups; i++ ) {
			monitor.checkCanceled();
			if( isSparseSuper && (!isXpowerOfY(i, 3) && !isXpowerOfY(i, 5) && !isXpowerOfY(i, 7)) ) {
				continue;
			}
			int offset = groupSize * i;
			Address address = toAddr(program, offset);
			reader.setPointerIndex(offset);
			Ext4SuperBlock superBlock = new Ext4SuperBlock(reader);
			createData(program, address, superBlock.toDataType());
			
			
			long groupDescOffset = offset + blockSize;
			Address groupDescAddress = toAddr(program, groupDescOffset);
			reader.setPointerIndex(groupDescOffset);
			for( int j = 0; j < numGroups; j++ ) {
				Ext4GroupDescriptor groupDesc = new Ext4GroupDescriptor(reader, is64Bit);
				DataType groupDescDataType = groupDesc.toDataType();
				createData(program, groupDescAddress, groupDescDataType);
				groupDescAddress = groupDescAddress.add(groupDescDataType.getLength());			
			}
			monitor.incrementProgress(1);
		}
		
	}
	
	private boolean isXpowerOfY( int x, int y ) {
		if( x == 0 ) {
			return false;
		}
		while( x % y == 0 ) {
			x = x / y;
		}
		return x == 1;
	}

	private int calculateGroupSize(Ext4SuperBlock superBlock) {
		int logBlockSize = superBlock.getS_log_block_size();
		blockSize = (int) Math.pow(2, 10 + logBlockSize);
		int groupSize = blockSize * superBlock.getS_blocks_per_group();
		return groupSize;
	}

	private int getSuperBlockStart(BinaryReader reader) {
		try {
			int padding = -1;
			int padStart = 0;
			boolean isPadding = false;
			while( padStart < 1024 ) {
				if( !isPadding ) {
					padStart = (int)reader.getPointerIndex();
				}
				padding = reader.readNextInt();
				if( padding == 0 ) {
					if( isPadding ) {
						return padStart + 0x400;
					}
					isPadding = true;
				} else {
					isPadding = false;
				}
			}
		} catch (Exception e) {
		}
		return -1;
	}
	
}
