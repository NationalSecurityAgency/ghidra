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
import java.util.List;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class NewExt4Analyzer extends FileFormatAnalyzer {
	
	private int blockSize;

	private Program program2;
	private Program program3;

	@Override
	public String getName( ) {
		return "Ext4 Analyzer NEW";
	}

	@Override
	public boolean getDefaultEnablement( Program program ) {
		return true;
	}

	@Override
	public String getDescription( ) {
		return "Annotates Ext4 file systems. " +
				"For EXT4 files >2GB, split into 2 programs. Analysis will markup both. "+
				"Simply name the programs ABC and ABC_0x70000000 and ABC_0xF0000000";
	}

	@Override
	public boolean canAnalyze( Program program ) {
		ByteProvider provider = new MemoryByteProvider( program.getMemory( ), program.getAddressFactory( ).getDefaultAddressSpace( ) );
		BinaryReader reader = new BinaryReader( provider, true );
		int start = getSuperBlockStart( reader );
		if ( start == -1 ) {
			return false;
		}

		reader.setPointerIndex( start + 0x38 );

		int magic = -1;
		try {
			magic = reader.readNextShort( ) & 0xffff;
		}
		catch ( IOException e ) {
			// ignore
		}
		return magic == Ext4Constants.SUPER_BLOCK_MAGIC;
	}

	@Override
	public boolean isPrototype() {
		return false;
	}

	@Override
	public boolean analyze( Program program, AddressSetView set, TaskMonitor monitor, MessageLog log ) throws Exception {

		program2 = findOtherProgram( program, "0x70000000" );
		int transactionId2 = -1;
		if ( program2 != null ) {
			transactionId2 = program2.startTransaction( getName( ) );
		}

		program3 = findOtherProgram( program, "0xE0000000" );
		int transactionId3 = -1;
		if ( program3 != null ) {
			transactionId3 = program3.startTransaction( getName( ) );
		}

		try { 
			ByteProvider provider = new MultiProgramMemoryByteProvider( program, program2, program3 );
			BinaryReader reader = new BinaryReader( provider, true );
			int start = getSuperBlockStart( reader );
			int groupStart = 0;
			reader.setPointerIndex( start );
			Ext4SuperBlock superBlock = new Ext4SuperBlock( reader );
			Address superBlockAddress = toAddr( program, start );
			createData( program, superBlockAddress, superBlock.toDataType( ) );
			

			boolean is64Bit = ( superBlock.getS_desc_size( ) > 32 ) && ( ( superBlock.getS_feature_incompat( ) & 0x80 ) > 0 );

			long numBytes = program.getMaxAddress( ).getOffset( ) - program.getMinAddress( ).getOffset( ) + 1;
			if ( program2 != null ) {
				numBytes = program2.getMaxAddress( ).getOffset( ) - program.getMinAddress( ).getOffset( ) + 1;
			}
			if ( program3 != null ) {
				numBytes = program3.getMaxAddress( ).getOffset( ) - program.getMinAddress( ).getOffset( ) + 1;
			}

			int groupSize = calculateGroupSize( superBlock );
			int numGroups = ( int ) ( numBytes / groupSize );
			if ( numBytes % groupSize != 0 ) {
				numGroups++;
			}

			setPlateComment( program, superBlockAddress, "SuperBlock (main) \n" + 
							"Group Size In Bytes: 0x" + Integer.toHexString( groupSize ) + "\n" +
							"Number of Groups: 0x" + Integer.toHexString( numGroups ) );

			long groupDescOffset = groupStart + blockSize;
			Address groupDescAddress = toAddr( program, groupDescOffset );
			reader.setPointerIndex( groupDescOffset );
			Ext4GroupDescriptor groupDescriptors[] = new Ext4GroupDescriptor [ numGroups ];
			monitor.setMessage( "Creating group descriptors..." );
			monitor.setMaximum( numGroups );
			for ( int i = 0; i < numGroups; i++ ) {
				monitor.checkCanceled( );
				groupDescriptors[ i ] = new Ext4GroupDescriptor( reader, is64Bit );
				DataType groupDescDataType = groupDescriptors[ i ].toDataType( );
				createData( program, groupDescAddress, groupDescDataType );
				setPlateComment( program, groupDescAddress, "group descriptor: " + i );

				groupDescAddress = groupDescAddress.add( groupDescDataType.getLength( ) );
				monitor.incrementProgress( 1 );
			}

			boolean isSparseSuper = ( superBlock.getS_feature_ro_compat( ) & 1 ) != 0;
			createSuperBlockCopies( program, reader, groupSize, numGroups, is64Bit, isSparseSuper, monitor );

			createInodeTables( program, reader, superBlock, groupDescriptors, is64Bit, monitor );
			
	//		test(program, reader);
		}
		catch ( Exception e ) {
			throw e;
		}
		finally {
			if ( program2 != null ) {
				program2.endTransaction( transactionId2, true );
				program2 = null;
			}
			if ( program3 != null ) {
				program3.endTransaction( transactionId3, true );
				program3 = null;
			}
		}

		return true;
	}

	/**
	 * This method allows for EXT4 files larger than 2GB to be imported as 2 (or 3) separate programs.
	 * Then if both programs are opened (and have the same base name), then both will be analyzed. 
	 */
	private Program findOtherProgram( Program program, String suffix ) {
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager( program );
		ProgramManager programManager = manager.getAnalysisTool( ).getService( ProgramManager.class );
		Program [] openPrograms = programManager.getAllOpenPrograms( );
		for ( Program otherProgram : openPrograms ) {
			if ( program != otherProgram ) {
				if ( otherProgram.getName( ).startsWith( program.getName( ) ) && otherProgram.getName( ).endsWith( suffix ) ) {
					return otherProgram;
				}
			}
		}
		return null;// not using a 2nd program
	}

	@Override
	protected Data createData( Program program, Address address, DataType datatype ) throws Exception {
		if ( program.getMemory( ).contains( address ) ) {
			return super.createData( program, address, datatype );
		}
		if ( program2 != null && program2.getMemory( ).contains( address ) ) {
			return super.createData( program2, address, datatype );
		}
		throw new RuntimeException( "Cannot create data, neither program contains that address." );
	}

	@Override
	protected boolean setPlateComment( Program program, Address address, String comment ) {
		SetCommentCmd cmd = new SetCommentCmd( address, CodeUnit.PLATE_COMMENT, comment );
		if ( program.getMemory( ).contains( address ) ) {
			return cmd.applyTo( program );
		}
		if ( program2 != null && program2.getMemory( ).contains( address ) ) {
			return cmd.applyTo( program2 );
		}
		throw new RuntimeException( "Cannot set plate comment, neither program contains that address." );
	}

	private void createInodeTables( Program program, 
									BinaryReader reader, 
									Ext4SuperBlock superBlock, 
									Ext4GroupDescriptor [] groupDescriptors, 
									boolean is64Bit, 
									TaskMonitor monitor ) throws DuplicateNameException, Exception {
		
		int inodeCount = superBlock.getS_inodes_count( );
		Ext4Inode [] inodes = new Ext4Inode [ inodeCount ];
		int inodeIndex = 0;

		for ( int i = 0; i < groupDescriptors.length; i++ ) {
			monitor.checkCanceled( );
			long inodeTableBlockOffset = groupDescriptors[ i ].getBg_inode_table_lo( ) & 0xffffffffL;
			if ( is64Bit ) {
				inodeTableBlockOffset = ( groupDescriptors[ i ].getBg_inode_table_hi( ) << 32 ) | inodeTableBlockOffset;
			}
			long offset = inodeTableBlockOffset * blockSize;
			reader.setPointerIndex( offset );
			Address address = null;
			try {
				address = toAddr( program, offset );
			}
			catch ( Exception e ) {
				throw new IOException( "offset " + offset + " not in program." );
			}

			int inodesPerGroup = superBlock.getS_inodes_per_group( );
			monitor.setMessage( "Creating inode table " + i + " of " + ( groupDescriptors.length - 1 ) + "..." );
			monitor.setMaximum( inodesPerGroup );
			monitor.setProgress( 0 );
			for ( int j = 0; j < inodesPerGroup; j++ ) {
				monitor.checkCanceled( );

				Ext4Inode inode = new Ext4Inode( reader );
				DataType dataType = inode.toDataType( );
				createData( program, address, dataType );

				String comment = "Inode: 0x" + Integer.toHexString( inodeIndex + 1 ) + "\n";
				comment += "Group Descriptor ID: 0x" + Integer.toHexString( i ) + "\n";
				comment += "Inode Offset Into Group: 0x" + Integer.toHexString( j ) + "\n";

//				Ext4IBlock iBlock = inode.getI_block( );
//				if ( iBlock != null ) {
//					for ( Ext4Extent extent : iBlock.getExtentEntries( ) ) {
//						monitor.checkCanceled( );
//						long destination = extent.getExtentStartBlockNumber() * blockSize;
//						comment += "Extent: 0x" + Long.toHexString( destination ) + "\n";
//					}
//				}

				setPlateComment( program, address, comment );
				createLabel( program, address, "INODE_" + "0x" + Integer.toHexString( inodeIndex + 1 ) );
				address = address.add( superBlock.getS_inode_size( ) );
				reader.setPointerIndex( address.getOffset( ) );
				monitor.incrementProgress( 1 );
				inodes[ inodeIndex++ ] = inode; //inodes[ inodesPerGroup * i + j ] = inode;
			}
		}

		processInodes( program, reader, superBlock, inodes, monitor );
	}

	private void createLabel( Program program, Address address, String labelName ) throws Exception {
		if ( program.getMemory( ).contains( address ) ) {
			program.getSymbolTable( ).createLabel( address, labelName, SourceType.ANALYSIS );
			return;
		}
		if ( program2 != null && program2.getMemory( ).contains( address ) ) {
			program2.getSymbolTable( ).createLabel( address, labelName, SourceType.ANALYSIS );
			return;
		}
		throw new RuntimeException( "Cannot create label, neither program contains that address." );
	}

	private void processInodes(Program program, BinaryReader reader,
			Ext4SuperBlock superBlock, Ext4Inode[] inodes, TaskMonitor monitor) throws Exception {
		//first 0xa inodes are reserved (0 doesn't exist)
		for ( int i = 0x1; i < inodes.length; i++ ) {
			monitor.checkCanceled( );
			Ext4Inode inode = inodes[ i ];
			
			short mode = inode.getI_mode();
			if ( ( mode & Ext4Constants.S_IFDIR ) != 0 ) {
				processDirectory(program, reader, superBlock, inode, monitor );
			}
			else if ( (mode & Ext4Constants.S_IFREG ) != 0 ) {
				processFile( program, reader, superBlock, inode, monitor );
			} 
		}
	}

	private void processFile(Program program, 
							BinaryReader reader,
							Ext4SuperBlock superBlock, 
							Ext4Inode inode, 
							TaskMonitor monitor ) {
		// TODO?
	}

	private void processDirectory( Program program, 
									BinaryReader reader,
									Ext4SuperBlock superBlock, 
									Ext4Inode inode, 
									TaskMonitor monitor ) throws Exception {

		if ( (inode.getI_flags() & Ext4Constants.EXT4_INDEX_FL) != 0 ) {
			processHashTreeDirectory( program, reader, superBlock, inode, monitor );
		}
		boolean isDirEntry2 = (superBlock.getS_feature_incompat() & Ext4Constants.INCOMPAT_FILETYPE) != 0;
		// if uses extents
		if ( (inode.getI_flags() & Ext4Constants.EXT4_EXTENTS_FL) != 0 ) {
//			Ext4IBlock i_block = inode.getI_block();
//			processIBlock( program, reader, isDirEntry2, i_block, monitor );
		}
	}

	private void processIBlock( Program program,
								BinaryReader reader, 
								boolean isDirEntry2, 
								Ext4IBlock i_block,
								TaskMonitor monitor ) throws Exception {

		Ext4ExtentHeader header = i_block.getHeader();
		if ( header.getEh_depth() == 0 ) {//leaf node....
			short numEntries = header.getEh_entries();
			List<Ext4Extent> entries = i_block.getExtentEntries();
			for ( int i = 0; i < numEntries; i++ ) {
				Ext4Extent extent = entries.get( i );
				long offset = extent.getExtentStartBlockNumber() * blockSize;
				reader.setPointerIndex(offset);
				Address address = toAddr( program, offset );
				if ( isDirEntry2 ) {
					while ( ( reader.getPointerIndex( ) - offset ) < ( extent.getEe_len( ) * blockSize ) ) {
						Ext4DirEntry2 dirEnt2 = Ext4DirEntry2.read(reader);
						DataType dataType = dirEnt2.toDataType( );
						createData( program, address, dataType );
						String comment = "Name: " + dirEnt2.getName( ) + "\n";
						if ( dirEnt2.getFile_type( ) == Ext4Constants.FILE_TYPE_REGULAR_FILE ) {
							comment += "Type: REGULAR FILE" + "\n";
						}
						else if ( dirEnt2.getFile_type( ) == Ext4Constants.FILE_TYPE_DIRECTORY ) {
							comment += "Type: DIRECTORY" + "\n";
						}
						comment += "Type: INODE_0x" + Integer.toHexString( dirEnt2.getInode( ) );
						//TODO: add link to iNode using {@program program_name.exe@symbol_name}
						//TODO: add parent path to comment
						setPlateComment( program, address, comment );
						address = address.add( dataType.getLength( ) );
					}
				}
				else {
					throw new RuntimeException( "TODO: support old style dir entry" );
				}
			}
		}
		else {//interior node....
			short numEntries = header.getEh_entries( );
			List<Ext4ExtentIdx> entries = i_block.getIndexEntries();
			for ( int i = 0; i < numEntries; i++ ) {
				monitor.checkCanceled( );

				Ext4ExtentIdx extentIndex = entries.get( i );
				long lo = extentIndex.getEi_leaf_lo();
				long hi = extentIndex.getEi_leaf_hi();
				long physicalBlockOfNextLevel = ( hi << 32 ) | lo;
				long offset = physicalBlockOfNextLevel * blockSize;

				Address address = toAddr( program, offset );
				setPlateComment( program, address, "TODO Ext4ExtentIdx / ext4_fsblk_t  ???" );

				reader.setPointerIndex( offset );

				Ext4IBlock iBlock = new Ext4IBlock( reader, true );
				DataType dataType = iBlock.toDataType( );
				createData( program, address, dataType );

				processIBlock( program, reader, isDirEntry2, iBlock, monitor );
			}
		}
	}

	private void processHashTreeDirectory(	Program program, 
											BinaryReader reader,
											Ext4SuperBlock superBlock, 
											Ext4Inode inode, 
											TaskMonitor monitor ) {
		// TODO?
	}

	private void createSuperBlockCopies(Program program, 
										BinaryReader reader, 
										int groupSize, 
										int numGroups, 
										boolean is64Bit, 
										boolean isSparseSuper, 
										TaskMonitor monitor ) throws Exception {
		monitor.setMessage( "Creating super block and group descriptor copies..." );
		monitor.setMaximum(numGroups);
		for ( int i = 1; i < numGroups; i++ ) {
			monitor.checkCanceled();
			if( isSparseSuper && (!isXpowerOfY(i, 3) && !isXpowerOfY(i, 5) && !isXpowerOfY(i, 7)) ) {
				continue;
			}
			int offset = groupSize * i;
			Address address = toAddr(program, offset);
			reader.setPointerIndex(offset);
			Ext4SuperBlock superBlock = new Ext4SuperBlock(reader);
			createData(program, address, superBlock.toDataType());
			setPlateComment( program, address, "SuperBlock Copy 0x" + Integer.toHexString( i ) );

			long groupDescOffset = ( offset & 0xffffffffL ) + blockSize;
			Address groupDescAddress = toAddr(program, groupDescOffset);
			reader.setPointerIndex(groupDescOffset);
			for ( int j = 0; j < numGroups; j++ ) {

				Ext4GroupDescriptor groupDesc = new Ext4GroupDescriptor(reader, is64Bit);
				DataType groupDescDataType = groupDesc.toDataType();
				createData(program, groupDescAddress, groupDescDataType);
				setPlateComment( program, groupDescAddress, "SuperBlock Copy 0x" + Integer.toHexString( i ) + " Group 0x" + Integer.toHexString( j ) );

				groupDescAddress = groupDescAddress.add(groupDescDataType.getLength());			
			}
			monitor.incrementProgress(1);
		}
	}
	
	private boolean isXpowerOfY( int x, int y ) {
		if ( x == 0 ) {
			return false;
		}
		while ( x % y == 0 ) {
			x = x / y;
		}
		return x == 1;
	}

	private int calculateGroupSize( Ext4SuperBlock superBlock ) {
		int logBlockSize = superBlock.getS_log_block_size( );
		blockSize = ( int ) Math.pow( 2, 10 + logBlockSize );
		int groupSize = blockSize * superBlock.getS_blocks_per_group( );
		return groupSize;
	}

	private int getSuperBlockStart( BinaryReader reader ) {
		try {
			int padding = -1;
			int padStart = 0;
			boolean isPadding = false;
			while ( padStart < 1024 ) {
				if ( !isPadding ) {
					padStart = ( int ) reader.getPointerIndex( );
				}
				padding = reader.readNextInt( );
				if ( padding == 0 ) {
					if ( isPadding ) {
						return padStart + 0x400;
					}
					isPadding = true;
				}
				else {
					isPadding = false;
				}
			}
		}
		catch ( Exception e ) {
		}
		return -1;
	}
}
