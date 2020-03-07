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
package ghidra.file.formats.ios.dyldcache;

import java.io.*;
import java.util.*;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.bin.format.macho.commands.*;
import ghidra.formats.gfilesystem.GFile;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class FixupMacho32bitArmOffsets {
	private DataConverter converter = LittleEndianDataConverter.INSTANCE;

	public InputStream fix(GFile file, long offsetAdjustment, ByteProvider provider,
			TaskMonitor monitor) throws IOException, MachException {
		Map<Long, byte []> changeMap = new HashMap<Long, byte []>();

		//check to make sure mach-o header is valid
		MachHeader header = MachHeader.createMachHeader( RethrowContinuesFactory.INSTANCE, provider, offsetAdjustment, false );
		header.parse();

		//fix up index, offsets, etc in the header
		List<LoadCommand> commands = header.getLoadCommands();
		for ( LoadCommand loadCommand : commands ) {
			if ( monitor.isCancelled() ) {
				break;
			}
			switch ( loadCommand.getCommandType() ) {
				case LoadCommandTypes.LC_SEGMENT: {
					SegmentCommand segmentCommand = (SegmentCommand) loadCommand;
					if ( segmentCommand.getFileOffset() > 0 ) {
						long newOffset = segmentCommand.getFileOffset() - offsetAdjustment;
						changeMap.put( segmentCommand.getStartIndex() + 0x20 - offsetAdjustment, converter.getBytes( (int)newOffset ) );
					}
					if ( segmentCommand.getNumberOfSections() > 0 ) {
						long sectionStartIndex = segmentCommand.getStartIndex() + 0x38 - offsetAdjustment;
						for ( Section section : segmentCommand.getSections() ) {
							if ( monitor.isCancelled() ) {
								break;
							}
							if ( section.getOffset() > 0  && section.getOffset() > offsetAdjustment ) {
								long newOffset = Conv.intToLong( section.getOffset() ) - offsetAdjustment;
								changeMap.put( sectionStartIndex + 0x28, converter.getBytes( (int)newOffset ) );
							}
							if ( section.getRelocationOffset() > 0 && section.getRelocationOffset() > offsetAdjustment ) {
								long newOffset = Conv.intToLong( section.getRelocationOffset() ) - offsetAdjustment;
								changeMap.put( sectionStartIndex + 0x30, converter.getBytes( (int)newOffset ) );
							}
							try {
								sectionStartIndex += section.toDataType().getLength();
							}
							catch ( DuplicateNameException e ) {
								throw new IOException( e );
							}
						}
					}
					break;
				}
				case LoadCommandTypes.LC_SYMTAB: {
					SymbolTableCommand symbolTableCommand = (SymbolTableCommand) loadCommand;
					if ( symbolTableCommand.getSymbolOffset() > 0 ) {
						long newOffset = Conv.intToLong( symbolTableCommand.getSymbolOffset() ) - offsetAdjustment;
						changeMap.put( symbolTableCommand.getStartIndex() + 0x8 - offsetAdjustment, converter.getBytes( (int)newOffset ) );
					}
					if ( symbolTableCommand.getStringTableOffset() > 0 ) {
						long newOffset = Conv.intToLong( symbolTableCommand.getStringTableOffset() ) - offsetAdjustment;
						changeMap.put( symbolTableCommand.getStartIndex() + 0x10 - offsetAdjustment, converter.getBytes( (int)newOffset ) );
					}
					break;
				}
				case LoadCommandTypes.LC_DYSYMTAB: {
					DynamicSymbolTableCommand dynamicSymbolTableCommand = (DynamicSymbolTableCommand) loadCommand;
					if ( dynamicSymbolTableCommand.getTableOfContentsOffset() > 0 ) {
						long newOffset = Conv.intToLong( dynamicSymbolTableCommand.getTableOfContentsOffset() ) - offsetAdjustment;
						changeMap.put( dynamicSymbolTableCommand.getStartIndex() + 0x20 - offsetAdjustment, converter.getBytes( (int)newOffset ) );
					}
					if ( dynamicSymbolTableCommand.getModuleTableOffset() > 0 ) {
						long newOffset = Conv.intToLong( dynamicSymbolTableCommand.getModuleTableOffset() ) - offsetAdjustment;
						changeMap.put( dynamicSymbolTableCommand.getStartIndex() + 0x28 - offsetAdjustment, converter.getBytes( (int)newOffset ) );
					}
					if ( dynamicSymbolTableCommand.getReferencedSymbolTableOffset() > 0 ) {
						long newOffset = Conv.intToLong( dynamicSymbolTableCommand.getReferencedSymbolTableOffset() ) - offsetAdjustment;
						changeMap.put( dynamicSymbolTableCommand.getStartIndex() + 0x30 - offsetAdjustment, converter.getBytes( (int)newOffset ) );
					}
					if ( dynamicSymbolTableCommand.getIndirectSymbolTableOffset() > 0 ) {
						long newOffset = Conv.intToLong( dynamicSymbolTableCommand.getIndirectSymbolTableOffset() ) - offsetAdjustment;
						changeMap.put( dynamicSymbolTableCommand.getStartIndex() + 0x38 - offsetAdjustment, converter.getBytes( (int)newOffset ) );
					}
					if ( dynamicSymbolTableCommand.getExternalRelocationOffset() > 0 ) {
						long newOffset = Conv.intToLong( dynamicSymbolTableCommand.getExternalRelocationOffset() ) - offsetAdjustment;
						changeMap.put( dynamicSymbolTableCommand.getStartIndex() + 0x40 - offsetAdjustment, converter.getBytes( (int)newOffset ) );
					}
					if ( dynamicSymbolTableCommand.getLocalRelocationOffset() > 0 ) {
						long newOffset = Conv.intToLong( dynamicSymbolTableCommand.getLocalRelocationOffset() ) - offsetAdjustment;
						changeMap.put( dynamicSymbolTableCommand.getStartIndex() + 0x48 - offsetAdjustment, converter.getBytes( (int)newOffset ) );
					}
					break;
				}
				case LoadCommandTypes.LC_DYLD_INFO:
				case LoadCommandTypes.LC_DYLD_INFO_ONLY: {
					DyldInfoCommand dyldInfoCommand = (DyldInfoCommand) loadCommand;
					if ( dyldInfoCommand.getRebaseOffset() > 0 ) {
						long newOffset = Conv.intToLong( dyldInfoCommand.getRebaseOffset() ) - offsetAdjustment;
						changeMap.put( dyldInfoCommand.getStartIndex() + 0x8 - offsetAdjustment, converter.getBytes( (int)newOffset ) );
					}
					if ( dyldInfoCommand.getBindOffset() > 0 ) {
						long newOffset = Conv.intToLong( dyldInfoCommand.getBindOffset() ) - offsetAdjustment;
						changeMap.put( dyldInfoCommand.getStartIndex() + 0x10 - offsetAdjustment, converter.getBytes( (int)newOffset ) );
					}
					if ( dyldInfoCommand.getWeakBindOffset() > 0 ) {
						long newOffset = Conv.intToLong( dyldInfoCommand.getWeakBindOffset() ) - offsetAdjustment;
						changeMap.put( dyldInfoCommand.getStartIndex() + 0x18 - offsetAdjustment, converter.getBytes( (int)newOffset ) );
					}
					if ( dyldInfoCommand.getLazyBindOffset() > 0 ) {
						long newOffset = Conv.intToLong( dyldInfoCommand.getLazyBindOffset() ) - offsetAdjustment;
						changeMap.put( dyldInfoCommand.getStartIndex() + 0x20 - offsetAdjustment, converter.getBytes( (int)newOffset ) );
					}
					if ( dyldInfoCommand.getExportOffset() > 0 ) {
						long newOffset = Conv.intToLong(dyldInfoCommand.getExportOffset() ) - offsetAdjustment;
						changeMap.put( dyldInfoCommand.getStartIndex() + 0x28 - offsetAdjustment, converter.getBytes( (int)newOffset ) );
					}
					break;
				}
			}
		}

		List<Long> indexList = new ArrayList<Long>( changeMap.keySet() );
		Collections.sort( indexList );
		
		ByteArrayOutputStream tempOut = new ByteArrayOutputStream();
		try {
			long tempIndex = offsetAdjustment;
			while ( !monitor.isCancelled() ) {
				final int length = 0x10000;
				byte [] buffer = provider.readBytes( tempIndex, length );

				for ( Long index : indexList ) {
					if ( index + offsetAdjustment >= tempIndex && index + offsetAdjustment < tempIndex + length ) {
						byte [] changedBytes = changeMap.get( index );
						System.arraycopy( changedBytes, 0, buffer, index.intValue(), changedBytes.length );
					}
				}

				tempOut.write( buffer );
				tempIndex += buffer.length;
				monitor.setMessage( "0x" + Long.toHexString( tempIndex ) );
				if ( tempIndex > provider.length() ) {
					break;
				}
			}
		}
		finally {
			tempOut.close();
		}

		return new ByteArrayInputStream(tempOut.toByteArray());
	}
}
