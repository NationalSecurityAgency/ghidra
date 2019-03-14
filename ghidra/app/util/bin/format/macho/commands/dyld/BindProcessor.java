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
package ghidra.app.util.bin.format.macho.commands.dyld;

import java.io.ByteArrayInputStream;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.commands.DyldInfoCommand;
import ghidra.app.util.bin.format.macho.commands.DyldInfoCommandConstants;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class BindProcessor extends AbstractDyldInfoProcessor {

	public BindProcessor( Program program, MachHeader header, ByteProvider provider, DyldInfoCommand command ) {
		super( header, program, provider, command );
	}

	@Override
	public void process( TaskMonitor monitor ) throws Exception {

		BindState bind = new BindState( header, program );

		boolean done = false;
		
		byte [] commandBytes = provider.readBytes( command.getBindOffset(), command.getBindSize() );
		ByteArrayInputStream byteServer = new ByteArrayInputStream( commandBytes );

		while ( !done ) {

			if ( monitor.isCancelled() ) {
				break;
			}

			int value = byteServer.read();

			if ( value == -1 ) {
				break;
			}

			byte b = (byte) value;

			int opcode    = b & DyldInfoCommandConstants.BIND_OPCODE_MASK;
			int immediate = b & DyldInfoCommandConstants.BIND_IMMEDIATE_MASK;

			switch ( opcode ) {
				case DyldInfoCommandConstants.BIND_OPCODE_ADD_ADDR_ULEB: {
					bind.segmentOffset += uleb128( byteServer, monitor );
					break;
				}
				case DyldInfoCommandConstants.BIND_OPCODE_DO_BIND: {
					bind.perform( monitor );
					bind.segmentOffset += program.getDefaultPointerSize();
					break;
				}
				case DyldInfoCommandConstants.BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: {
					bind.perform( monitor );
					bind.segmentOffset += ( immediate * program.getDefaultPointerSize() ) + program.getDefaultPointerSize();
					break;
				}
				case DyldInfoCommandConstants.BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: {
					bind.perform( monitor );
					bind.segmentOffset += uleb128( byteServer, monitor ) + program.getDefaultPointerSize();
					break;
				}
				case DyldInfoCommandConstants.BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
					long count = uleb128( byteServer, monitor );
					long skip  = uleb128( byteServer, monitor );
					for ( int i = 0 ; i < count ; ++i ) {
						if ( monitor.isCancelled() ) {
							break;
						}
						bind.perform( monitor );
						bind.segmentOffset += skip + program.getDefaultPointerSize();
					}
					break;
				}
				case DyldInfoCommandConstants.BIND_OPCODE_DONE: {
					done = true;
					break;
				}
				case DyldInfoCommandConstants.BIND_OPCODE_SET_ADDEND_SLEB: {
					bind.addend = sleb128( byteServer, monitor );
					break;
				}
				case DyldInfoCommandConstants.BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: {
					bind.libraryOrdinal = immediate;
					break;
				}
				case DyldInfoCommandConstants.BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: {
					bind.libraryOrdinal = (int) uleb128( byteServer, monitor );
					break;
				}
				case DyldInfoCommandConstants.BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: {
					//the special ordinals are negative numbers
					if ( immediate == 0 ) {
						bind.libraryOrdinal = 0;
					}
					else {
						byte signExtended = (byte) ( DyldInfoCommandConstants.BIND_OPCODE_MASK | immediate );
						bind.libraryOrdinal = signExtended;
					}
					break;
				}
				case DyldInfoCommandConstants.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: {
					bind.segmentIndex = immediate;
					bind.segmentOffset = uleb128( byteServer, monitor );
					break;
				}
				case DyldInfoCommandConstants.BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
					bind.symbolName = readString( byteServer, monitor );
					if ( ( immediate & DyldInfoCommandConstants.BIND_SYMBOL_FLAGS_WEAK_IMPORT ) != 0 ) {
						bind.setWeak( true );
					}
					else {
						bind.setWeak( false );
					}
					break;
				}
				case DyldInfoCommandConstants.BIND_OPCODE_SET_TYPE_IMM: {
					bind.type = immediate;
					break;
				}
				default: {
					throw new Exception(
						"Unknown dyld info bind opcode " + Integer.toHexString(opcode));
				}
			}
		}	
	}
}
