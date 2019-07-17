/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.commands.DyldInfoCommand;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.io.ByteArrayInputStream;

abstract public class AbstractDyldInfoProcessor {
	protected MachHeader header;
	protected Program program;
	protected ByteProvider provider;
	protected DyldInfoCommand command;

	protected AbstractDyldInfoProcessor( MachHeader header, Program program, ByteProvider provider, DyldInfoCommand command ) {
		super();
		this.header = header;
		this.program = program;
		this.provider = provider;
		this.command = command;
	}

	abstract public void process( TaskMonitor monitor ) throws Exception;

	/**
	 * Unsigned Little-endian Base-128
	 */
	protected long uleb128( ByteArrayInputStream byteStream, TaskMonitor monitor ) throws Exception {
		long result = 0;
		int  bit    = 0;

		while ( !monitor.isCancelled() ) {

			int value = byteStream.read();

			if ( value == -1 ) {
				break;
			}

			byte b = (byte) value;

			long slice = b & 0x7f;

			if ( ( b & 0x80 ) == 0x80 ) {//if upper bit is set
				if ( bit >= 64 || slice << bit >> bit != slice ) {//then left shift and right shift
					throw new RuntimeException( "uleb128 too big" );
				}
			}

			result |= ( slice << bit );
			bit += 7;

			if ( ( b & 0x80 ) == 0 ) {//if upper bit NOT set, then we are done
				break;
			}
		}
		return result;
	}

	/**
	 * Signed Little-endian Base-128
	 */
	protected long sleb128( ByteArrayInputStream byteStream, TaskMonitor monitor ) throws Exception {
		long result = 0;
		int  bit    = 0;
		while ( !monitor.isCancelled() ) {

			int value = byteStream.read();

			if ( value == -1 ) {
				break;
			}

			byte nextByte = (byte) value;

			result |= ( ( nextByte & 0x7f ) << bit );
			bit += 7;

			if ( ( nextByte & 0x80 ) == 0 ) {
				break;
			}
		}
		return result;
	}

	protected String readString( ByteArrayInputStream byteStream, TaskMonitor monitor ) {
		StringBuffer buffer = new StringBuffer();
		while ( !monitor.isCancelled() ) {
			int value = byteStream.read();
			if ( value == -1 ) {
				break;
			}
			byte b = (byte) value;
			if ( b == '\0' ) {
				break;
			}
			buffer.append( (char) ( b & 0xff ) );
		}
		return buffer.toString();
	}

}
