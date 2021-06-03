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
package ghidra.file.formats.bplist;

import java.math.BigInteger;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.BigEndianDataConverter;
import ghidra.util.DataConverter;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class NSObject implements StructConverter {

	/**
	 * All data is stored BIG ENDIAN in a binary plist.
	 */
	protected DataConverter converter = BigEndianDataConverter.INSTANCE;

	public abstract String getType();

	public abstract String toString();

	protected void addHeader( Structure structure, int size ) {
		if ( size < 0xf ) {
			structure.add( BYTE, "objectDescriptor", null );
		}
		else if ( size < 0xff ) {
			structure.add( BYTE, "objectDescriptor", null );
			structure.add( BYTE, "indicator", null );
			structure.add( BYTE, "length", null );
		}
		else if ( size < 0xffff ) {
			structure.add( BYTE, "objectDescriptor", null );
			structure.add( BYTE, "indicator", null );
			structure.add( WORD, "length", null );
		}
		else {
			throw new RuntimeException( "unexpected size in " + getClass( ).getName( ) );
		}
	}

	public void markup(Data objectData, Program program, TaskMonitor monitor)
			throws CancelledException {

	}

	protected long getValue( Data component ) {
		try {
			byte [] bytes = component.getBytes( );
//			if ( bytes.length == 1 ) {
//				return bytes[ 0 ] & 0xffL;
//			}
//			else if ( bytes.length == 2 ) {
//				return converter.getShort( bytes ) & 0xffffL;
//			}
//			else if ( bytes.length == 4 ) {
//				return converter.getInt( bytes ) & 0xffffffffL;
//			}
//			else if ( bytes.length == 8 ) {
//				return converter.getLong( bytes );
//			}
//			else {
//				
//			}
			BigInteger bi = new BigInteger( bytes );
			return bi.longValue( );
		}
		catch ( MemoryAccessException e ) {

		}
		return -1;
	}
}
