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

import ghidra.program.model.data.*;
import ghidra.util.StringUtilities;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class NSData extends NSObject {

	private byte [] bytes;

	public NSData( byte [] bytes ) {
		this.bytes = bytes;
	}

	@Override
	public String getType() {
		return "NSData";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType( "NSData_" + bytes.length, 0 );
		addHeader( structure, bytes.length );
		if ( bytes.length > 0 ) {
			structure.add( new ArrayDataType( BYTE, bytes.length, BYTE.getLength( ) ), "data", null );
		}
		return structure;
	}

	@Override
	public String toString() {
		return StringUtilities.toQuotedString( bytes );
	}

	public byte [] getData() {
		return bytes;
	}

}
