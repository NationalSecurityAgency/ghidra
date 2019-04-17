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
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class NSString extends NSObject {

	private String string;
	private NSStringTypes type;

	public NSString( String string, NSStringTypes type ) {
		this.string = string;
		this.type = type;
	}

	@Override
	public String getType() {
		return "NSString";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType( "NSString_" + string.length( ), 0 );
		addHeader( structure, string.length( ) );
		if ( string.length( ) > 0 ) {
			if ( type == NSStringTypes.TYPE_ASCII ) {
				structure.add( STRING, string.length( ), "ascii", null );
			}
			else if ( type == NSStringTypes.TYPE_UTF16BE ) {
				structure.add( UTF16, string.length( ) * 2, "utf16be", null );
			}
			else {
				throw new RuntimeException( );
			}
		}

		return structure;
	}

	@Override
	public String toString() {
		return string;
	}
}
