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
package ghidra.file.formats.ios.btree;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a User Data Record.
 * 
 * @see <a href="https://developer.apple.com/library/archive/technotes/tn/tn1150.html">User Data Record</a> 
 */
public class BTreeUserDataRecord implements StructConverter {

	private byte [] unused;

	BTreeUserDataRecord( BinaryReader reader ) throws IOException {
		this.unused  =  reader.readNextByteArray( 128 );
	}

	public byte [] getUnused() {
		return unused;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType( this );
	}
}
