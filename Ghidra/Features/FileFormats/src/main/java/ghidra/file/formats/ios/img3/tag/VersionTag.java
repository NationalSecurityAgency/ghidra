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
package ghidra.file.formats.ios.img3.tag;

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.ios.img3.AbstractImg3Tag;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class VersionTag extends AbstractImg3Tag {
	private int _length;
	private byte [] _versionString;

	VersionTag(BinaryReader reader) throws IOException {
		super(reader);

		_length = reader.readNextInt();
		_versionString = reader.readNextByteArray( _length );
	}

	public int getLength() {
		return _length;
	}

	public String getVersionString() {
		return new String( _versionString );
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = (Structure)super.toDataType();
		structure.add( DWORD, "length", null );
		structure.add( STRING, _length, "version", null );
		return structure;
	}
}
