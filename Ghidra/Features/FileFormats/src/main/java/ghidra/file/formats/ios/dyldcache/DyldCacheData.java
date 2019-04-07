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

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class DyldCacheData implements StructConverter{

	private long libraryOffset;
	private long unknown0;
	private long unknown1;
	private long fileOffset;

	private String _path;

	public DyldCacheData(BinaryReader reader) throws IOException {
		libraryOffset  = reader.readNextLong();
		unknown0       = reader.readNextLong();
		unknown1       = reader.readNextLong();
		fileOffset     = reader.readNextLong();

		_path = reader.readAsciiString( fileOffset );
	}

	public long getLibraryOffset() {
		return libraryOffset;
	}

	public long getFileOffset() {
		return fileOffset;
	}

	public long getUnknown(int index) {
		switch (index) {
			case 0: return unknown0;
			case 1: return unknown1;
		}
		return -1;
	}

	public String getPath() {
		return _path;
	}

 	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}
}
