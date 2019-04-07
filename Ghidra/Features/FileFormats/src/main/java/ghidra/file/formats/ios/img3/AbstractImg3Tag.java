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
package ghidra.file.formats.ios.img3;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.StringUtilities;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public abstract class AbstractImg3Tag implements StructConverter {
	protected BinaryReader _reader;

	protected int magic;
	protected int totalLength;
	protected int dataLength;

	protected AbstractImg3Tag(BinaryReader reader) throws IOException {
		this._reader = reader;

		magic        =  reader.readNextInt();
		totalLength  =  reader.readNextInt();
		dataLength   =  reader.readNextInt();
	}

	public String getMagic() {
		return StringUtilities.toString(magic);
	}
	public int getTotalLength() {
		return totalLength;
	}
	public int getDataLength() {
		return dataLength;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}

}
