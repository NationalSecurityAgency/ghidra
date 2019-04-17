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
package ghidra.file.formats.ios.ibootim;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class iBootImHeader implements StructConverter {

	private byte [] signature;
	private int unknown;
	private int compressionType;
	private int format;
	private short width;
	private short height;
	private byte [] padding;

	public iBootImHeader(ByteProvider provider) throws IOException {
		BinaryReader reader = new BinaryReader(provider, true);

		signature        =  reader.readNextByteArray( iBootImConstants.SIGNATURE_LENGTH );
		unknown          =  reader.readNextInt();
		compressionType  =  reader.readNextInt();
		format           =  reader.readNextInt();
		width            =  reader.readNextShort();
		height           =  reader.readNextShort();
		padding          =  reader.readNextByteArray( iBootImConstants.PADDING_LENGTH );
	}

	public String getSignature() {
		return new String(signature).trim();
	}
	public int getUnknown() {
		return unknown;
	}
	public int getCompressionType() {
		return compressionType;
	}
	public int getFormat() {
		return format;
	}
	public short getWidth() {
		return width;
	}
	public short getHeight() {
		return height;
	}
	public byte[] getPadding() {
		return padding;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(StructConverterUtil.parseName(iBootImHeader.class), 0);
		struct.add(STRING, iBootImConstants.SIGNATURE_LENGTH, "signature", null);
		struct.add(DWORD, "unknown", null);
		struct.add(DWORD, "compression", null);
		struct.add(DWORD, "format", null);
		struct.add(WORD, "width", null);
		struct.add(WORD, "height", null);
		DataType paddingDataType = new ArrayDataType(BYTE, iBootImConstants.PADDING_LENGTH, BYTE.getLength());
		struct.add(paddingDataType, "padding", null);
		return struct;
	}
}
