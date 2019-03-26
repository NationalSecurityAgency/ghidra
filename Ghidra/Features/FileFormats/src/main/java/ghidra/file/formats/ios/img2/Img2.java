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
package ghidra.file.formats.ios.img2;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.StringUtilities;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class Img2 implements StructConverter {

	private int     signature;
	private int     imageType;
	private byte [] unknown0;
	private short   securityEpoch;
	private int     flags1;
	private int     dataLenPadded;
	private int     dataLen;
	private byte [] unknown1;
	private int     flags2;
	private byte [] reserved;
	private byte [] unknown2;
	private int     headerChecksum;
	private int     checksum2;
	private byte [] unknown3;

	public Img2(ByteProvider provider) throws IOException {
		this(new BinaryReader(provider, true));
	}

	public Img2(BinaryReader reader) throws IOException {
		signature       = reader.readNextInt();
		imageType       = reader.readNextInt();
		unknown0        = reader.readNextByteArray( 2 );
		securityEpoch   = reader.readNextShort();
		flags1          = reader.readNextInt();
		dataLenPadded   = reader.readNextInt();
		dataLen         = reader.readNextInt();
		unknown1        = reader.readNextByteArray( 4 );
		flags2          = reader.readNextInt();
		reserved        = reader.readNextByteArray( 0x40 );
		unknown2        = reader.readNextByteArray( 4 );
		headerChecksum  = reader.readNextInt();
		checksum2       = reader.readNextInt();
		unknown3        = reader.readNextByteArray( 0x394 );
	}

	public String getSignature() {
		return StringUtilities.toString(signature);
	}
	public String getImageType() {
		return StringUtilities.toString(imageType);
	}
	public short getSecurityEpoch() {
		return securityEpoch;
	}
	public int getFlags1() {
		return flags1;
	}
	public int getDataLenPadded() {
		return dataLenPadded;
	}
	public int getDataLen() {
		return dataLen;
	}
	public int getFlags2() {
		return flags2;
	}
	public byte [] getReserved() {
		return reserved;
	}
	public int getHeaderChecksum() {
		return headerChecksum;
	}
	public int getChecksum2() {
		return checksum2;
	}
	public byte [] getUnknown(int index) {
		switch (index) {
			case 0: return unknown0;
			case 1: return unknown1;
			case 2: return unknown2;
			case 3: return unknown3;
		}
		throw new RuntimeException("invalid unknown index");
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}
}
