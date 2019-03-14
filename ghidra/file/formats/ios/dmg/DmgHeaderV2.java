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
package ghidra.file.formats.ios.dmg;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class DmgHeaderV2 extends DmgHeader {
	private byte [] signature;
	private int     version;
	private int     ivSize;
	private int     unknown0;
	private int     unknown1;
	private int     unknown2;
	private int     unknown3;
	private int     unknown4;
	private byte [] uuid;
	private int     blockSize;
	private long    dataSize;
	private long    dataOffset;

	public DmgHeaderV2(BinaryReader reader) throws IOException {
		if (reader.isLittleEndian()) {
			throw new IOException("binary reader must be BIG endian");
		}
		signature   =  reader.readNextByteArray( 0x8 );
		version     =  reader.readNextInt();
		ivSize      =  reader.readNextInt();
		unknown0    =  reader.readNextInt();
		unknown1    =  reader.readNextInt();
		unknown2    =  reader.readNextInt();
		unknown3    =  reader.readNextInt();
		unknown4    =  reader.readNextInt();
		uuid        =  reader.readNextByteArray( 0x10 );
		blockSize   =  reader.readNextInt();
		dataSize    =  reader.readNextLong();
		dataOffset  =  reader.readNextLong();
	}

	@Override
	public byte [] getSignature() {
		return signature;
	}
	public int getVersion() {
		return version;
	}
	public int getIvSize() {
		return ivSize;
	}
	public int getUnknown0() {
		return unknown0;
	}
	public int getUnknown1() {
		return unknown1;
	}
	public int getUnknown2() {
		return unknown2;
	}
	public int getUnknown3() {
		return unknown3;
	}
	public int getUnknown4() {
		return unknown4;
	}
	public byte[] getUUID() {
		return uuid;
	}
	public int getBlockSize() {
		return blockSize;
	}
	public long getDataOffset() {
		return dataOffset;
	}
	public long getDataSize() {
		return dataSize;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = (StructureDataType)StructConverterUtil.toDataType( this );
		DataTypeComponent component0 = struct.getComponent(0);
		struct.replace(0, new StringDataType(), component0.getLength());
		return struct;
	}
}
