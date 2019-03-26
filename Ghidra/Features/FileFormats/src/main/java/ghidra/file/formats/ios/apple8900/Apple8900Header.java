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
package ghidra.file.formats.ios.apple8900;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;
import utilities.util.ArrayUtilities;

public class Apple8900Header implements StructConverter {

	private byte[] magic;
	private byte[] version;
	private byte encrypted;
	private byte[] unknown0;
	private int sizeOfData;
	private int footerSignatureOffset;
	private int footerCertOffset;
	private int footerCertLength;
	private byte[] key1;
	private byte[] unknown1;
	private byte[] key2;
	private byte[] unknown2;

	public Apple8900Header(ByteProvider provider) throws IOException {
		this(new BinaryReader(provider, true));
	}

	public Apple8900Header(BinaryReader reader) throws IOException {
		magic = reader.readNextByteArray(0x4);
		version = reader.readNextByteArray(0x3);
		encrypted = reader.readNextByte();
		unknown0 = reader.readNextByteArray(0x4);
		sizeOfData = reader.readNextInt();
		footerSignatureOffset = reader.readNextInt();
		footerCertOffset = reader.readNextInt();
		footerCertLength = reader.readNextInt();
		key1 = reader.readNextByteArray(0x20);
		unknown1 = reader.readNextByteArray(0x4);
		key2 = reader.readNextByteArray(0x10);
		unknown2 = reader.readNextByteArray(0x7b0);
	}

	public String getMagic() {
		return new String(magic);
	}

	public String getVersion() {
		return new String(ArrayUtilities.reverse(version));
	}

	public boolean isEncrypted() {
		return encrypted == Apple8900Constants.FORMAT_ENCRYPTED;
	}

	public int getSizeOfData() {
		return sizeOfData;
	}

	public int getFooterSignatureOffset() {
		return footerSignatureOffset;
	}

	public int getFooterCertificateOffset() {
		return footerCertOffset;
	}

	public int getFooterCertificateLength() {
		return footerCertLength;
	}

	public byte[] getKey1() {
		return key1;
	}

	public byte[] getKey2() {
		return key2;
	}

	public byte[] getUnknown(int index) {
		switch (index) {
			case 0:
				return unknown0;
			case 1:
				return unknown1;
			case 2:
				return unknown2;
		}
		throw new RuntimeException("invalid unknown index");
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = (Structure) StructConverterUtil.toDataType(this);

		DataTypeComponent component0 = structure.getComponent(0);
		structure.replace(0, new StringDataType(), 4, component0.getFieldName(),
			component0.getComment());

		DataTypeComponent component1 = structure.getComponent(1);
		structure.replace(1, new StringDataType(), 3, component1.getFieldName(),
			component1.getComment());

		return structure;
	}

	public static byte[] reverse(byte[] array) {
		byte[] reversed = new byte[array.length];
		for (int i = 0; i < reversed.length; i++) {
			reversed[i] = array[array.length - 1 - i];
		}
		return reversed;
	}
}
