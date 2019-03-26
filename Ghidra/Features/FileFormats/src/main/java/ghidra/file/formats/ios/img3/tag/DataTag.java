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
import ghidra.app.util.bin.ByteProviderPaddedInputStream;
import ghidra.file.crypto.CryptoKey;
import ghidra.file.crypto.CryptoKeyFactory;
import ghidra.file.formats.ios.generic.iOS_AesCrypto;
import ghidra.file.formats.ios.img3.AbstractImg3Tag;
import ghidra.util.exception.CryptoException;

import java.io.IOException;
import java.io.InputStream;

public class DataTag extends AbstractImg3Tag {
	private long _dataStartIndex;

	DataTag(BinaryReader reader) throws IOException {
		super(reader);
		_dataStartIndex = reader.getPointerIndex();
	}

	/**
	 * Returns an array contains the DATA. It
	 * will be padded as needed.
	 * @return an array of data
	 * @throws IOException
	 */
	public byte[] getData() throws IOException {
		byte[] data = _reader.readByteArray(_dataStartIndex, dataLength);

		int remainder = data.length % 0x10;

		if (remainder == 0) {
			return data;
		}

		byte[] padded = new byte[data.length + (0x10 - remainder)];

		System.arraycopy(data, 0, padded, 0, data.length);

		return padded;
	}

	public long getLengthWithPadding() {
		int remainder = dataLength % 0x10;
		return dataLength + (0x10 - remainder);
	}

	public InputStream getDataAsInputStream() {
		return new ByteProviderPaddedInputStream(_reader.getByteProvider(), _dataStartIndex,
			dataLength, 16 - (dataLength % 16));
	}

	public InputStream getDecryptedInputStream(String containerName, String img3Name)
			throws CryptoException {
		CryptoKey cryptoKey = CryptoKeyFactory.getCryptoKey(containerName, img3Name);
		if (cryptoKey == CryptoKey.NOT_ENCRYPTED_KEY) {
			return getDataAsInputStream();
		}

		iOS_AesCrypto aes = new iOS_AesCrypto(cryptoKey.key, cryptoKey.iv);
		return aes.decrypt(getDataAsInputStream());

	}
}
