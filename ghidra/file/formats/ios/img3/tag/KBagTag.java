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

import java.io.IOException;

public class KBagTag extends AbstractImg3Tag {
	public final static String MAGIC = "KBAG";

	public final static int AES_128  =  0x080;
	public final static int AES_192  =  0x0c0;
	public final static int AES_256  =  0x100;

	private int     iv_key_crypt_state;
	private int     aes_type;
	private byte [] enc_iv;
	private byte [] enc_key;

	KBagTag(BinaryReader reader) throws IOException {
		super(reader);

		iv_key_crypt_state  =  reader.readNextInt();
		aes_type            =  reader.readNextInt();
		enc_iv              =  reader.readNextByteArray(16);

		switch (aes_type) {
			case AES_128:
				enc_key     =  reader.readNextByteArray(16);
				break;
			case AES_192:
				enc_key     =  reader.readNextByteArray(24);
				break;
			case AES_256:
				enc_key     =  reader.readNextByteArray(32);
				break;
			default:
				throw new RuntimeException("unrecognized AES size: "+aes_type);
		}
	}

	public int getIVKeyCryptState() {
		return iv_key_crypt_state;
	}
	public int getAesType() {
		return aes_type;
	}
	public byte [] getEncryptionIV() {
		return enc_iv;
	}
	public byte [] getEncryptionKey() {
		return enc_key;
	}
}
