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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.file.crypto.DecryptedPacket;
import ghidra.file.crypto.Decryptor;
import ghidra.file.formats.ios.generic.iOS_AesCrypto;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

public class Apple8900Decryptor implements Decryptor {

	public boolean isValid( ByteProvider provider ) throws IOException {
		byte [] bytes = provider.readBytes( 0, 4 );
		return Arrays.equals( bytes, Apple8900Constants.MAGIC_BYTES );
	}

	public DecryptedPacket decrypt( String firmwareName, String firmwarePath, ByteProvider provider, TaskMonitor monitor ) throws IOException, CryptoException {
		BinaryReader reader = new BinaryReader( provider, true );

		Apple8900Header header = new Apple8900Header( reader );

		if (!header.getMagic( ).equals( Apple8900Constants.MAGIC )) {
			throw new IOException( "The 8900 file is not valid!" );
		}

		byte [] encryptedBlock = reader.readNextByteArray( header.getSizeOfData( ) );

		if (header.isEncrypted( )) {
			iOS_AesCrypto crypto = new iOS_AesCrypto( Apple8900Constants.AES_KEY_BYTES, Apple8900Constants.AES_IV_ZERO_BYTES );

			byte [] decryptedBlock = crypto.decrypt( encryptedBlock );

			return new DecryptedPacket( new ByteArrayInputStream( decryptedBlock ), decryptedBlock.length );
		}
		return new DecryptedPacket(new ByteArrayInputStream(encryptedBlock), encryptedBlock.length);
	}

}
