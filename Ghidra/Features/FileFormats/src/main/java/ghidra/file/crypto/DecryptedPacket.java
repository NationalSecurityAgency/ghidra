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
package ghidra.file.crypto;

import java.io.*;

public class DecryptedPacket {
	public final File decryptedFile;
	public final InputStream decryptedStream;
	public final int decryptedStreamLength;

	public DecryptedPacket(File decryptedFile) {
		this.decryptedFile = decryptedFile;
		this.decryptedStream = null;
		this.decryptedStreamLength = -1;
	}

	public DecryptedPacket(InputStream decryptedStream, int decryptedStreamLength) {
		this.decryptedFile = null;
		this.decryptedStream = decryptedStream;
		this.decryptedStreamLength = decryptedStreamLength;
	}

	public void dispose() {
		try {
			decryptedStream.close();
		}
		catch (IOException e) {/* don't care */}
	}

}
