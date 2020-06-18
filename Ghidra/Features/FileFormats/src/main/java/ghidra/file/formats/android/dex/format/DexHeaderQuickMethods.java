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
package ghidra.file.formats.android.dex.format;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

public final class DexHeaderQuickMethods {

	public static int getDexLength(BinaryReader reader) throws IOException {
		byte[] magic = reader.readNextByteArray(DexConstants.DEX_MAGIC_BASE.length());

		if (!DexConstants.DEX_MAGIC_BASE.equals(new String(magic))) {
			throw new IOException("not a dex file.");
		}

		byte[] version = reader.readNextByteArray(DexConstants.DEX_VERSION_LENGTH);

		int checksum = reader.readNextInt();

		byte[] signature = reader.readNextByteArray(20);

		int fileSize = reader.readNextInt();
		return fileSize;
	}

}
