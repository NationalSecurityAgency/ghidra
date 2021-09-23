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
package ghidra.file.formats.android.bootimg;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

public final class BootImageHeaderFactory {

	public final static BootImageHeader getBootImageHeader(ByteProvider provider,
			boolean littleEndian) throws IOException {
		return getBootImageHeader(new BinaryReader(provider, littleEndian));
	}

	public final static BootImageHeader getBootImageHeader(BinaryReader reader) throws IOException {

		if (!BootImageUtil.isBootImage(reader)) {
			throw new IOException("BootImageHeader magic not found.");
		}

		int version = reader.readInt(BootImageConstants.HEADER_VERSION_OFFSET);

		switch (version) {
			case 0:
				return new BootImageHeaderV0(reader);
			case 1:
				return new BootImageHeaderV1(reader);
			case 2:
				return new BootImageHeaderV2(reader);
			case 3:
				return new BootImageHeaderV3(reader);
			case 4:
				return new BootImageHeaderV4(reader);
			default:
				throw new IOException("BootImageHeader unsupported version found: " + version);
		}
	}

}
