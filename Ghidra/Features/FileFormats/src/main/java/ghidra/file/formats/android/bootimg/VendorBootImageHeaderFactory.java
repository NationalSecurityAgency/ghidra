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

public final class VendorBootImageHeaderFactory {

	public final static VendorBootImageHeader getVendorBootImageHeader(ByteProvider provider,
			boolean littleEndian) throws IOException {
		return getVendorBootImageHeader(new BinaryReader(provider, littleEndian));
	}

	public final static VendorBootImageHeader getVendorBootImageHeader(BinaryReader reader)
			throws IOException {

		if (!BootImageUtil.isVendorBootImage(reader)) {
			throw new IOException("VendorBootImageHeader magic not found.");
		}

		int version = reader.readInt(BootImageConstants.VENDOR_BOOT_MAGIC_SIZE);

		switch (version) {
			case 3:
				return new VendorBootImageHeaderV3(reader);
			case 4:
				return new VendorBootImageHeaderV4(reader);
			default:
				throw new IOException(
					"VendorBootImageHeader unsupported version found: " + version);
		}
	}

}
