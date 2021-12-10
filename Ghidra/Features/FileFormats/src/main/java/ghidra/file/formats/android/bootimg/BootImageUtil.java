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

import java.util.Arrays;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public final class BootImageUtil {

	public final static boolean isBootImage(Program program) {
		byte[] bytes = new byte[BootImageConstants.BOOT_MAGIC_SIZE];
		try {
			Address address = program.getMinAddress();
			program.getMemory().getBytes(address, bytes);
		}
		catch (Exception e) {
			//ignore
		}
		return Arrays.equals(bytes, BootImageConstants.BOOT_MAGIC.getBytes());
	}

	public final static boolean isBootImage(BinaryReader reader) {
		try {
			String magic = reader.readAsciiString(0, BootImageConstants.BOOT_MAGIC_SIZE);
			return BootImageConstants.BOOT_MAGIC.equals(magic);
		}
		catch (Exception e) {
			//ignore
		}
		return false;
	}

	public final static boolean isVendorBootImage(Program program) {
		byte[] bytes = new byte[BootImageConstants.VENDOR_BOOT_MAGIC_SIZE];
		try {
			Address address = program.getMinAddress();
			program.getMemory().getBytes(address, bytes);
		}
		catch (Exception e) {
			//ignore
		}
		return Arrays.equals(bytes, BootImageConstants.VENDOR_BOOT_MAGIC.getBytes());
	}

	public final static boolean isVendorBootImage(BinaryReader reader) {
		try {
			String magic = reader.readAsciiString(0, BootImageConstants.VENDOR_BOOT_MAGIC_SIZE);
			return BootImageConstants.VENDOR_BOOT_MAGIC.equals(magic);
		}
		catch (Exception e) {
			//ignore
		}
		return false;
	}

	public final static String getOSVersionString(int os_version) {
		int a = (os_version & 0xfe000000) >>> 25;
		int b = (os_version & 0x01fc0000) >>> 18;
		int c = (os_version & 0x0003f800) >>> 11;
		int y = (os_version & 0x000007f0) >>> 4;
		int m = (os_version & 0x0000000f);
		return a + "." + b + "." + c + "_" + y + "_" + m;
	}

}
