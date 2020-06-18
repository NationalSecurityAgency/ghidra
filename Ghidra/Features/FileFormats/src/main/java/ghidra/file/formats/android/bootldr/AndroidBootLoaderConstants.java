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
package ghidra.file.formats.android.bootldr;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;

/**
 * Source: https://android.googlesource.com/device/lge/mako/+/android-4.2.2_r1/releasetools.py
 * #
 * # #define BOOTLDR_MAGIC "BOOTLDR!"
 * # #define BOOTLDR_MAGIC_SIZE 8
 * #
 * # struct bootloader_images_header {
 * #         char magic[BOOTLDR_MAGIC_SIZE];
 * #         unsigned int num_images;
 * #         unsigned int start_offset;
 * #         unsigned int bootldr_size;
 * #         struct {
 * #                 char name[64];
 * #                 unsigned int size;
 * #         } img_info[];
 * # };
 */
public final class AndroidBootLoaderConstants {

	public static final String BOOTLDR_NAME = "bootloader_images_header";

	public static final String BOOTLDR_MAGIC = "BOOTLDR!";

	public static final int BOOTLDR_MAGIC_SIZE = BOOTLDR_MAGIC.length();

	public static final String IMG_INFO_NAME = "img_info";

	public static final int IMG_INFO_NAME_LENGTH = 64;

	public static boolean isBootLoader(Program program) {
		try {
			Memory memory = program.getMemory();
			byte[] bytes = new byte[AndroidBootLoaderConstants.BOOTLDR_MAGIC_SIZE];
			memory.getBytes(program.getMinAddress(), bytes);
			String magic = new String(bytes).trim();
			return AndroidBootLoaderConstants.BOOTLDR_MAGIC.equals(magic);
		}
		catch (Exception e) {
			//ignore
		}
		return false;
	}
}
