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

/**
 * 
 * https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/master/include/bootimg/bootimg.h
 * 
 */
public final class BootImageConstants {

	public final static String BOOT_MAGIC = "ANDROID!";
	public final static int BOOT_MAGIC_SIZE = 8;
	public final static int BOOT_NAME_SIZE = 16;
	public final static int BOOT_ARGS_SIZE = 512;
	public final static int BOOT_EXTRA_ARGS_SIZE = 1024;

	public final static int ID_SIZE = 8;

	public final static int V3_HEADER_SIZE = 4096;
	public final static int V3_PAGE_SIZE = 4096;
	public final static int V4_HEADER_SIZE = V3_HEADER_SIZE;
	public final static int V4_PAGE_SIZE = V3_PAGE_SIZE;

	public final static String VENDOR_BOOT_MAGIC = "VNDRBOOT";
	public final static int VENDOR_BOOT_MAGIC_SIZE = 8;
	public final static int VENDOR_BOOT_ARGS_SIZE = 2048;
	public final static int VENDOR_BOOT_NAME_SIZE = 16;

	public final static int VENDOR_RAMDISK_TYPE_NONE = 0;
	public final static int VENDOR_RAMDISK_TYPE_PLATFORM = 1;
	public final static int VENDOR_RAMDISK_TYPE_RECOVERY = 2;
	public final static int VENDOR_RAMDISK_TYPE_DLKM = 3;
	public final static int VENDOR_RAMDISK_NAME_SIZE = 32;
	public final static int VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE = 16;

	public final static String SECOND_STAGE = "second stage";
	public final static String RAMDISK = "ramdisk";
	public final static String KERNEL = "kernel";
	public final static String DTB = "dtb";

	public final static int HEADER_VERSION_OFFSET = 0x28;
}
