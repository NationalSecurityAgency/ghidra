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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;

/**
 * https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/master/include/bootimg/bootimg.h#401
 * <pre>
 * The structure of the vendor boot image version 4, which is required to be
 * present when a version 4 boot image is used, is as follows:
 *
 * +------------------------+
 * | vendor boot header     | o pages
 * +------------------------+
 * | vendor ramdisk section | p pages
 * +------------------------+
 * | dtb                    | q pages
 * +------------------------+
 * | vendor ramdisk table   | r pages
 * +------------------------+
 * | bootconfig             | s pages
 * +------------------------+
 *
 * o = (2128 + page_size - 1) / page_size
 * p = (vendor_ramdisk_size + page_size - 1) / page_size
 * q = (dtb_size + page_size - 1) / page_size
 * r = (vendor_ramdisk_table_size + page_size - 1) / page_size
 * s = (vendor_bootconfig_size + page_size - 1) / page_size
 *
 * Note that in version 4 of the vendor boot image, multiple vendor ramdisks can
 * be included in the vendor boot image. The bootloader can select a subset of
 * ramdisks to load at runtime. To help the bootloader select the ramdisks, each
 * ramdisk is tagged with a type tag and a set of hardware identifiers
 * describing the board, soc or platform that this ramdisk is intended for.
 *
 * The vendor ramdisk section is consist of multiple ramdisk images concatenated
 * one after another, and vendor_ramdisk_size is the size of the section, which
 * is the total size of all the ramdisks included in the vendor boot image.
 *
 * The vendor ramdisk table holds the size, offset, type, name and hardware
 * identifiers of each ramdisk. The type field denotes the type of its content.
 * The hardware identifiers are specified in the board_id field in each table
 * entry. The board_id field is consist of a vector of unsigned integer words,
 * and the encoding scheme is defined by the hardware vendor.
 *
 * For the different type of ramdisks, there are:
 *    - VENDOR_RAMDISK_TYPE_NONE indicates the value is unspecified.
 *    - VENDOR_RAMDISK_TYPE_PLATFORM ramdisk contains platform specific bits.
 *    - VENDOR_RAMDISK_TYPE_RECOVERY ramdisk contains recovery resources.
 *    - VENDOR_RAMDISK_TYPE_DLKM ramdisk contains dynamic loadable kernel
 *      modules.
 *
 * Version 4 of the vendor boot image also adds a bootconfig section to the end
 * of the image. This section contains Boot Configuration parameters known at
 * build time. The bootloader is responsible for placing this section directly
 * after the generic ramdisk, followed by the bootconfig trailer, before
 * entering the kernel.
 *
 * 0. all entities in the boot image are 4096-byte aligned in flash, all
 *    entities in the vendor boot image are page_size (determined by the vendor
 *    and specified in the vendor boot image header) aligned in flash
 * 1. kernel, ramdisk, and DTB are required (size != 0)
 * 2. load the kernel and DTB at the specified physical address (kernel_addr,
 *    dtb_addr)
 * 3. load the vendor ramdisks at ramdisk_addr
 * 4. load the generic ramdisk immediately following the vendor ramdisk in
 *    memory
 * 5. load the bootconfig immediately following the generic ramdisk. Add
 *    additional bootconfig parameters followed by the bootconfig trailer.
 * 6. set up registers for kernel entry as required by your architecture
 * 7. if the platform has a second stage bootloader jump to it (must be
 *    contained outside boot and vendor boot partitions), otherwise
 *    jump to kernel_addr
 * </pre>
 *
 */
public class VendorBootImageHeaderV4 extends VendorBootImageHeaderV3 {

	private int vendor_ramdisk_table_size;
	private int vendor_ramdisk_table_entry_num;
	private int vendor_ramdisk_table_entry_size;
	private int bootconfig_size;

	public VendorBootImageHeaderV4(BinaryReader reader) throws IOException {
		super(reader);
		vendor_ramdisk_table_size = reader.readNextInt();
		vendor_ramdisk_table_entry_num = reader.readNextInt();
		vendor_ramdisk_table_entry_size = reader.readNextInt();
		bootconfig_size = reader.readNextInt();
	}

	/**
	 * Size in bytes for the vendor ramdisk table
	 * @return size in bytes for the vendor ramdisk table
	 */
	public int getVendorRamdiskTableSize() {
		return vendor_ramdisk_table_size;
	}

	/**
	 * Number of entries in the vendor ramdisk table
	 * @return number of entries in the vendor ramdisk table
	 */
	public int getVendorRamdiskTableEntryNum() {
		return vendor_ramdisk_table_entry_num;
	}

	/**
	 * Size in bytes for a vendor ramdisk table entry
	 * @return size in bytes for a vendor ramdisk table entry
	 */
	public int getVendorRamdiskTableEntrySize() {
		return vendor_ramdisk_table_entry_size;
	}

	/**
	 * Size in bytes for the bootconfig section
	 * @return size in bytes for the bootconfig section
	 */
	public int getBootConfigSize() {
		return bootconfig_size;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = (Structure) super.toDataType();
		try {
			structure.setName("vendor_boot_img_hdr_v4");
		}
		catch (InvalidNameException e) {
			//ignore
		}
		structure.add(DWORD, "vendor_ramdisk_table_size", null);
		structure.add(DWORD, "vendor_ramdisk_table_entry_num", null);
		structure.add(DWORD, "vendor_ramdisk_table_entry_size", null);
		structure.add(DWORD, "bootconfig_size", null);
		return structure;
	}
}
