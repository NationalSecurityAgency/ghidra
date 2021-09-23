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
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/master/include/bootimg/bootimg.h#286
 * <pre>
 * The structure of the vendor boot image (introduced with version 3 and
 * required to be present when a v3 boot image is used) is as follows:
 *
 * +---------------------+
 * | vendor boot header  | o pages
 * +---------------------+
 * | vendor ramdisk      | p pages
 * +---------------------+
 * | dtb                 | q pages
 * +---------------------+
 * o = (2112 + page_size - 1) / page_size
 * p = (vendor_ramdisk_size + page_size - 1) / page_size
 * q = (dtb_size + page_size - 1) / page_size
 *
 * 0. all entities in the boot image are 4096-byte aligned in flash, all
 *    entities in the vendor boot image are page_size (determined by the vendor
 *    and specified in the vendor boot image header) aligned in flash
 * 1. kernel, ramdisk, vendor ramdisk, and DTB are required (size != 0)
 * 2. load the kernel and DTB at the specified physical address (kernel_addr,
 *    dtb_addr)
 * 3. load the vendor ramdisk at ramdisk_addr
 * 4. load the generic ramdisk immediately following the vendor ramdisk in
 *    memory
 * 5. set up registers for kernel entry as required by your architecture
 * 6. if the platform has a second stage bootloader jump to it (must be
 *    contained outside boot and vendor boot partitions), otherwise
 *    jump to kernel_addr
 * </pre>
 *
 */
public class VendorBootImageHeaderV3 extends VendorBootImageHeader {

	private String magic;
	private int header_version;
	private int page_size;
	private int kernel_addr;
	private int ramdisk_addr;
	private int vendor_ramdisk_size;
	private String cmdline;
	private int tags_addr;
	private String name;
	private int header_size;
	private int dtb_size;
	private long dtb_addr;

	public VendorBootImageHeaderV3(BinaryReader reader) throws IOException {
		magic = reader.readNextAsciiString(BootImageConstants.VENDOR_BOOT_MAGIC_SIZE);
		header_version = reader.readNextInt();
		page_size = reader.readNextInt();
		kernel_addr = reader.readNextInt();
		ramdisk_addr = reader.readNextInt();
		vendor_ramdisk_size = reader.readNextInt();
		cmdline = reader.readNextAsciiString(BootImageConstants.VENDOR_BOOT_ARGS_SIZE);
		tags_addr = reader.readNextInt();
		name = reader.readNextAsciiString(BootImageConstants.VENDOR_BOOT_NAME_SIZE);
		header_size = reader.readNextInt();
		dtb_size = reader.readNextInt();
		dtb_addr = reader.readNextLong();
	}

	public String getMagic() {
		return magic;
	}

	public int getHeaderVersion() {
		return header_version;
	}

	public int getPageSize() {
		return page_size;
	}

	public int getKernelAddress() {
		return kernel_addr;
	}

	public int getRamdiskAddress() {
		return ramdisk_addr;
	}

	public int getVendorRamdiskSize() {
		return vendor_ramdisk_size;
	}

	@Override
	public long getVendorRamdiskOffset() {
		return page_size;
	}

	public String getCmdline() {
		return cmdline;
	}

	public int getTagsAddress() {
		return tags_addr;
	}

	public String getName() {
		return name;
	}

	public int getHeaderSize() {
		return header_size;
	}

	public int getDtbSize() {
		return dtb_size;
	}

	public long getDtbAddress() {
		return dtb_addr;
	}

	@Override
	public long getDtbOffset() {
		int o = ((2112 + page_size - 1) / page_size);
		int p = ((vendor_ramdisk_size + page_size - 1) / page_size);
		return (o + p) * page_size;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("vendor_boot_img_hdr_v3", 0);
		structure.add(UTF8, BootImageConstants.VENDOR_BOOT_MAGIC_SIZE, "magic", null);
		structure.add(DWORD, "header_version", null);
		structure.add(DWORD, "page_size", null);
		structure.add(DWORD, "kernel_addr", null);
		structure.add(DWORD, "ramdisk_addr", null);
		structure.add(DWORD, "vendor_ramdisk_size", null);
		structure.add(UTF8, BootImageConstants.VENDOR_BOOT_ARGS_SIZE, "cmdline", null);
		structure.add(DWORD, "tags_addr", null);
		structure.add(UTF8, BootImageConstants.VENDOR_BOOT_NAME_SIZE, "name", null);
		structure.add(DWORD, "header_size", null);
		structure.add(DWORD, "dtb_size", null);
		structure.add(QWORD, "dtb_addr", null);
		return structure;
	}
}
