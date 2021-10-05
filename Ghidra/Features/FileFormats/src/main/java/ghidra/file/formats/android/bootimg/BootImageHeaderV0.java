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
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/master/include/bootimg/bootimg.h#67
 */
public class BootImageHeaderV0 extends BootImageHeader {

	private String magic;
	private int kernel_size;
	private int kernel_addr;
	private int ramdisk_size;
	private int ramdisk_addr;
	private int second_size;
	private int second_addr;
	private int tags_addr;
	private int page_size;
	private int header_version;
	private int os_version;
	private String name;
	private String cmdline;
	private int[] id;
	private String extra_cmdline;

	public BootImageHeaderV0(BinaryReader reader) throws IOException {
		magic = reader.readNextAsciiString(BootImageConstants.BOOT_MAGIC_SIZE);
		kernel_size = reader.readNextInt();
		kernel_addr = reader.readNextInt();
		ramdisk_size = reader.readNextInt();
		ramdisk_addr = reader.readNextInt();
		second_size = reader.readNextInt();
		second_addr = reader.readNextInt();
		tags_addr = reader.readNextInt();
		page_size = reader.readNextInt();
		header_version = reader.readNextInt();
		os_version = reader.readNextInt();
		name = reader.readNextAsciiString(BootImageConstants.BOOT_NAME_SIZE);
		cmdline = reader.readNextAsciiString(BootImageConstants.BOOT_ARGS_SIZE);
		id = reader.readNextIntArray(BootImageConstants.ID_SIZE);
		extra_cmdline = reader.readNextAsciiString(BootImageConstants.BOOT_EXTRA_ARGS_SIZE);
	}

	@Override
	public String getMagic() {
		return magic;
	}

	@Override
	public int getKernelSize() {
		return kernel_size;
	}

	@Override
	public long getKernelOffset() {
		return page_size;//see header comment...
	}

	public int getKernelAddress() {
		return kernel_addr;
	}

	/**
	 * n = (kernel_size + page_size - 1) / page_size
	 */
	@Override
	public int getKernelPageCount() {
		return (int) (pageAlign(kernel_size) / page_size);
	}

	@Override
	public int getRamdiskSize() {
		return ramdisk_size;
	}

	@Override
	public int getRamdiskOffset() {
		return page_size + getKernelPageCount() * page_size;//see header comment...
	}

	public int getRamdiskAddress() {
		return ramdisk_addr;
	}

	/**
	 * m = (ramdisk_size + page_size - 1) / page_size
	 */
	@Override
	public int getRamdiskPageCount() {
		return (int) (pageAlign(ramdisk_size) / page_size);
	}

	@Override
	public int getSecondSize() {
		return second_size;
	}

	@Override
	public long getSecondOffset() {
		return page_size + (getKernelPageCount() + getRamdiskPageCount()) * page_size;//see header comment...
	}

	public int getSecondAddress() {
		return second_addr;
	}

	/**
	 * o = (second_size + page_size - 1) / page_size
	 */
	@Override
	public int getSecondPageCount() {
		return (int) (pageAlign(second_size) / page_size);
	}

	/**
	 * Physical address for kernel tags (if required)
	 * @return physical address for kernel tags
	 */
	public int getTagsAddress() {
		return tags_addr;
	}

	@Override
	public int getPageSize() {
		return page_size;
	}

	/**
	 * Version of the boot image header.
	 * @return version of the boot image header
	 */
	public int getHeaderVersion() {
		return header_version;
	}

	/**
	 * Operating system version and security patch level.
	 * For version "A.B.C" and patch level "Y-M-D":
	 * (7 bits for each of A, B, C; 7 bits for (Y-2000), 4 bits for M)
	 * os_version = A[31:25] B[24:18] C[17:11] (Y-2000)[10:4] M[3:0]
	 * @return OS version
	 */
	public int getOSVersion() {
		return os_version;
	}

	public String getName() {
		return name;
	}

	@Override
	public String getCommandLine() {
		return cmdline;
	}

	public int[] getId() {
		return id;
	}

	public String getExtraCommandLine() {
		return extra_cmdline;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("boot_img_hdr_v0", 0);
		structure.add(UTF8, BootImageConstants.BOOT_MAGIC_SIZE, "magic", null);
		structure.add(DWORD, "kernel_size", null);
		structure.add(DWORD, "kernel_addr", null);
		structure.add(DWORD, "ramdisk_size", null);
		structure.add(DWORD, "ramdisk_addr", null);
		structure.add(DWORD, "second_size", null);
		structure.add(DWORD, "second_addr", null);
		structure.add(DWORD, "tags_addr", null);
		structure.add(DWORD, "page_size", null);
		structure.add(DWORD, "header_version", null);
		structure.add(DWORD, "os_version", BootImageUtil.getOSVersionString(os_version));
		structure.add(UTF8, BootImageConstants.BOOT_NAME_SIZE, "name", null);
		structure.add(UTF8, BootImageConstants.BOOT_ARGS_SIZE, "cmdline", null);
		ArrayDataType array =
			new ArrayDataType(DWORD, BootImageConstants.ID_SIZE, DWORD.getLength());
		structure.add(array, "id", null);
		structure.add(UTF8, BootImageConstants.BOOT_EXTRA_ARGS_SIZE, "extra_cmdline", null);
		return structure;
	}

}
