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
 * https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/master/include/bootimg/bootimg.h#250
 */
public class BootImageHeaderV3 extends BootImageHeader {

	private String magic;
	private int kernel_size;
	private int ramdisk_size;
	private int os_version;
	private int header_size;
	private int[] reserved;// 4 elements
	private int header_version;
	private String cmdline;

	public BootImageHeaderV3(BinaryReader reader) throws IOException {
		magic = reader.readNextAsciiString(BootImageConstants.BOOT_MAGIC_SIZE);
		kernel_size = reader.readNextInt();
		ramdisk_size = reader.readNextInt();
		os_version = reader.readNextInt();
		header_size = reader.readNextInt();
		reserved = reader.readNextIntArray(4);
		header_version = reader.readNextInt();
		cmdline = reader.readNextAsciiString(
			BootImageConstants.BOOT_ARGS_SIZE + BootImageConstants.BOOT_EXTRA_ARGS_SIZE);
	}

	@Override
	public String getMagic() {
		return magic;
	}

	@Override
	public int getPageSize() {
		return BootImageConstants.V3_PAGE_SIZE;
	}

	@Override
	public int getKernelSize() {
		return kernel_size;
	}

	/**
	 * n = (kernel_size + page_size - 1) / page_size
	 */
	@Override
	public int getKernelPageCount() {
		return (int)(pageAlign(kernel_size) / BootImageConstants.V3_PAGE_SIZE);
	}

	@Override
	public long getKernelOffset() {
		return BootImageConstants.V3_PAGE_SIZE;//see header comment...
	}

	@Override
	public int getRamdiskSize() {
		return ramdisk_size;
	}

	/**
	 * m = (ramdisk_size + page_size - 1) / page_size
	 */
	@Override
	public int getRamdiskPageCount() {
		return (int) (pageAlign(Integer.toUnsignedLong(ramdisk_size)) /
			BootImageConstants.V3_PAGE_SIZE);
	}

	@Override
	public int getRamdiskOffset() {
		return BootImageConstants.V3_PAGE_SIZE +
			(getKernelPageCount() * BootImageConstants.V3_PAGE_SIZE);
	}

	@Override
	public long getSecondOffset() {
		// v3 does not contain 2nd stage, just return 0
		return 0;
	}

	@Override
	public int getSecondSize() {
		// v3 does not contain 2nd stage, just return 0
		return 0;
	}

	@Override
	public int getSecondPageCount() {
		// v3 does not contain 2nd stage, just return 0
		return 0;
	}

	public int getOSVersion() {
		return os_version;
	}

	public int getHeaderSize() {
		return header_size;
	}

	public int[] getReserved() {
		return reserved;
	}

	public int getHeaderVersion() {
		return header_version;
	}

	@Override
	public String getCommandLine() {
		return cmdline;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("boot_img_hdr_v3", 0);
		structure.add(UTF8, BootImageConstants.BOOT_MAGIC_SIZE, "magic", null);
		structure.add(DWORD, "kernel_size", null);
		structure.add(DWORD, "ramdisk_size", null);
		structure.add(DWORD, "os_version", BootImageUtil.getOSVersionString(os_version));
		structure.add(DWORD, "header_size", null);
		ArrayDataType array = new ArrayDataType(DWORD, 4, DWORD.getLength());
		structure.add(array, "reserved", null);
		structure.add(DWORD, "header_version", null);
		structure.add(UTF8,
			BootImageConstants.BOOT_ARGS_SIZE + BootImageConstants.BOOT_EXTRA_ARGS_SIZE, "cmdline",
			null);
		return structure;
	}

}
