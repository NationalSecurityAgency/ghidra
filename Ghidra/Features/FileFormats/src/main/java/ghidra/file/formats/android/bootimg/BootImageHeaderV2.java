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
 * https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/master/include/bootimg/bootimg.h#199
 */
public class BootImageHeaderV2 extends BootImageHeaderV1 {

	private int dtb_size;
	private long dtb_addr;

	public BootImageHeaderV2(BinaryReader reader) throws IOException {
		super(reader);
		dtb_size = reader.readNextInt();
		dtb_addr = reader.readNextLong();
	}

	/**
	 * Size in bytes for DTB image
	 * @return size in bytes for DTB image
	 */
	public int getDtbSize() {
		return dtb_size;
	}

	/**
	 * q = (dtb_size + page_size - 1) / page_size
	 * @return the DTB adjusted size, as page counts
	 */
	public int getDtbSizeAdjusted() {
		return (int) (pageAlign(Integer.toUnsignedLong(dtb_size)) / getPageSize());
	}

	/**
	 * Physical load address for DTB image
	 * @return physical load address for DTB image
	 */
	public long getDtbAddress() {
		return dtb_addr;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = (Structure) super.toDataType();
		try {
			structure.setName("boot_img_hdr_v2");
		}
		catch (InvalidNameException e) {
			//ignore
		}
		structure.add(DWORD, "dtb_size", null);
		structure.add(QWORD, "dtb_addr", null);
		return structure;
	}

}
