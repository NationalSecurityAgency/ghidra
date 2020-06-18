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
 * https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/master/include/bootimg/bootimg.h#397
 */
public class BootImageHeaderV4 extends BootImageHeaderV3 {

	private int signature_size;

	public BootImageHeaderV4(BinaryReader reader) throws IOException {
		super(reader);
	}

	public int getSignatureSize() {
		return signature_size;
	}

	@Override
	public int getPageSize() {
		return BootImageConstants.V4_PAGE_SIZE;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = (Structure) super.toDataType();
		try {
			structure.setName("boot_img_hdr_v4");
		}
		catch (InvalidNameException e) {
			//ignore
		}
		structure.add(DWORD, "signature_size", null);
		return structure;
	}

}
