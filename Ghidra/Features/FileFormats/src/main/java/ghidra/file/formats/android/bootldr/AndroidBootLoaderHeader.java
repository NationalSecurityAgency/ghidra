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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Class to represent the Android boot loader header.
 *
 */
public class AndroidBootLoaderHeader implements StructConverter {

	private String magic;
	private int numberOfImages;
	private int startOffset;
	private int bootLoaderSize;
	private List<AndroidBootLoaderImageInfo> imageInfoList =
		new ArrayList<AndroidBootLoaderImageInfo>();

	public AndroidBootLoaderHeader(BinaryReader reader) throws IOException {
		magic = reader.readNextAsciiString(AndroidBootLoaderConstants.BOOTLDR_MAGIC_SIZE);
		numberOfImages = reader.readNextInt();
		startOffset = reader.readNextInt();
		bootLoaderSize = reader.readNextInt();
		for (int i = 0; i < numberOfImages; ++i) {
			imageInfoList.add(new AndroidBootLoaderImageInfo(reader));
		}
	}

	public String getMagic() {
		return magic;
	}

	public int getNumberOfImages() {
		return numberOfImages;
	}

	public int getStartOffset() {
		return startOffset;
	}

	public int getBootLoaderSize() {
		return bootLoaderSize;
	}

	public List<AndroidBootLoaderImageInfo> getImageInfoList() {
		return new ArrayList<AndroidBootLoaderImageInfo>(imageInfoList);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(
			AndroidBootLoaderConstants.BOOTLDR_NAME + "_" + numberOfImages, 0);
		struct.add(STRING, AndroidBootLoaderConstants.BOOTLDR_MAGIC_SIZE, "magic", null);
		struct.add(DWORD, "num_images", null);
		struct.add(DWORD, "start_offset", null);
		struct.add(DWORD, "bootldr_size", null);
		for (int i = 0; i < numberOfImages; ++i) {
			struct.add(imageInfoList.get(i).toDataType(), "img_info[" + i + "]", null);
		}
		return struct;
	}

}
