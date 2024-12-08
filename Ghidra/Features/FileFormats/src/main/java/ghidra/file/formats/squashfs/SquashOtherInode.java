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
package ghidra.file.formats.squashfs;

import java.io.IOException;
import java.util.HexFormat;

import ghidra.app.util.bin.BinaryReader;

public class SquashOtherInode extends SquashInode {

	// The number of hard links to this inode
	private long linkCount;

	// The size of the target path in bytes
	private int targetSize;

	// Index into the xattr table
	private long xattrIndex;

	// System specific device number (on Linux, this contains both a major and a minor device number)
	// major = (deviceNumber & 0xFFF00) >> 8
	// minor = (deviceNumber & 0x000FF)
	private long deviceNumber;

	/**
	 * Represents a SquashFS basic file inode
	 * @param reader A binary reader with pointer index at the start of the inode data
	 * @param superBlock The SuperBlock for the current archive
	 * @param inodeType The type of the inode
	 * @throws IOException Any read operation failure
	 */
	public SquashOtherInode(BinaryReader reader, SquashSuperBlock superBlock, int inodeType)
			throws IOException {

		// Assign common inode header values
		super(reader, superBlock);
		switch (inodeType) {
			case SquashConstants.INODE_TYPE_BASIC_BLOCK_DEVICE:
			case SquashConstants.INODE_TYPE_BASIC_CHAR_DEVICE:
				linkCount = reader.readNextUnsignedInt();
				deviceNumber = reader.readNextUnsignedInt();
				break;
			case SquashConstants.INODE_TYPE_EXTENDED_BLOCK_DEVICE:
			case SquashConstants.INODE_TYPE_EXTENDED_CHAR_DEVICE:
				linkCount = reader.readNextUnsignedInt();
				deviceNumber = reader.readNextUnsignedInt();
				xattrIndex = reader.readNextUnsignedInt();
				break;
			case SquashConstants.INODE_TYPE_BASIC_FIFO:
			case SquashConstants.INODE_TYPE_BASIC_SOCKET:
				linkCount = reader.readNextUnsignedInt();
				break;
			case SquashConstants.INODE_TYPE_EXTENDED_FIFO:
			case SquashConstants.INODE_TYPE_EXTENDED_SOCKET:
				linkCount = reader.readNextUnsignedInt();
				xattrIndex = reader.readNextUnsignedInt();
				break;
			default:
				throw new IOException(
					"Unknown inode type: 0x" + HexFormat.of().toHexDigits(inodeType));
		}
	}

	public long getLinkCount() {
		return linkCount;
	}

	public int getTargetSize() {
		return targetSize;
	}

	public long getXattrIndex() {
		return xattrIndex;
	}

	public long getDeviceNumber() {
		return deviceNumber;
	}

}
