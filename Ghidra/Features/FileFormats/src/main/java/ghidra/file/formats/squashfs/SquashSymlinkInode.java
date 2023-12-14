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

import ghidra.app.util.bin.BinaryReader;

public class SquashSymlinkInode extends SquashInode {

	// The number of hard links to this inode
	private long linkCount;

	// The path to the link target (not null terminated when stored)
	private String targetPath;

	// Index into the xattr table
	private long xattrIndex;

	public SquashSymlinkInode(BinaryReader reader, SquashSuperBlock superBlock, boolean isExtended)
			throws IOException {
		super(reader, superBlock);

		linkCount = reader.readNextUnsignedInt();
		int targetSize = reader.readNextInt();
		targetPath = reader.readNextAsciiString(targetSize);

		if (isExtended) {
			xattrIndex = reader.readNextUnsignedInt();
		}
	}

	public long getLinkCount() {
		return linkCount;
	}

	public String getPath() {
		return targetPath;
	}

	public long getXattrIndex() {
		return xattrIndex;
	}
}
