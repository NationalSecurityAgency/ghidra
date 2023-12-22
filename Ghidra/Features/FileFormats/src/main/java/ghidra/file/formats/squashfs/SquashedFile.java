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

public class SquashedFile {

	// The name of this file/directory
	private final String name;

	// The path to this file/directory
	private final String filePath;

	// The inode representing this file/directory
	private final SquashInode inode;

	// The fragment holding the tail end of the file (null if not)
	private final SquashFragment fragment;

	// The total uncompressed size of the file (-1 for directories)
	private final long size;

	/**
	 * Represents a file or directory within a SquashFS archive
	 * @param fileInode The inode representing this file/directory
	 * @param tailEndFragment Fragment holding the tail end of the file
	 */
	public SquashedFile(SquashInode fileInode, SquashFragment tailEndFragment) {

		name = fileInode.getDirectoryTableEntry().getFileName();
		filePath = fileInode.getDirectoryTableEntry().getPath();
		inode = fileInode;
		fragment = tailEndFragment;

		if (inode.isFile()) {
			SquashBasicFileInode castInode = (SquashBasicFileInode) inode;
			size = castInode.getFileSize();
		}
		else {
			size = -1;
		}
	}

	public String getName() {
		return name;
	}

	public String getPath() {
		return filePath;
	}

	public SquashInode getInode() {
		return inode;
	}

	public long getUncompressedSize() {
		return size;
	}

	public boolean hasFragment() {
		return fragment != null;
	}

	public SquashFragment getFragment() {
		return fragment;
	}
}
