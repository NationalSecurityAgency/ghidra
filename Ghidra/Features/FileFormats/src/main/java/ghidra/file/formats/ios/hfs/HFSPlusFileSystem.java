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
package ghidra.file.formats.ios.hfs;

import ghidra.file.formats.sevenzip.SevenZipFileSystem;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;

@FileSystemInfo(type = "hfsplus", description = "Apple HFS+ Disk Volume", factory = HFSPlusFileSystemFactory.class)
public class HFSPlusFileSystem extends SevenZipFileSystem {
	public HFSPlusFileSystem(FSRLRoot fsrl, FileSystemService fsService) {
		super(fsrl, fsService);
	}
}
