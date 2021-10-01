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
package ghidra.file.formats.zip;

import ghidra.file.formats.sevenzip.SevenZipFileSystem;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;

/**
 * Derivative of 7zip file system to provide "zip" flavored FSRLs.
 * <p>
 * 7Zip's features are superior to the native java zip handling (ie. passwords)
 */
@FileSystemInfo(type = "zip", description = "ZIP", factory = ZipFileSystemFactory.class, priority = FileSystemInfo.PRIORITY_HIGH)
public class ZipFileSystem extends SevenZipFileSystem {

	public ZipFileSystem(FSRLRoot fsrl, FileSystemService fsService) {
		super(fsrl, fsService);
	}

}
