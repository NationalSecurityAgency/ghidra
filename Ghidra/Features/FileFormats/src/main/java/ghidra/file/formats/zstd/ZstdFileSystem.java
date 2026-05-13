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
package ghidra.file.formats.zstd;

import ghidra.app.util.bin.ByteProvider;
import ghidra.file.formats.sevenzip.SevenZipCliToolWrapper;
import ghidra.formats.gfilesystem.AbstractSinglePayloadFileSystem;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;

/**
 * GFileSystem that decompresses a zstd file and presents the decompressed payload as the file
 * system's single file.
 * <p>
 * Depends on the user already having a zstd or 7zip cmd line tool installed somewhere within their 
 * operating system's PATH.
 * <p>
 * See {@link ZstdCliToolWrapper} and {@link SevenZipCliToolWrapper}.
 */
@FileSystemInfo(type = "zstd", description = "zStandard", factory = ZstdFileSystemFactory.class)
public class ZstdFileSystem extends AbstractSinglePayloadFileSystem {

	public ZstdFileSystem(FSRLRoot fsFSRL, ByteProvider payloadProvider, String payloadFilename,
			FileAttributes attrs) {
		super(fsFSRL, payloadProvider, payloadFilename, attrs);
	}
}
