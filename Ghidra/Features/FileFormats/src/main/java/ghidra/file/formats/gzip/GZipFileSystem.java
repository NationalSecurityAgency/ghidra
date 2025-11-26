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
package ghidra.file.formats.gzip;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.AbstractSinglePayloadFileSystem;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;

/**
 * A pseudo-filesystem that contains a single file that represents the decompressed
 * contents of the Gzip file.
 * <p>
 * If the filename can be recovered from the embedded metadata, it will be used as the
 * name of the singleton file, otherwise the name "gzip_decompressed" will be used.
 */
@FileSystemInfo(type = "gzip", description = "GZIP", priority = FileSystemInfo.PRIORITY_LOW, factory = GZipFileSystemFactory.class)
public class GZipFileSystem extends AbstractSinglePayloadFileSystem {

	public GZipFileSystem(FSRLRoot fsFSRL, ByteProvider payloadProvider, String payloadFilename,
			FileAttributes payloadAttrs) {
		super(fsFSRL, payloadProvider, payloadFilename, payloadAttrs);
	}
}
