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
package ghidra.file.formats.sparseimage;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.AbstractSinglePayloadFileSystem;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;

/**
 * A pseudo filesystem that contains a single file that is the decompressed contents
 * of the sparse container file.
 */
@FileSystemInfo(type = "simg", description = "Android Sparse Image (simg)", factory = SparseImageFileSystemFactory.class)
public class SparseImageFileSystem extends AbstractSinglePayloadFileSystem {


	public SparseImageFileSystem(FSRLRoot fsFSRL, ByteProvider payloadProvider,
			String payloadFilename, FileAttributes attrs) {
		super(fsFSRL, payloadProvider, payloadFilename, attrs);
	}
}
