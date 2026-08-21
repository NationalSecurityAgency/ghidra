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
package ghidra.file.formats.lzfse;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;

/**
 * A {@link GFileSystem} implementation LZFSE compressed files
 * <p>
 * This implementation depends on a cmd line native binary lzfse (see 
 * {@link LzfseFileSystemFactory#ensureTool})
 * 
 * @see <a href="https://github.com/lzfse/lzfse">lzfse reference implementation</a> 
 */
@FileSystemInfo(type = "lzfse", description = "LZFSE", factory = LzfseFileSystemFactory.class, priority = FileSystemInfo.PRIORITY_HIGH)
public class LzfseFileSystem extends AbstractSinglePayloadFileSystem {

	/**
	 * Creates a new {@link LzfseFileSystem}.
	 * 
	 * @param fsFSRL This filesystem's {@link FSRLRoot}
	 * @param payloadProvider {@link ByteProvider}
	 * @param payloadFilename name of the single payload file
	 * @param payloadAttrs attributes of the payload file
	 */
	public LzfseFileSystem(FSRLRoot fsFSRL, ByteProvider payloadProvider, String payloadFilename,
			FileAttributes payloadAttrs) {
		super(fsFSRL, payloadProvider, payloadFilename, payloadAttrs);
	}

}
