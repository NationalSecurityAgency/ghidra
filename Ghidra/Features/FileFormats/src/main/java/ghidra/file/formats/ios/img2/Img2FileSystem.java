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
package ghidra.file.formats.ios.img2;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;

//@formatter:off
@FileSystemInfo(
	type = "img2",
	description = "iOS " + Img2Constants.IMG2_SIGNATURE, 
	factory = Img2FileSystemFactory.class)
//@formatter:on
public class Img2FileSystem extends AbstractSinglePayloadFileSystem {

	private ByteProvider containerProvider;

	public Img2FileSystem(FSRLRoot fsFSRL, ByteProvider payloadProvider, String payloadFilename,
			FileAttributes attrs, ByteProvider containerProvider) {
		super(fsFSRL, payloadProvider, payloadFilename, attrs);
	}

	@Override
	public void close() throws IOException {
		super.close();
		FSUtilities.uncheckedClose(containerProvider, null);
	}
}
