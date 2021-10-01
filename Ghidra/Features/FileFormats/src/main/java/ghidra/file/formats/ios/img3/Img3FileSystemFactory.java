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
package ghidra.file.formats.ios.img3;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.ArrayUtilities;

public class Img3FileSystemFactory
		implements GFileSystemFactoryByteProvider<Img3FileSystem>, GFileSystemProbeBytesOnly {
	@Override
	public int getBytesRequired() {
		return Img3Constants.IMG3_SIGNATURE_LENGTH;
	}

	@Override
	public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
		return ArrayUtilities.arrayRangesEquals(startBytes, 0, Img3Constants.IMG3_SIGNATURE_BYTES,
			0, Img3Constants.IMG3_SIGNATURE_LENGTH);
	}

	@Override
	public Img3FileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {
		return new Img3FileSystem(targetFSRL, byteProvider, fsService, monitor);
	}

}
