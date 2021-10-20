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
package ghidra.file.formats.iso9660;

import java.io.IOException;
import java.util.Arrays;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ISO9660FileSystemFactory
		implements GFileSystemFactoryByteProvider<ISO9660FileSystem>, GFileSystemProbeByteProvider {
	private static final long[] SIGNATURE_PROBE_OFFSETS = new long[] { 0x8000L, 0x8800L, 0x9000L };

	@Override
	public boolean probe(ByteProvider byteProvider, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {

		for (long probeOffset : SIGNATURE_PROBE_OFFSETS) {
			if (isMagicSignatureAt(byteProvider, probeOffset + 1)) {
				return true;
			}
		}
		return false;
	}

	private boolean isMagicSignatureAt(ByteProvider provider, long offset) throws IOException {
		int magicLen = ISO9660Constants.MAGIC_BYTES.length;
		long providerLen = provider.length();
		return (providerLen > offset + magicLen) &&
			Arrays.equals(provider.readBytes(offset, magicLen), ISO9660Constants.MAGIC_BYTES);
	}

	@Override
	public ISO9660FileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {

		ISO9660FileSystem fs = new ISO9660FileSystem(targetFSRL, fsService);
		try {
			fs.mount(byteProvider, monitor);
			return fs;
		}
		catch (IOException ioe) {
			fs.close();
			throw ioe;
		}
	}

}
