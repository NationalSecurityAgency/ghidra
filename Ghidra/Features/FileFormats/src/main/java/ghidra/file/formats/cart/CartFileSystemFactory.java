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
package ghidra.file.formats.cart;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * File system factory for the CaRT format (Version 1). Probe to quickly
 * determine if proposed data appears to be CaRT format and provide the
 * appropriate file system object back.
 */
public class CartFileSystemFactory
		implements GFileSystemFactoryByteProvider<CartFileSystem>, GFileSystemProbeByteProvider {

	@Override
	public CartFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {

		CartFileSystem fs = null;

		try {
			fs = new CartFileSystem(targetFSRL, fsService);
			fs.mount(byteProvider, monitor);
			return fs;
		}
		catch (IOException | CancelledException e) {
			FSUtilities.uncheckedClose(fs, null);
			throw e;
		}
	}

	@Override
	public boolean probe(ByteProvider byteProvider, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {

		// Quickly and efficiently examine the bytes in 'byteProvider' to determine if
		// it's a valid CaRT file system. If it is, return true.
		if (CartV1File.isCart(byteProvider)) {
			return true;
		}
		// If/when future CaRT file versions exist, check them here.

		// If we make it to the end without a match, return false
		return false;
	}
}
