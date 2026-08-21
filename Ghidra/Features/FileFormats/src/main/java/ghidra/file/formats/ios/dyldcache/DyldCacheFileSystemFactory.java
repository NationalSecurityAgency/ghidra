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
package ghidra.file.formats.ios.dyldcache;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.MachException;
import ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader;
import ghidra.app.util.opinion.DyldCacheUtils;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Factory to identify and create instances of a {@link DyldCacheFileSystem}
 */
public class DyldCacheFileSystemFactory implements
		GFileSystemFactoryByteProvider<DyldCacheFileSystem>, GFileSystemProbeByteProvider {

	@Override
	public DyldCacheFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {
		DyldCacheFileSystem fs = new DyldCacheFileSystem(targetFSRL, byteProvider);
		try {
			fs.mount(monitor);
			return fs;
		}
		catch (MachException e) {
			throw new IOException(e);
		}
	}

	@Override
	public boolean probe(ByteProvider byteProvider, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {
		if (!DyldCacheUtils.isDyldCache(byteProvider)) {
			return false;
		}
		try {
			DyldCacheHeader header = new DyldCacheHeader(new BinaryReader(byteProvider, true));
			return !header.isSubcache();
		}
		catch (IOException e) {
			return false;
		}
	}
}
