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
package ghidra.file.formats.omf51;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.omf.AbstractOmfRecordFactory;
import ghidra.app.util.bin.format.omf.OmfException;
import ghidra.app.util.bin.format.omf.omf51.Omf51LibraryHeaderRecord;
import ghidra.app.util.bin.format.omf.omf51.Omf51RecordFactory;
import ghidra.app.util.opinion.Omf51Loader;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class Omf51ArchiveFileSystemFactory implements
		GFileSystemFactoryByteProvider<Omf51ArchiveFileSystem>, GFileSystemProbeByteProvider {

	@Override
	public Omf51ArchiveFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {

		Omf51ArchiveFileSystem fs = new Omf51ArchiveFileSystem(targetFSRL, byteProvider);
		try {
			fs.mount(monitor);
		}
		catch (OmfException e) {
			throw new IOException(e);
		}
		return fs;
	}

	@Override
	public boolean probe(ByteProvider byteProvider, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {

		if (byteProvider.length() < Omf51Loader.MIN_BYTE_LENGTH) {
			return false;
		}

		try {
			AbstractOmfRecordFactory factory = new Omf51RecordFactory(byteProvider);
			return factory.readNextRecord() instanceof Omf51LibraryHeaderRecord;
		}
		catch (OmfException | IOException e) {
			return false;
		}
	}
}
