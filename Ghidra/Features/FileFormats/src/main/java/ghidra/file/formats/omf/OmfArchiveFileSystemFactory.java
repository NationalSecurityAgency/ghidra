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
package ghidra.file.formats.omf;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.omf.AbstractOmfRecordFactory;
import ghidra.app.util.bin.format.omf.OmfException;
import ghidra.app.util.bin.format.omf.omf.OmfLibraryRecord;
import ghidra.app.util.bin.format.omf.omf.OmfRecordFactory;
import ghidra.app.util.opinion.OmfLoader;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class OmfArchiveFileSystemFactory implements
		GFileSystemFactoryByteProvider<OmfArchiveFileSystem>, GFileSystemProbeByteProvider {

	@Override
	public OmfArchiveFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {

		OmfArchiveFileSystem fs = new OmfArchiveFileSystem(targetFSRL, byteProvider);
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

		if (byteProvider.length() < OmfLoader.MIN_BYTE_LENGTH) {
			return false;
		}

		try {
			AbstractOmfRecordFactory factory = new OmfRecordFactory(byteProvider);
			return OmfLibraryRecord.checkMagicNumber(factory.getReader());
		}
		catch (IOException e) {
			return false;
		}
	}
}
