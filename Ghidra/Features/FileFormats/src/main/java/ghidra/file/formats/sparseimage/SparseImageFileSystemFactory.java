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

import java.io.File;
import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryWithFile;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeFull;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SparseImageFileSystemFactory
		implements GFileSystemFactoryWithFile<SparseImageFileSystem>, GFileSystemProbeFull {

	@Override
	public SparseImageFileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL, File containerFile,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {

		return new SparseImageFileSystem(targetFSRL, containerFSRL, fsService, monitor);
	}

	@Override
	public boolean probe(FSRL containerFSRL, ByteProvider byteProvider, File containerFile,
			FileSystemService fsService, TaskMonitor taskMonitor)
			throws IOException, CancelledException {

		BinaryReader reader = new BinaryReader(byteProvider, true);
		SparseHeader header = new SparseHeader(reader);
		return header.getMagic() == SparseConstants.SPARSE_HEADER_MAGIC;

	}

}
