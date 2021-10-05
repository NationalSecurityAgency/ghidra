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
package ghidra.file.formats.ext4;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class Ext4FileSystemFactory
		implements GFileSystemProbeByteProvider, GFileSystemFactoryByteProvider<Ext4FileSystem> {

	@Override
	public Ext4FileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {

		Ext4FileSystem fs = new Ext4FileSystem(targetFSRL, byteProvider);
		fs.mountFS(monitor);

		return fs;
	}

	@Override
	public boolean probe(ByteProvider byteProvider, FileSystemService fsService,
			TaskMonitor taskMonitor) throws IOException, CancelledException {
		try {
			BinaryReader reader = new BinaryReader(byteProvider, true);
			//ext4 has a 1024 byte padding at the beginning
			reader.setPointerIndex(Ext4Constants.SUPER_BLOCK_START);
			Ext4SuperBlock superBlock = new Ext4SuperBlock(reader);
			return superBlock.isValid();
		}
		catch (IOException e) {
			// ignore
		}
		return false;
	}
}
