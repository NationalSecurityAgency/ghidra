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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryFull;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeFull;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.IOException;

public class Ext4FileSystemFactory
		implements GFileSystemProbeFull, GFileSystemFactoryFull<Ext4FileSystem> {

	@Override
	public Ext4FileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL, ByteProvider byteProvider,
			File containerFile, FileSystemService fsService, TaskMonitor monitor)
					throws IOException, CancelledException {

		Ext4FileSystem fs = new Ext4FileSystem(targetFSRL, byteProvider);
		fs.mountFS(monitor);

		return fs;
	}

	@Override
	public boolean probe(FSRL containerFSRL, ByteProvider byteProvider, File containerFile,
			FileSystemService fsService, TaskMonitor taskMonitor)
					throws IOException, CancelledException {
		try {
			BinaryReader reader = new BinaryReader(byteProvider, true);
			//ext4 has a 1024 byte padding at the beginning
			reader.setPointerIndex(0x400);
			Ext4SuperBlock superBlock = new Ext4SuperBlock(reader);
			if ((superBlock.getS_magic() & 0xffff) == Ext4Constants.SUPER_BLOCK_MAGIC) {
				return true;
			}
		}
		catch (IOException e) {
			// ignore
		}
		return false;
	}
}
