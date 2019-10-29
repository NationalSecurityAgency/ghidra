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
package ghidra.file.formats.sevenzip;

import java.io.File;
import java.io.IOException;
import java.util.List;

import ghidra.app.util.recognizer.*;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryWithFile;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SevenZipFileSystemFactory
		implements GFileSystemFactoryWithFile<SevenZipFileSystem>, GFileSystemProbeBytesOnly {

	private List<Recognizer> recognizers = List.of(new SevenZipRecognizer(), new XZRecognizer(),
		new Bzip2Recognizer(), new MSWIMRecognizer(), new ArjRecognizer(), new CabarcRecognizer(),
		new CHMRecognizer(), new CramFSRecognizer(), new DebRecognizer(), new LhaRecognizer(),
		new RarRecognizer(), new RPMRecognizer(), new VHDRecognizer(), new XarRecognizer(),
		new UnixCompressRecognizer());

	private final int recognizerBytesRequired;

	public SevenZipFileSystemFactory() {
		int max = 0;
		for (Recognizer recognizer : recognizers) {
			max = Math.max(max, recognizer.numberOfBytesRequired());
		}
		recognizerBytesRequired = max;
	}

	@Override
	public int getBytesRequired() {
		return recognizerBytesRequired;
	}

	@Override
	public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
		for (Recognizer recognizer : recognizers) {
			String recognized = recognizer.recognize(startBytes);
			if (recognized != null) {
				return true;
			}
		}
		return false;
	}

	@Override
	public SevenZipFileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL, File containerFile,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {

		SevenZipFileSystem fs = new SevenZipFileSystem(targetFSRL);
		try {
			fs.mount(containerFile, monitor);
			return fs;
		}
		catch (IOException ioe) {
			fs.close();
			throw ioe;
		}
	}

}
