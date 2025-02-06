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

import java.io.IOException;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.recognizer.*;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import net.sf.sevenzipjbinding.SevenZipNativeInitializationException;

public class SevenZipFileSystemFactory
		implements GFileSystemFactoryByteProvider<SevenZipFileSystem>, GFileSystemProbeBytesOnly {

	private List<Recognizer> recognizers = List.of(new SevenZipRecognizer(), new XZRecognizer(),
		new Bzip2Recognizer(), new MSWIMRecognizer(), new ArjRecognizer(), new CabarcRecognizer(),
		new CHMRecognizer(), new CramFSRecognizer(), new DebRecognizer(), new LhaRecognizer(),
		new RarRecognizer(), new RPMRecognizer(), new VHDRecognizer(), new XarRecognizer(),
		new UnixCompressRecognizer());

	private static boolean initFailed;
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
	public SevenZipFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {

		SevenZipFileSystem fs = new SevenZipFileSystem(targetFSRL, fsService);
		try {
			fs.mount(byteProvider, monitor);
			return fs;
		}
		catch (IOException ioe) {
			fs.close();
			throw ioe;
		}
	}

	/**
	 * Returns true if the native libraries for 7zip were initialized.
	 * 
	 * @return boolean true if 7zip dlls/libs/etc were successfully initialized
	 */
	public static boolean initNativeLibraries() {
		try {
			SevenZipCustomInitializer.initSevenZip();
			return true;
		}
		catch (SevenZipNativeInitializationException e) {
			if (!initFailed) {
				Msg.warn(SevenZipFileSystemFactory.class,
					"Sevenzip native libraries failed to initialize: " + e.getMessage());
				initFailed = true;
			}
			return false;
		}

	}

}
