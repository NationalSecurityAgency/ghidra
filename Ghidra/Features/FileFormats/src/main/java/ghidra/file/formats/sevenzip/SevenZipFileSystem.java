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

import java.io.*;
import java.util.*;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.recognizer.*;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;
import net.sf.sevenzipjbinding.*;
import net.sf.sevenzipjbinding.impl.RandomAccessFileInStream;
import net.sf.sevenzipjbinding.simple.ISimpleInArchive;
import net.sf.sevenzipjbinding.simple.ISimpleInArchiveItem;

@FileSystemInfo(type = "7zip", description = "7Zip", factory = GFileSystemBaseFactory.class)
public class SevenZipFileSystem extends GFileSystemBase {

	private static final Recognizer[] RECOGNIZERS =
		new Recognizer[] { new SevenZipRecognizer(), new XZRecognizer(), new Bzip2Recognizer(),
			//new GzipRecognizer(),
			//new TarRecognizer(),
			//new PkzipRecognizer(),
			new MSWIMRecognizer(), new ArjRecognizer(), new CabarcRecognizer(), new CHMRecognizer(),
			//new CpioRecognizer(),
			new CramFSRecognizer(), new DebRecognizer(),
			//new DmgRecognizer(),
			//new ISO9660Recognizer(),
			new LhaRecognizer(), new RarRecognizer(), new RPMRecognizer(), new VHDRecognizer(),
			new XarRecognizer(), new UnixCompressRecognizer() };

	private static final int MAX_BYTES;

	static {
		int max = 0;
		for (Recognizer recognizer : RECOGNIZERS) {
			int numberOfBytesRequired = recognizer.numberOfBytesRequired();
			if (numberOfBytesRequired > max) {
				max = numberOfBytesRequired;
			}
		}
		MAX_BYTES = max;
	}

	private Map<GFile, ISimpleInArchiveItem> map = new HashMap<>();
	private IInArchive archive;
	private ISimpleInArchive archiveInterface;
	private RandomAccessFile randomAccessFile;

	public SevenZipFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		try {
			byte[] bytes = provider.readBytes(0, MAX_BYTES);
			for (Recognizer recognizer : RECOGNIZERS) {
				String recognized = recognizer.recognize(bytes);
				if (recognized != null) {
					return true;
				}
			}
		}
		catch (IOException e) {
			// we squash exceptions here...not sure why we'd get an
			// IOException...maybe permissions or something
		}
		return false;
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {
		monitor.setMessage("Opening ZIP...");

		try {
			if (openFile(monitor)) {
				return;
			}
		}
		catch (SevenZipException e) {
			Msg.warn(this, "Problem opening 7-Zip archive", e);
			throw new IOException(e);
		}
		if (openInputStream(monitor)) {
			return;
		}
		throw new IOException("Unable to open zip file system.");
	}

	private boolean openFile(TaskMonitor monitor) throws FileNotFoundException, SevenZipException {
		File file = provider.getFile();
		if (file != null) {
			randomAccessFile = new RandomAccessFile(file, "r");
			archive = SevenZip.openInArchive(null, new RandomAccessFileInStream(randomAccessFile));
			archiveInterface = archive.getSimpleInterface();

			ISimpleInArchiveItem[] items = archiveInterface.getArchiveItems();
			for (ISimpleInArchiveItem item : items) {
				if (monitor.isCancelled()) {
					break;
				}
				storeEntry(item, monitor);
			}
			return true;
		}
		return false;
	}

	private void storeEntry(ISimpleInArchiveItem entry, TaskMonitor monitor)
			throws SevenZipException {
		String path = entry.getPath();
		monitor.setMessage(path);
		GFileImpl file =
			GFileImpl.fromPathString(this, root, path, null, entry.isFolder(), getSize(entry));
		storeFile(file, entry);
	}

	private void storeFile(GFile file, ISimpleInArchiveItem entry) {
		if (file == null) {
			return;
		}
		if (file.equals(root)) {
			return;
		}
		if (!map.containsKey(file) || map.get(file) == null) {
			map.put(file, entry);
		}
		GFile parentFile = file.getParentFile();
		storeFile(parentFile, null);
	}

	// at least until we implement it
	private boolean openInputStream(TaskMonitor monitor) {
		// TODO: is there any way 7Zip will let us work with a stream?
		// moreover: will we ever be handed a stream???
		return false;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		if (directory == null || directory.equals(root)) {
			List<GFile> roots = new ArrayList<>();
			for (GFile file : map.keySet()) {
				if (file.getParentFile() == root || file.getParentFile().equals(root)) {
					roots.add(file);
				}
			}
			return roots;
		}
		List<GFile> tmp = new ArrayList<>();
		for (GFile file : map.keySet()) {
			if (file.getParentFile() == null) {
				continue;
			}
			if (file.getParentFile().equals(directory)) {
				tmp.add(file);
			}
		}
		return tmp;
	}

	@Override
	public String getInfo(GFile file, TaskMonitor monitor) throws IOException {
		ISimpleInArchiveItem entry = map.get(file);
		StringBuffer buffer = new StringBuffer();
		try {
			buffer.append("Path: " + entry.getPath() + "\n");
			buffer.append("Folder?: " + entry.isFolder() + "\n");
			buffer.append("Encrypted?: " + entry.isEncrypted() + "\n");
			buffer.append("Comment: " + entry.getComment() + "\n");
			final Long packedSize = entry.getPackedSize();
			buffer.append("Compressed Size: " +
				(packedSize == null ? "(null)" : " 0x" + Long.toHexString(packedSize)) + "\n");
			buffer.append("Uncompressed Size: 0x" + getSize(entry) + "\n");
			final Integer crc = entry.getCRC();
			buffer.append(
				"CRC: " + (crc == null ? "(null)" : " 0x" + Long.toHexString(crc)) + "\n");
			buffer.append("Compression Method: " + entry.getMethod() + "\n");
			buffer.append("Time: " + entry.getCreationTime() + "\n");
		}
		catch (SevenZipException e) {
			Msg.warn(this, "7-Zip exception trying to get info on item", e);
		}
		return buffer.toString();
	}

	@Override
	protected InputStream getData(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {

		ISimpleInArchiveItem entry = map.get(file);

		if (entry == null) {
			return null;
		}

		try {
			if (entry.isFolder()) {
				throw new IOException(file.getName() + " is a directory");
			}
		}
		catch (SevenZipException e) {
			throw new IOException("trying to test if " + file + " is a folder", e);
		}

		if (archiveInterface != null) {

			MySequentialOutStream sequentialOutputStream = new MySequentialOutStream();

			try {
				entry.extractSlow(sequentialOutputStream);
			}
			catch (SevenZipException e1) {
				throw new IOException(e1);
			}

			try {
				ExtractOperationResult operationResult = entry.extractSlow(sequentialOutputStream);

				if (operationResult == null) {
					throw new IOException("7-Zip returned null operation result");
				}

				switch (operationResult) {
					case CRCERROR: {
						throw new IOException("7-Zip returned CRC error");
					}
					case DATAERROR: {
						throw new IOException("7-Zip returned data error");
					}
					case UNSUPPORTEDMETHOD: {
						throw new IOException("Unexpected: 7-Zip returned unsupported method");
					}
					case UNKNOWN_OPERATION_RESULT: {
						throw new IOException(
							"Unexpected: 7-Zip returned unknown operation result");
					}
					case OK:
					default: {
						// it's all ok!
					}
				}
			}
			catch (SevenZipException e) {
				Throwable cause = e.getCause();
				if (cause != null && cause instanceof IOException) {
					throw (IOException) cause;
				}
				if (cause != null && cause instanceof CancelledException) {
					throw (CancelledException) cause;
				}
				throw new IOException("7-Zip exception", e);
			}

			return sequentialOutputStream.getData();
		}

		return null;
	}

	private int getSize(ISimpleInArchiveItem entry) {
		try {
			Long tempSize = entry.getSize();
			return tempSize == null ? 0 : tempSize.intValue();
		}
		catch (SevenZipException e) {
			//don't care
		}
		return 0;
	}

	@Override
	public void close() throws IOException {
		// FYI: no need to close the iface, because the archive will
		// shut it down on close anyways
		try {
			archive.close();
		}
		catch (SevenZipException e) {
			Msg.warn(this, "Problem closing 7-Zip archive", e);
		}
		randomAccessFile.close();
		super.close();
	}

	class MySequentialOutStream implements ISequentialOutStream {

		private File tempFile = File.createTempFile("Ghidra_", ".tmp");
		private OutputStream outputStream;

		MySequentialOutStream() throws IOException {
			outputStream = new FileOutputStream(tempFile);
		}

		InputStream getData() throws IOException {
			outputStream.close();
			return new FileInputStream(tempFile);
		}

		@Override
		public int write(byte[] buffer) throws SevenZipException {
			try {
				outputStream.write(buffer);
			}
			catch (IOException e) {
				throw new SevenZipException(e);
			}
			return buffer.length;
		}
	}
}
