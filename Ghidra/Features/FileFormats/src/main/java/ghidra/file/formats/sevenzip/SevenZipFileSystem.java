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

import java.util.*;

import java.io.*;

import org.apache.commons.io.FilenameUtils;

import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import net.sf.sevenzipjbinding.*;
import net.sf.sevenzipjbinding.impl.RandomAccessFileInStream;
import net.sf.sevenzipjbinding.simple.ISimpleInArchive;
import net.sf.sevenzipjbinding.simple.ISimpleInArchiveItem;
import utilities.util.FileUtilities;

@FileSystemInfo(type = "7zip", description = "7Zip", factory = SevenZipFileSystemFactory.class)
public class SevenZipFileSystem implements GFileSystem {

	private FileSystemService fileSystemService;
	private FileSystemIndexHelper<ISimpleInArchiveItem> fsIndexHelper;
	private FSRLRoot fsrl;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);

	private IInArchive archive;
	private ISimpleInArchive archiveInterface;
	private RandomAccessFile randomAccessFile;

	public SevenZipFileSystem(FSRLRoot fsrl) {
		this.fsrl = fsrl;
		this.fsIndexHelper = new FileSystemIndexHelper<>(this, fsrl);
		this.fileSystemService = FileSystemService.getInstance();
	}

	/**
	 * Opens the specified sevenzip container file and initializes this file system with the
	 * contents.
	 *  
	 * @param containerFile file to open
	 * @param monitor {@link TaskMonitor} to allow the user to monitor and cancel
	 * @throws CancelledException if user cancels
	 * @throws IOException if error when reading data
	 */
	public void mount(File containerFile, TaskMonitor monitor)
			throws CancelledException, IOException {
		randomAccessFile = new RandomAccessFile(containerFile, "r");
		try {
			archive = SevenZip.openInArchive(null, new RandomAccessFileInStream(randomAccessFile));
			archiveInterface = archive.getSimpleInterface();

			ISimpleInArchiveItem[] items = archiveInterface.getArchiveItems();
			for (ISimpleInArchiveItem item : items) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}

				String itemPath = item.getPath();
				if (items.length == 1 && itemPath.isBlank()) {
					// special case when there is a single unnamed file.
					// use the name of the 7zip file itself, minus the extension
					itemPath = FilenameUtils.getBaseName(fsrl.getContainer().getName());
				}
				fsIndexHelper.storeFile(itemPath, item.getItemIndex(), item.isFolder(),
					getSize(item), item);
			}
			preCacheAll(monitor);
		}
		catch (SevenZipException e) {
			throw new IOException("Failed to open archive: " + fsrl, e);
		}
	}

	private void preCacheAll(TaskMonitor monitor) throws SevenZipException {
		// Because the performance of single file extract is SOOOOOO SLOOOOOOOW, we pre-load
		// all files in the sevenzip archive into the file cache using the faster sevenzip
		// bulk extract method.
		// Single file extract is still possible if file cache info is evicted from memory due
		// to pressure.
		SZExtractCallback szCallback = new SZExtractCallback(monitor);
		archive.extract(null, false, szCallback);
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();

		if (randomAccessFile != null) {
			// FYI: no need to close the iface, because the archive will
			// shut it down on close anyways
			try {
				archive.close();
			}
			catch (SevenZipException e) {
				Msg.warn(this, "Problem closing 7-Zip archive", e);
			}
			archive = null;
			archiveInterface = null;

			randomAccessFile.close();
			randomAccessFile = null;
		}

		fsIndexHelper.clear();
	}

	@Override
	public String getName() {
		return fsrl.getContainer().getName();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsrl;
	}

	@Override
	public boolean isClosed() {
		return randomAccessFile == null;
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsIndexHelper.lookup(path);
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsIndexHelper.getListing(directory);
	}

	@Override
	public String getInfo(GFile file, TaskMonitor monitor) {
		ISimpleInArchiveItem entry = fsIndexHelper.getMetadata(file);
		return (entry != null) ? FSUtilities.infoMapToString(getInfoMap(entry)) : null;
	}

	private Map<String, String> getInfoMap(ISimpleInArchiveItem entry) {
		Map<String, String> info = new LinkedHashMap<>();
		try {
			info.put("Name", entry.getPath());
			info.put("Folder?", Boolean.toString(isFolder(entry)));
			info.put("Encrypted?", Boolean.toString(entry.isEncrypted()));
			info.put("Comment", entry.getComment());
			Long compressedSize = getCompressedSize(entry);
			info.put("Compressed Size",
				compressedSize != null ? NumericUtilities.toHexString(compressedSize) : "NA");
			info.put("Uncompressed Size", NumericUtilities.toHexString(getSize(entry)));
			Integer crc = getCRC(entry);
			info.put("CRC",
				crc != null ? NumericUtilities.toHexString(crc.intValue() & 0xffffffffL) : "NA");
			info.put("Compression Method", entry.getMethod());
			Date creationTime = getCreateDate(entry);
			info.put("Time", creationTime != null ? creationTime.toGMTString() : "NA");
		}
		catch (SevenZipException e) {
			Msg.warn(this, "7-Zip exception trying to get info on item", e);
		}
		return info;
	}

	@Override
	public InputStream getInputStream(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		ISimpleInArchiveItem entry = fsIndexHelper.getMetadata(file);

		if (entry == null) {
			return null;
		}

		try {
			if (entry.isFolder()) {
				throw new IOException("Not a file: " + file.getName());
			}
		}
		catch (SevenZipException e) {
			throw new IOException("Error getting status of file: " + file.getName(), e);
		}

		File cachedFile = extractSZFile(file, entry, monitor);
		return new FileInputStream(cachedFile);
	}

	private File extractSZFile(GFile file, ISimpleInArchiveItem entry, TaskMonitor monitor)
			throws CancelledException, IOException {
		// push the sevenzip compressed file into the file cache (if not already there)
		FileCacheEntry fce = FileSystemService.getInstance().getDerivedFilePush(fsrl.getContainer(),
			Integer.toString(entry.getItemIndex()), (os) -> {
				Msg.info(this, "Extracting singleton file from sevenzip (slow): " + file.getFSRL());
				try {
					ExtractOperationResult operationResult =
						entry.extractSlow(new ISequentialOutStream() {

							@Override
							public int write(byte[] data) throws SevenZipException {
								try {
									os.write(data);
									return data.length;
								}
								catch (IOException ioe) {
									throw new SevenZipException(ioe);
								}
							}
						});
					extractOperationResultToException(operationResult);
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

			}, monitor);
		return fce.file;
	}

	//----------------------------------------------------------------------------------------------

	private static void extractOperationResultToException(ExtractOperationResult operationResult)
			throws IOException {
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
				throw new IOException("Unexpected: 7-Zip returned unknown operation result");
			}
			case WRONG_PASSWORD: {
				throw new IOException("7-Zip wrong password");
			}
			case OK:
			default: {
				// it's all ok!
			}
		}
	}

	private static long getSize(ISimpleInArchiveItem entry) throws SevenZipException {
		Long tempSize = entry.getSize();
		return tempSize == null ? -1 : tempSize.intValue();
	}

	private static Long getCompressedSize(ISimpleInArchiveItem entry) {
		try {
			return entry.getPackedSize();
		}
		catch (SevenZipException e) {
			//don't care
		}
		return null;
	}

	private static Integer getCRC(ISimpleInArchiveItem entry) {
		try {
			return entry.getCRC();
		}
		catch (SevenZipException e) {
			//don't care
		}
		return null;
	}

	private static Date getCreateDate(ISimpleInArchiveItem entry) {
		try {
			return entry.getCreationTime();
		}
		catch (SevenZipException e) {
			//don't care
		}
		return null;
	}

	private static boolean isFolder(ISimpleInArchiveItem entry) {
		try {
			return entry.isFolder();
		}
		catch (SevenZipException e) {
			//don't care
		}
		return false;
	}

	//----------------------------------------------------------------------------------------------

	/**
	 * Implements SevenZip bulk extract callback.
	 * <p>
	 * For each file in the archive, SZ will call this class's 1) getStream(), 2) prepare(), 
	 * 3) lots of write()s, and then 4) setOperationResult().
	 * <p>
	 * This class writes the extracted bytes to a temp file, and then pushes that temp file
	 * into the FileSystem cache, and then deletes that temp file.
	 * <p>
	 * Without this bulk extract method, SevenZip takes ~500ms per file when used via the singleton
	 * extract method.
	 */
	private class SZExtractCallback implements IArchiveExtractCallback, ISequentialOutStream {

		private TaskMonitor monitor;
		private int currentIndex;
		private File currentTempFile;
		private OutputStream currentTempFileOutputStream;

		public SZExtractCallback(TaskMonitor monitor) {
			this.monitor = monitor;
		}

		@Override
		public ISequentialOutStream getStream(int index, ExtractAskMode extractAskMode)
				throws SevenZipException {
			// STEP 1: SevenZip calls this method to get a object it can use to write the bytes to.
			// If we return null, SZ treats it as a skip.
			try {
				if (!fileSystemService.hasDerivedFile(fsrl.getContainer(), Integer.toString(index),
					monitor)) {
					this.currentIndex = index;
					return this;
				}
			}
			catch (CancelledException | IOException e) {
				// ignore
			}
			return null;
		}

		@Override
		public void prepareOperation(ExtractAskMode extractAskMode) throws SevenZipException {
			// STEP 2: SevenZip calls this method to further prepare to operate on the file.
			// In our case, we only handle extract operations.
			if (extractAskMode == ExtractAskMode.EXTRACT) {
				try {
					currentTempFile = File.createTempFile("ghidra_sevenzip_", ".tmp");
					currentTempFileOutputStream = new FileOutputStream(currentTempFile);
				}
				catch (IOException e) {
					throw new SevenZipException(e);
				}
			}
		}

		@Override
		public int write(byte[] data) throws SevenZipException {
			// STEP 3: SevenZip calls this multiple times for all the bytes in the file.
			// We write them to our temp file.
			try {
				currentTempFileOutputStream.write(data);
				return data.length;
			}
			catch (IOException e) {
				throw new SevenZipException(e);
			}
		}

		@Override
		public void setOperationResult(ExtractOperationResult extractOperationResult)
				throws SevenZipException {
			// STEP 4: SevenZip calls this to signal that the extract is done for this file.
			if (currentTempFileOutputStream != null) {
				try {
					currentTempFileOutputStream.close();
					extractOperationResultToException(extractOperationResult);
					fileSystemService.getDerivedFilePush(fsrl.getContainer(),
						Integer.toString(currentIndex), (os) -> {
							try (InputStream is = new FileInputStream(currentTempFile)) {
								FileUtilities.copyStreamToStream(is, os, monitor);
							}
						}, monitor);
					currentTempFile.delete();
				}
				catch (IOException | CancelledException e) {
					throw new SevenZipException(e);
				}
				finally {
					currentTempFile = null;
					currentTempFileOutputStream = null;
				}
			}
		}

		//@formatter:off
		@Override public void setTotal(long total) throws SevenZipException { /* nada */ }
		@Override public void setCompleted(long complete) throws SevenZipException {/* nada */ }
		//@formatter:on

	}

}
