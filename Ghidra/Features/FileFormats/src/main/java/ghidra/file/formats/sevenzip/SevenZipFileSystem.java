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


import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.Closeable;
import java.io.IOException;
import java.util.*;

import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.FileCache.FileCacheEntry;
import ghidra.formats.gfilesystem.FileCache.FileCacheEntryBuilder;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.crypto.CryptoSession;
import ghidra.formats.gfilesystem.crypto.PasswordValue;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.formats.gfilesystem.fileinfo.FileType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;
import net.sf.sevenzipjbinding.*;
import net.sf.sevenzipjbinding.simple.ISimpleInArchive;
import net.sf.sevenzipjbinding.simple.ISimpleInArchiveItem;

@FileSystemInfo(type = "7zip", description = "7Zip", factory = SevenZipFileSystemFactory.class)
public class SevenZipFileSystem implements GFileSystem {
	private FileSystemService fsService;
	private FileSystemIndexHelper<ISimpleInArchiveItem> fsIndexHelper;
	private FSRLRoot fsrl;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);
	private Map<Integer, String> passwords = new HashMap<>();

	private IInArchive archive;
	private ISimpleInArchive archiveInterface;
	private SZByteProviderStream szBPStream;
	private ISimpleInArchiveItem[] items;
	private ArchiveFormat archiveFormat;

	public SevenZipFileSystem(FSRLRoot fsrl, FileSystemService fsService) {
		this.fsService = fsService;
		this.fsrl = fsrl;
		this.fsIndexHelper = new FileSystemIndexHelper<>(this, fsrl);
	}

	/**
	 * Opens the specified sevenzip container file and initializes this file system with the
	 * contents.
	 * 
	 * @param byteProvider container file 
	 * @param monitor {@link TaskMonitor} to allow the user to monitor and cancel
	 * @throws CancelledException if user cancels
	 * @throws IOException if error when reading data
	 */
	public void mount(ByteProvider byteProvider, TaskMonitor monitor)
			throws CancelledException, IOException {
		try {
			szBPStream = new SZByteProviderStream(byteProvider);
			SevenZip.initSevenZipFromPlatformJAR(); // calling this multiple times is ok
			archive = SevenZip.openInArchive(null, szBPStream);
			archiveFormat = archive.getArchiveFormat();
			archiveInterface = archive.getSimpleInterface();
			items = archiveInterface.getArchiveItems();

			indexFiles(monitor);
			ensurePasswords(monitor);
		}
		catch (SevenZipException | SevenZipNativeInitializationException e) {
			throw new IOException("Failed to open archive: " + fsrl, e);
		}
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();

		FSUtilities.uncheckedClose(archive, "Problem closing 7-Zip archive");
		archive = null;
		archiveInterface = null;

		FSUtilities.uncheckedClose(szBPStream, null);
		szBPStream = null;

		fsIndexHelper.clear();
		items = null;
	}

	private void indexFiles(TaskMonitor monitor) throws CancelledException, SevenZipException {
		monitor.initialize(items.length);
		monitor.setMessage("Indexing files");
		for (ISimpleInArchiveItem item : items) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}

			long itemSize = Objects.requireNonNullElse(item.getSize(), -1L);
			fsIndexHelper.storeFile(fixupItemPath(item), item.getItemIndex(), item.isFolder(),
				itemSize, item);
		}
	}

	private String fixupItemPath(ISimpleInArchiveItem item) throws SevenZipException {
		String itemPath = item.getPath();
		if (items.length == 1 && itemPath.isBlank()) {
			// special case when there is a single unnamed file.
			// use the name of the 7zip file itself, minus the extension
			itemPath = FilenameUtils.getBaseName(fsrl.getContainer().getName());
		}
		return itemPath;
	}

	private String getPasswordForFile(GFile file, ISimpleInArchiveItem encryptedItem,
			TaskMonitor monitor) {
		int itemIndex = encryptedItem.getItemIndex();
		if (!passwords.containsKey(itemIndex)) {
			try (CryptoSession cryptoSession = fsService.newCryptoSession()) {
				String prompt = passwords.isEmpty()
						? fsrl.getContainer().getName()
						: String.format("%s in %s", file.getName(), fsrl.getContainer().getName());
				for (Iterator<PasswordValue> pwIt =
					cryptoSession.getPasswordsFor(fsrl.getContainer(), prompt); pwIt.hasNext();) {
					try (PasswordValue passwordValue = pwIt.next()) {
						monitor.setMessage("Testing password for " + file.getName());

						String password = String.valueOf(passwordValue.getPasswordChars());	// we are forced to use strings by 7zip's api
						int[] encryptedItemIndexes = getEncryptedItemIndexes();
						TestPasswordsCallback testCB =
							new TestPasswordsCallback(password, encryptedItemIndexes[0], monitor);

						// call the SZ extract method using "TEST" mode (ie. no bytes are extracted)
						// on any files that don't have a password yet 
						archive.extract(encryptedItemIndexes, true /* test mode */, testCB);
						List<Integer> successFileIndexes = testCB.getSuccessFileIndexes();
						for (Integer unlockedFileIndex : successFileIndexes) {
							passwords.put(unlockedFileIndex, password);
						}
						if (!successFileIndexes.isEmpty()) {
							cryptoSession.addSuccessfulPassword(fsrl.getContainer(), passwordValue);
						}
						if (passwords.containsKey(itemIndex)) {
							break;
						}
					}
					catch (SevenZipException e) {
						Msg.error(this, "Error when testing password for " + file.getFSRL(), e);
						return null;
					}
				}
			}
		}
		return passwords.get(itemIndex);

	}

	private int[] getEncryptedItemIndexes() throws SevenZipException {
		List<Integer> result = new ArrayList<>();
		for (ISimpleInArchiveItem item : items) {
			if (item.isEncrypted() && !passwords.containsKey(item.getItemIndex())) {
				result.add(item.getItemIndex());
			}
		}
		int[] arrayResult = new int[result.size()];
		int arrayResultIndex = 0;
		for (Integer i : result) {
			arrayResult[arrayResultIndex++] = i;
		}
		return arrayResult;
	}

	private void ensurePasswords(TaskMonitor monitor) throws CancelledException, IOException {
		// Alert!  Unusual code!
		// Background: contrary to normal expectations, zip container files can have a
		// unique password per-embedded-file.
		// Other archive formats may not have that feature, but the SevenZip jbinding
		// API is designed to allow a per-embedded-file password. 
		// The following loop tests passwords against the file, first trying a
		// common password against all the embedded files (this is the most likely
		// scenario), and then when a password has been found that successfully unlocks
		// the first subset of files, each remaining subsequent encrypted file's name is used to
		// prompt for the next password.
		// If the loop ends without finding a password for an encrypted file,
		// that file will not be readable unless a password is found for it (see 
		// getPasswordForFile()).
		
		try (CryptoSession cryptoSession = fsService.newCryptoSession()) {
			List<ISimpleInArchiveItem> encryptedItems = getEncryptedItemsWithoutPasswords();
			ISimpleInArchiveItem encryptedItem = null;
			while ((encryptedItem = getFirstItemWithoutPassword(encryptedItems)) != null &&
				!monitor.isCancelled()) {
				GFile gFile = fsIndexHelper.getFileByIndex(encryptedItem.getItemIndex());
				if (gFile == null) {
					throw new IOException("Unable to retrieve file " + encryptedItem.getPath());
				}
				getPasswordForFile(gFile, encryptedItem, monitor);
				if (passwords.isEmpty()) {
					// we didn't find any password for any file in the archive.  Abort the loop
					// instead of badgering the user by using other files as prompts
					break;
				}
				encryptedItems.remove(encryptedItem);
			}
			List<ISimpleInArchiveItem> noPasswordFoundList = getEncryptedItemsWithoutPasswords();
			if (!noPasswordFoundList.isEmpty()) {
				Msg.warn(this,
					"Unable to find password for " + noPasswordFoundList.size() + " file(s) in " +
						fsrl.getContainer().getName());
			}
		}
	}

	private ISimpleInArchiveItem getFirstItemWithoutPassword(
			List<ISimpleInArchiveItem> encryptedItems) {
		for (ISimpleInArchiveItem item : encryptedItems) {
			if (!passwords.containsKey(item.getItemIndex())) {
				return item;
			}
		}
		return null;
	}

	private List<ISimpleInArchiveItem> getEncryptedItemsWithoutPasswords()
			throws SevenZipException {
		List<ISimpleInArchiveItem> result = new LinkedList<>();
		for (ISimpleInArchiveItem item : items) {
			if (item.isEncrypted() && !passwords.containsKey(item.getItemIndex())) {
				result.add(item);
			}
		}
		return result;
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
		return szBPStream == null;
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
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		FileAttributes result = new FileAttributes();
		if (fsIndexHelper.getRootDir().equals(file)) {
			result.add(NAME_ATTR, "/");
			result.add("Archive Format", archiveFormat.toString());
		}
		else {
			ISimpleInArchiveItem item = fsIndexHelper.getMetadata(file);
			if (item == null) {
				return result;
			}

			result.add(NAME_ATTR, FilenameUtils.getName(uncheckedGet(item::getPath, "unknown")));
			result.add(FILE_TYPE_ATTR,
				uncheckedGet(item::isFolder, false) ? FileType.DIRECTORY : FileType.FILE);
			boolean encrypted = uncheckedGet(item::isEncrypted, false);
			result.add(IS_ENCRYPTED_ATTR, encrypted);
			if (encrypted) {
				result.add(HAS_GOOD_PASSWORD_ATTR, passwords.get(item.getItemIndex()) != null);
			}
			String comment = uncheckedGet(item::getComment, null);
			result.add(COMMENT_ATTR, !comment.isBlank() ? comment : null);
			result.add(COMPRESSED_SIZE_ATTR, uncheckedGet(item::getPackedSize, null));
			result.add(SIZE_ATTR, uncheckedGet(item::getSize, null));

			Integer crc = uncheckedGet(item::getCRC, null);
			result.add("CRC", crc != null ? String.format("%08X", crc) : null);
			result.add("Compression Method", uncheckedGet(item::getMethod, null));
			result.add(CREATE_DATE_ATTR, uncheckedGet(item::getCreationTime, null));
			result.add(MODIFIED_DATE_ATTR, uncheckedGet(item::getLastWriteTime, null));
		}
		return result;
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		try {
			ISimpleInArchiveItem item = fsIndexHelper.getMetadata(file);

			if (item == null) {
				return null;
			}

			int itemIndex = item.getItemIndex();

			if (item.isFolder()) {
				throw new IOException("Not a file: " + file.getName());
			}
			if (item.isEncrypted()) {
				String password = getPasswordForFile(file, item, monitor);
				if (password == null) {
					throw new CryptoException(
						"Unable to extract encrypted file, missing password: " + item.getPath());
				}
			}
			try (SZExtractCallback szCallback = new SZExtractCallback(monitor, itemIndex, true)) {
				archive.extract(new int[] { itemIndex }, false /* extract mode */, szCallback);
				FileCacheEntry result = szCallback.getExtractResult(itemIndex);
				if (result == null) {
					throw new IOException("Unable to extract " + file.getFSRL());
				}
				return result.asByteProvider(file.getFSRL());
			}
		}
		catch (SevenZipException e) {
			throw unwrapSZException(e);
		}

	}

	//----------------------------------------------------------------------------------------------
	/**
	 * Implements SevenZip bulk extract callback.
	 * <p>
	 * For each file in the archive, SZ will call this class's 1) getStream(), 2) prepare(), 
	 * 3) lots of write()s, and then 4) setOperationResult().
	 * <p>
	 * This class writes the extracted bytes to the FileCache.
	 * <p>
	 */
	private class SZExtractCallback
			implements IArchiveExtractCallback, ISequentialOutStream, ICryptoGetTextPassword,
			Closeable {

		private TaskMonitor monitor;
		private int currentIndex;
		private ISimpleInArchiveItem currentItem;
		private String currentName = "unknown";
		private FileCacheEntryBuilder currentCacheEntryBuilder;
		private boolean saveResults;
		private Map<Integer, FileCacheEntry> extractResults = new HashMap<>();

		public SZExtractCallback(TaskMonitor monitor, int initalIndex, boolean saveResults) {
			this.monitor = monitor;
			this.currentIndex = initalIndex;
			this.saveResults = saveResults;
		}

		FileCacheEntry getExtractResult(int itemIndex) {
			return extractResults.get(itemIndex);
		}

		@Override
		public void close() throws IOException {
			if (currentCacheEntryBuilder != null) {
				currentCacheEntryBuilder.close();
			}
		}

		@Override
		public ISequentialOutStream getStream(int index, ExtractAskMode extractAskMode)
				throws SevenZipException {
			currentIndex = index;

			// STEP 1: SevenZip calls this method to get a object it can use to write the bytes to.
			// If we return null, SZ treats it as a skip. (except for folders)
			currentItem = items[currentIndex];
			currentName = currentItem.getPath();

			if (currentItem.isFolder() || extractAskMode != ExtractAskMode.EXTRACT) {
				return null;
			}

			if (currentItem.isEncrypted() && !passwords.containsKey(currentIndex)) {
				// if we lack a password for this item, don't try to extract it
				Msg.debug(SevenZipFileSystem.this,
					"No password for file[" + currentIndex + "] " + currentName + " of " +
						fsrl.getContainer().getName() + ", unable to extract.");
				return null;
			}

			return this;
		}

		@Override
		public void prepareOperation(ExtractAskMode extractAskMode) throws SevenZipException {
			// STEP 2: SevenZip calls this method to further prepare to operate on the file.
			// In our case, we only handle extract operations.
			if (!currentItem.isFolder() && extractAskMode == ExtractAskMode.EXTRACT) {
				try {
					currentCacheEntryBuilder = fsService.createTempFile(currentItem.getSize());
					monitor.initialize(currentItem.getSize());
					monitor.setMessage("Extracting " + currentName);
				}
				catch (IOException e) {
					throw new SevenZipException(e);
				}
			}
		}

		@Override
		public String cryptoGetTextPassword() throws SevenZipException {
			// STEP 2.5 or 0: SevenZip calls this method to get the password of the file (if encrypted).
			// Sometimes after prepareOperation(), sometimes before getStream(). 
			String password = passwords.get(currentIndex);
			if (password == null) {

				Msg.debug(SevenZipFileSystem.this,
					"No password for file[" + currentIndex + "] " + currentName + " of " +
						fsrl.getContainer().getName());
				// hack, return a non-null bad password.  normally shouldn't get here as
				// encrypted files w/missing password are skipped by getStream()
				password = "";
			}
			return password;
		}

		@Override
		public int write(byte[] data) throws SevenZipException {
			// STEP 3: SevenZip calls this multiple times for all the bytes in the file.
			// We write them to our temp file.
			if (currentCacheEntryBuilder == null) {
				throw new SevenZipException(
					"Bad Sevenzip Extract Callback state, " + currentIndex + ", " + currentName);
			}
			try {
				currentCacheEntryBuilder.write(data);
				monitor.incrementProgress(data.length);
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
			if (currentCacheEntryBuilder == null) {
				return;
			}
			try {
				FileCacheEntry fce = currentCacheEntryBuilder.finish();
				if (extractOperationResult == ExtractOperationResult.OK) {
					GFile gFile = fsIndexHelper.getFileByIndex(currentIndex);
					if (gFile != null && gFile.getFSRL().getMD5() == null) {
						fsIndexHelper.updateFSRL(gFile, gFile.getFSRL().withMD5(fce.getMD5()));
					}
					if (saveResults) {
						extractResults.put(currentIndex, fce);
					}
					Msg.debug(SevenZipFileSystem.this, "Wrote file to cache: " + gFile + ", " +
						FSUtilities.formatSize(fce.length()));
				}
				else {
					Msg.warn(SevenZipFileSystem.this, "Failed to push file[" + currentIndex +
						"] " + currentName + " to cache: " + extractOperationResult);
					extractOperationResultToException(extractOperationResult);
				}
			}
			catch (IOException e) {
				throw new SevenZipException(e);
			}
			finally {
				FSUtilities.uncheckedClose(currentCacheEntryBuilder, null);
				currentCacheEntryBuilder = null;

				// hack to advance the currentIndex for the next file so cryptoGetTextPassword
				// will have a correct currentIndex value if it is called before getStream(), 
				// which does happen depending on the phase of the moon or the 7zip
				// library's mood.
				currentIndex++;
			}
		}

		//@formatter:off
		@Override public void setTotal(long total) throws SevenZipException { /* nada */ }
		@Override public void setCompleted(long complete) throws SevenZipException {/* nada */ }
		//@formatter:on

		private void extractOperationResultToException(ExtractOperationResult operationResult)
				throws IOException {
			if (operationResult == null) {
				throw new IOException("7-Zip returned null operation result");
			}
			switch (operationResult) {
				case CRCERROR:
					throw new IOException("7-Zip returned CRC error");
				case DATAERROR:
					throw new IOException("7-Zip returned data error");
				case UNSUPPORTEDMETHOD:
					throw new IOException("Unexpected: 7-Zip returned unsupported method");
				case UNKNOWN_OPERATION_RESULT:
					throw new IOException("Unexpected: 7-Zip returned unknown operation result");
				case WRONG_PASSWORD:
					throw new IOException("7-Zip wrong password");
				default:
					throw new IOException("7-Zip unknown error " + operationResult);
				case OK:
					// it's all ok!
			}
		}

	}

	/**
	 * This class is has the same layout and hacks re: setting currentIndex as {@link SZExtractCallback},
	 * but is specialized to test passwords against the encrypted entries in the file. 
	 */
	private class TestPasswordsCallback implements IArchiveExtractCallback, ICryptoGetTextPassword {

		private int currentIndex;
		private String currentPassword;
		private List<Integer> successFileIndexes = new ArrayList<>();
		private TaskMonitor monitor;

		TestPasswordsCallback(String currentPassword, int initialIndex, TaskMonitor monitor) {
			this.currentPassword = currentPassword;
			this.currentIndex = initialIndex;
			this.monitor = monitor;
		}

		List<Integer> getSuccessFileIndexes() {
			return successFileIndexes;
		}

		@Override
		public ISequentialOutStream getStream(int index, ExtractAskMode extractAskMode)
				throws SevenZipException {
			currentIndex = index;
			ISimpleInArchiveItem item = items[currentIndex];
			monitor.setMessage("Testing password for " + item.getPath());
			return null;
		}

		@Override
		public void prepareOperation(ExtractAskMode extractAskMode) throws SevenZipException {
			// nothing
		}

		@Override
		public String cryptoGetTextPassword() throws SevenZipException {
			return currentPassword;
		}

		@Override
		public void setOperationResult(ExtractOperationResult extractOperationResult)
				throws SevenZipException {
			ISimpleInArchiveItem item = items[currentIndex];
			if (item.isEncrypted() && extractOperationResult == ExtractOperationResult.OK &&
				!passwords.containsKey(currentIndex)) {
				successFileIndexes.add(currentIndex);
			}
			currentIndex++;
		}

		@Override
		public void setTotal(long total) throws SevenZipException {
			monitor.initialize(total);
		}

		@Override
		public void setCompleted(long complete) throws SevenZipException {
			monitor.setProgress(complete);
		}

	}

	interface SZGetter<T> {
		T get() throws SevenZipException;
	}

	private static <T> T uncheckedGet(SZGetter<T> getter, T defaultValue) {
		try {
			return getter.get();
		}
		catch (SevenZipException e) {
			// don't care
			return defaultValue;
		}
	}

	private IOException unwrapSZException(SevenZipException e) {
		SevenZipException tmp = e;
		while (tmp != null && tmp.getCause() instanceof SevenZipException) {
			tmp = (SevenZipException) tmp.getCause();
		}
		return (tmp != null && tmp.getCause() instanceof IOException)
				? (IOException) tmp.getCause()
				: new IOException(e);
	}

}
