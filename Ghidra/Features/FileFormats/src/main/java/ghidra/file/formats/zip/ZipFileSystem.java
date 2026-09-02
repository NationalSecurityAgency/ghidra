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
package ghidra.file.formats.zip;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Date;
import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.bin.*;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.crypto.CryptoSession;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.framework.generic.auth.Password;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

/**
* File system that handles .zip files using Apache commons compress, and Zip4j for password
* protected files.
*/
//@formatter:off
@FileSystemInfo(
	type = "zip", 
	description = "ZIP", 
	factory = ZipFileSystemFactory.class,
	priority = FileSystemInfo.PRIORITY_HIGH,
	extensions = { "zip", "jar" }
)
//@formatter:on
public class ZipFileSystem extends AbstractFileSystem<ZipArchiveEntry> {
	private static final String INVALID_SYMLINK_PATH = "<invalid_or_unknown_symlink_destination>";

	private ZipFile zipFile;
	private ByteProvider bp;
	private Zip4jFileHandler zip4j; // only needed when password protected entries are present

	private List<ZipArchiveEntry> entries = List.of();
	private Map<Integer, Password> passwords = new HashMap<>();
	private Set<Password> uniquePasswords = new HashSet<>();

	public ZipFileSystem(FSRLRoot fsrl, FileSystemService fsService) {
		super(fsrl, fsService);
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();

		if (zipFile != null) {
			zipFile.close();
			zipFile = null;
		}
		entries.clear();
		if (zip4j != null) {
			zip4j.close();
			zip4j = null;
		}
		if (bp != null) {
			bp.close();
			bp = null;
		}

		uniquePasswords.forEach(password -> FSUtilities.uncheckedClose(password, null));
		uniquePasswords.clear();
		passwords.clear();

		fsIndex.clear();
	}

	@Override
	public boolean isClosed() {
		return zipFile == null;
	}

	public void mount(ByteProvider bp, TaskMonitor monitor) throws CancelledException, IOException {

		this.bp = bp;

		zipFile = ZipFile.builder()
				.setSeekableByteChannel(
					new ByteProviderSeekableByteChannel(new ByteProviderWrapper(bp, null)))
				.get();

		entries = Collections.list(zipFile.getEntriesInPhysicalOrder());

		try (CryptoSession _ = fsService.newCryptoSession()) {
			ensurePasswords(monitor);
			indexFiles(monitor);
		}
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		ZipArchiveEntry zipEntry = fsIndex.getMetadata(file);
		if (zipEntry == null) {
			return FileAttributes.EMPTY;
		}
		int fileIndex = (int) fsIndex.getFileIndex(file);
		FileAttributes result = new FileAttributes();

		String rawPath = zipEntry.getName();
		result.add(FileAttributeType.NAME_ATTR, FilenameUtils.getName(rawPath));
		result.add(FileAttributeType.PATH_ATTR, FilenameUtils.getFullPath(rawPath));
		result.add(FileAttributeType.COMMENT_ATTR, zipEntry.getComment());
		result.add(FileAttributeType.SIZE_ATTR, zipEntry.getSize());
		Date date = new Date(zipEntry.getLastModifiedTime().toMillis());
		result.add(FileAttributeType.MODIFIED_DATE_ATTR, date);
		result.add(FileAttributeType.COMPRESSED_SIZE_ATTR, zipEntry.getCompressedSize());
		result.add("CRC", Long.toHexString(zipEntry.getCrc()));
		result.add("Compression Method", "0x" + Integer.toHexString(zipEntry.getMethod()));
		if (zipEntry.getGeneralPurposeBit().usesEncryption()) {
			result.add(FileAttributeType.IS_ENCRYPTED_ATTR, true);
			result.add(HAS_GOOD_PASSWORD_ATTR, passwords.get(fileIndex) != null);
		}
		if (zipEntry.isUnixSymlink()) {
			String symlinkDest = fsIndex.getSymlinkPath(file);
			result.add(FileAttributeType.SYMLINK_DEST_ATTR, symlinkDest);

		}
		return result;
	}

	@Override
	public String toString() {
		return "ZipFilesystem [ fsrl=" + fsFSRL + " ]";
	}

	@Override
	public InputStream getInputStream(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		ZipArchiveEntry zipEntry = fsIndex.getMetadata(file);
		return (zipEntry != null) ? zipFile.getInputStream(zipEntry) : null;
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {

		GFile resolvedFile = fsIndex.resolveSymlinks(file);
		ZipArchiveEntry zipEntry = fsIndex.getMetadata(resolvedFile);
		if (zipEntry == null) {
			throw new IOException("Unknown file " + file);
		}

		int fileIndex = (int) fsIndex.getFileIndex(resolvedFile);

		return fsService.getDerivedByteProvider(fsFSRL.getContainer(), file.getFSRL(),
			file.getFSRL().getPath(), zipEntry.getSize(), () -> {

				if (zipEntry.getGeneralPurposeBit().usesEncryption()) {
					Password password = getPasswordForEntry(fileIndex, monitor);
					if (password == null) {
						throw new CryptoException(
							"Unable to extract encrypted file, missing password: " +
								zipEntry.getName());
					}
					return zip4j.getInputStream(fileIndex, password);
				}
				return zipFile.getInputStream(zipEntry);

			}, monitor);
	}

	private void indexFiles(TaskMonitor monitor) throws CancelledException {
		int zipIndex = 0;
		for (ZipArchiveEntry zipEntry : entries) {
			monitor.checkCancelled();
			if (zipEntry.isUnixSymlink()) {
				String symlinkDest = safeGetSymlinkDest(zipIndex, zipEntry, monitor);
				fsIndex.storeSymlink(zipEntry.getName(), zipIndex++, symlinkDest,
					zipEntry.getSize(), zipEntry);
			}
			else {
				fsIndex.storeFile(zipEntry.getName(), zipIndex++, zipEntry.isDirectory(),
					zipEntry.getSize(), zipEntry);
			}
		}
	}

	private String safeGetSymlinkDest(int fileIndex, ZipArchiveEntry zipEntry,
			TaskMonitor monitor) {
		try {
			if (zipEntry.getGeneralPurposeBit().usesEncryption()) {
				Password password = getPasswordForEntry(fileIndex, monitor);
				if (password != null) {
					try (InputStream is = zip4j.getInputStream(fileIndex, password)) {
						byte[] symlinkBytes = is.readAllBytes();
						return new String(symlinkBytes, StandardCharsets.UTF_8);
					}
				}
				return INVALID_SYMLINK_PATH;
			}
			return zipFile.getUnixSymlink(zipEntry);
		}
		catch (IOException e) {
			return INVALID_SYMLINK_PATH;
		}
	}

	private Password getPasswordForEntry(int fileIndex, TaskMonitor monitor) {
		ZipArchiveEntry zipEntry = entries.get(fileIndex);
		String fileName = zipEntry.getName();

		Password result = passwords.get(fileIndex);
		if (result != null) {
			return result;
		}

		for (Password previousPassword : uniquePasswords) {
			if (testPassword(fileIndex, previousPassword)) {
				passwords.put(fileIndex, previousPassword);
				return previousPassword;
			}
		}

		FSRL containerFSRL = fsFSRL.getContainer();
		try (CryptoSession cryptoSession = fsService.newCryptoSession()) {
			String prompt = uniquePasswords.isEmpty()
					? containerFSRL.getName()
					: "%s in %s".formatted(fileName, containerFSRL.getName());

			for (Iterator<Password> pwIt =
				cryptoSession.getPasswordsFor(containerFSRL, prompt); pwIt.hasNext();) {

				try (Password passwordValue = pwIt.next()) {
					monitor.setMessage("Testing password for " + fileName);

					// Even though the caller requested a password for a specific zipEntry,
					// we need to test the candidate password against all entries that are missing
					// passwords to avoid situations where the user entered a correct password
					// for a later file, but the caller has specified a different file.
					// This will also include the file the caller specified.
					List<Integer> successIndexes = new ArrayList<>();
					for (Entry<Integer, Password> entry : passwords.entrySet()) {
						if (entry.getValue() == null) {
							if (testPassword(entry.getKey(), passwordValue)) {
								successIndexes.add(entry.getKey());
							}
						}
					}

					if (!successIndexes.isEmpty()) {
						cryptoSession.addSuccessfulPassword(containerFSRL, passwordValue);
						Password successPassword = passwordValue.clone();
						uniquePasswords.add(successPassword);

						for (Integer successIndex : successIndexes) {
							passwords.put(successIndex, successPassword);
						}

						// Even though there was a successful password found, it might not have
						// been the password for the zipEntry the caller requested
						result = passwords.get(fileIndex);
						if (result != null) {
							return result;
						}
					}
				}
			}
		}

		return null;
	}

	private boolean testPassword(int fileIndex, Password password) {
		try (InputStream _ = zip4j.getInputStream(fileIndex, password)) {
			return true;
		}
		catch (IOException e) {
			return false;
		}
	}

	private void ensurePasswords(TaskMonitor monitor) throws IOException {

		for (int i = 0; i < entries.size(); i++) {
			ZipArchiveEntry zipEntry = entries.get(i);
			if (zipEntry.getGeneralPurposeBit().usesEncryption()) {
				passwords.put(i, null);
			}
		}

		if (passwords.isEmpty()) {
			// nothing to do
			return;
		}

		this.zip4j = new Zip4jFileHandler(bp, fsService, monitor);

		// Alert!  Unusual code!
		// Background: contrary to normal expectations, zip container files can have a
		// unique password per-embedded-file.
		// The following loop tests passwords against each file, first trying a
		// common password against all the embedded files (this is the most likely
		// scenario), and then when a password has been found that successfully unlocks
		// the first subset of files, each remaining subsequent encrypted file's name is used to
		// prompt for the next password.
		// If the loop ends without finding a password for an encrypted file,
		// that file will not be readable unless a password is found for it.
		for (Entry<Integer, Password> entry : passwords.entrySet()) {
			int fileIndex = entry.getKey();
			getPasswordForEntry(fileIndex, monitor);
		}

		long missingPasswordCount =
			passwords.entrySet().stream().filter(e -> e.getValue() == null).count();
		if (missingPasswordCount > 0) {
			Msg.warn(this, "Unable to find password(s) for %d file(s) in %s"
					.formatted(missingPasswordCount, fsFSRL.getContainer().getName()));
		}
	}

}
