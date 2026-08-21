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
import java.io.InputStream;
import java.nio.channels.SeekableByteChannel;
import java.util.*;

import org.apache.commons.compress.archivers.sevenz.SevenZArchiveEntry;
import org.apache.commons.compress.archivers.sevenz.SevenZFile;
import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.bin.*;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.crypto.CryptoSession;
import ghidra.framework.generic.auth.Password;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

//@formatter:off
@FileSystemInfo(
	type = "7zip",
	description = "7Zip",
	factory = SevenZipFileSystemFactory.class,
	extensions = { "7z" }
)
//@formatter:on
/**
* File system that handles 7z files.
*/
public class SevenZipFileSystem extends AbstractFileSystem<SevenZArchiveEntry> {

	private SevenZFile szFile;
	private ByteProvider bp;

	public SevenZipFileSystem(FSRLRoot fsrl, FileSystemService fsService) {
		super(fsrl, fsService);
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();

		if (szFile != null) {
			szFile.close();
			szFile = null;
		}
		if (bp != null) {
			bp.close();
			bp = null;
		}

		fsIndex.clear();
	}

	@Override
	public boolean isClosed() {
		return bp == null;
	}

	public void mount(ByteProvider bp, TaskMonitor monitor) throws CancelledException, IOException {
		this.bp = bp;

		szFile = tryMount(null, monitor);

		if (szFile == null) {
			FSRL containerFSRL = fsFSRL.getContainer();
			try (CryptoSession cryptoSession = fsService.newCryptoSession()) {
				for (Iterator<Password> pwIt = cryptoSession.getPasswordsFor(containerFSRL,
					containerFSRL.getName()); szFile == null && pwIt.hasNext();) {

					try (Password passwordValue = pwIt.next()) {
						szFile = tryMount(passwordValue, monitor);
					}
				}
			}
		}

		if (szFile == null) {
			throw new IOException("Failed to mount " + bp.getFSRL());
		}
	}

	private SevenZFile tryMount(Password password, TaskMonitor monitor) throws CancelledException {

		try {
			SeekableByteChannel sbc =
				new ByteProviderSeekableByteChannel(new ByteProviderWrapper(bp, null)); // wrap bp to prevent it from being closed

			// Entire file may be encrypted, or only individual file payloads may be encrypted.
			// If entire file is encrypted, we need the password to just list the contents of the
			// archive, otherwise we can open the file and list it without password until we try
			// to read a file's content.
			SevenZFile newSzFile = SevenZFile.builder()
					.setSeekableByteChannel(sbc)
					.setPassword(password != null ? password.getPasswordChars() : null) // SevenZFile makes a copy of the supplied char[]
					.get();

			List<SevenZArchiveEntry> entries = new ArrayList<>();

			// There may be independent passwords for individual files.
			// The SevenZFile impl only supports a single password for the entire file.
			// When attempting to read an encrypted file that has a non-matching password, we will
			// get some form of IOException, for example CorruptedInputException from the xz compressor
			int successCount = 0;
			int failCount = 0;
			SevenZArchiveEntry szEntry;
			while ((szEntry = newSzFile.getNextEntry()) != null) {
				monitor.checkCancelled();

				entries.add(szEntry);
				try (InputStream entryIs = newSzFile.getInputStream(szEntry);) {
					entryIs.read(); // read a byte to test if we have the correct password if this is an encrypted file
					successCount++;
				}
				catch (IOException e) {
					failCount++;
				}
			}

			if (successCount == 0 && failCount > 0) {
				// unable to read from any of the files in the archive.  (probably wrong password)
				return null;
			}

			if (password != null && failCount > 0) {
				Msg.warn(this, "Failed to apply supplied password to %d of %d files in %s"
						.formatted(failCount, entries.size(), fsFSRL.getContainer().getName()));
			}

			for (int entryIndex = 0; entryIndex < entries.size(); entryIndex++) {
				szEntry = entries.get(entryIndex);
				String name = szEntry.getName();
				if (name == null || name.isEmpty()) {
					if (entryIndex == 0) {
						name = FilenameUtils.getBaseName(fsFSRL.getContainer().getName());
					}
					else {
						name = "<blank>";
					}
				}

				fsIndex.storeFile(name, entryIndex, szEntry.isDirectory(), szEntry.getSize(),
					szEntry);
			}

			return newSzFile;
		}
		catch (IOException e) {
			return null;
		}
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		GFile resolvedFile = fsIndex.resolveSymlinks(file); // probably not needed with sz

		SevenZArchiveEntry szEntry = fsIndex.getMetadata(resolvedFile);
		if (szEntry == null) {
			throw new IOException("Unknown file " + file);
		}

		return fsService.getDerivedByteProvider(fsFSRL.getContainer(), file.getFSRL(),
			file.getFSRL().getPath(), szEntry.getSize(), () -> {

				return szFile.getInputStream(szEntry);

			}, monitor);
	}
}
