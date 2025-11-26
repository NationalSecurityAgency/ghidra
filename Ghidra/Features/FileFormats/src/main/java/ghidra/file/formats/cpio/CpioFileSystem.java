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
package ghidra.file.formats.cpio;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.apache.commons.compress.archivers.cpio.CpioArchiveEntry;
import org.apache.commons.compress.archivers.cpio.CpioArchiveInputStream;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.formats.gfilesystem.fileinfo.FileType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "cpio", description = "CPIO", factory = CpioFileSystemFactory.class)
public class CpioFileSystem extends AbstractFileSystem<CpioArchiveEntry> {
	private static final int MAX_SANE_SYMLINK = 64 * 1024;

	private ByteProvider provider;

	public CpioFileSystem(FSRLRoot fsFSRL, ByteProvider provider, FileSystemService fsService,
			TaskMonitor monitor) throws IOException {
		super(fsFSRL, fsService);

		monitor.setMessage("Opening CPIO...");
		this.provider = provider;

		try (CpioArchiveInputStream cpioInputStream =
			new CpioArchiveInputStream(provider.getInputStream(0))) {
			CpioArchiveEntry entry;
			int fileNum = 0;
			while ((entry = cpioInputStream.getNextEntry()) != null) {
				monitor.setMessage(entry.getName());
				if (entry.isSymbolicLink()) {
					String linkDest = entry.getSize() < MAX_SANE_SYMLINK
							? new String(cpioInputStream.readAllBytes(), StandardCharsets.UTF_8)
							: "???badsymlink???";
					fsIndex.storeSymlink(entry.getName(), fileNum++, linkDest, entry.getSize(),
						entry);
				}
				else {
					fsIndex.storeFile(entry.getName(), fileNum++, entry.isDirectory(),
						entry.getSize(), entry);
				}
			}
		}
		catch (EOFException e) {
			// silently ignore EOFExceptions
		}
		catch (IOException e) {
			throw e;
		}
		catch (Exception e) {
			throw new IOException(e);
		}
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		fsIndex.clear();
		if (provider != null) {
			provider.close();
			provider = null;
		}
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		FileAttributes result = new FileAttributes();
		CpioArchiveEntry entry = fsIndex.getMetadata(file);
		if (entry != null) {
			result.add(NAME_ATTR, entry.getName());
			result.add(SIZE_ATTR, entry.getSize());
			result.add(MODIFIED_DATE_ATTR, entry.getLastModifiedDate());
			result.add(USER_ID_ATTR, entry.getUID());
			result.add(GROUP_ID_ATTR, entry.getGID());
			result.add(FILE_TYPE_ATTR, getFileType(entry));
			result.add(SYMLINK_DEST_ATTR, fsIndex.getSymlinkPath(file));
			result.add("Mode", Long.toHexString(entry.getMode()));
			result.add("Inode", Long.toHexString(entry.getInode()));
			result.add("Format", Long.toHexString(entry.getFormat()));
			try {
				result.add("Device ID", Long.toHexString(entry.getDevice()));
				result.add("Remote Device", Long.toHexString(entry.getRemoteDevice()));
			}
			catch (Exception e) {
				// ignore old format missing exception
			}
			try {
				result.add("Checksum", Long.toHexString(entry.getChksum()));
			}
			catch (Exception e) {
				// ignore new format missing exception
			}
		}

		return result;
	}

	@Override
	public FileType getFileType(GFile f, TaskMonitor monitor) {
		CpioArchiveEntry entry = fsIndex.getMetadata(f);
		return entry != null ? getFileType(entry) : FileType.UNKNOWN;
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		file = fsIndex.resolveSymlinks(file);
		CpioArchiveEntry targetEntry = fsIndex.getMetadata(file);
		if (targetEntry == null) {
			return null;
		}
		if (!targetEntry.isRegularFile()) {
			throw new IOException("CPIO entry " + file.getName() + " is not a regular file.");
		}
		try (CpioArchiveInputStream cpioInputStream =
			new CpioArchiveInputStream(provider.getInputStream(0))) {

			CpioArchiveEntry currentEntry;
			while ((currentEntry = cpioInputStream.getNextEntry()) != null) {
				if (currentEntry.equals(targetEntry)) {
					ByteProvider bp =
						fsService.getDerivedByteProvider(provider.getFSRL(), file.getFSRL(),
							file.getPath(), currentEntry.getSize(), () -> cpioInputStream, monitor);
					return bp;
				}
			}
		}
		catch (IllegalArgumentException e) {
			throw new IOException(e);
		}
		throw new IOException("Unable to seek to entry: " + file.getName());
	}

	private FileType getFileType(CpioArchiveEntry entry) {
		if (entry.isSymbolicLink()) {
			return FileType.SYMBOLIC_LINK;
		}
		else if (entry.isDirectory()) {
			return FileType.DIRECTORY;
		}
		else if (entry.isRegularFile()) {
			return FileType.FILE;
		}
		else {
			return FileType.OTHER;
		}
	}
}
