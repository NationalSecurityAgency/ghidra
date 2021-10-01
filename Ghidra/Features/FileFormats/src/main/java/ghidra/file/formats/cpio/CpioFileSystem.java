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

import java.io.*;
import java.util.List;

import org.apache.commons.compress.archivers.cpio.CpioArchiveEntry;
import org.apache.commons.compress.archivers.cpio.CpioArchiveInputStream;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

@FileSystemInfo(type = "cpio", description = "CPIO", factory = CpioFileSystemFactory.class)
public class CpioFileSystem implements GFileSystem {
	private FileSystemService fsService;
	private FSRLRoot fsFSRL;
	private FileSystemIndexHelper<CpioArchiveEntry> fsIndex;
	private FileSystemRefManager fsRefManager = new FileSystemRefManager(this);
	private ByteProvider provider;


	public CpioFileSystem(FSRLRoot fsFSRL, ByteProvider provider, FileSystemService fsService,
			TaskMonitor monitor)
			throws IOException {
		monitor.setMessage("Opening CPIO...");
		this.fsService = fsService;
		this.fsFSRL = fsFSRL;
		this.provider = provider;
		this.fsIndex = new FileSystemIndexHelper<>(this, fsFSRL);

		try (CpioArchiveInputStream cpioInputStream =
			new CpioArchiveInputStream(provider.getInputStream(0))) {
			CpioArchiveEntry entry;
			int fileNum = 0;
			while ((entry = cpioInputStream.getNextCPIOEntry()) != null) {
				FileUtilities.copyStreamToStream(cpioInputStream, OutputStream.nullOutputStream(),
					monitor);

				monitor.setMessage(entry.getName());
				fsIndex.storeFile(entry.getName(), fileNum++, entry.isDirectory(),
					entry.getSize(), entry);
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
		fsRefManager.onClose();
		fsIndex.clear();
		if (provider != null) {
			provider.close();
			provider = null;
		}
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsFSRL;
	}

	@Override
	public String getName() {
		return fsFSRL.getContainer().getName();
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return fsRefManager;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsIndex.getListing(directory);
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsIndex.lookup(path);
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
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
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
			while ((currentEntry = cpioInputStream.getNextCPIOEntry()) != null) {
				if (currentEntry.equals(targetEntry)) {
					ByteProvider bp =
						fsService.getDerivedByteProvider(provider.getFSRL(), file.getFSRL(),
							file.getPath(), currentEntry.getSize(), () -> cpioInputStream, monitor);
					return bp;
				}
				FSUtilities.streamCopy(cpioInputStream, OutputStream.nullOutputStream(), monitor);
			}
		}
		catch (IllegalArgumentException e) {
			throw new IOException(e);
		}
		throw new IOException("Unable to seek to entry: " + file.getName());
	}
}
