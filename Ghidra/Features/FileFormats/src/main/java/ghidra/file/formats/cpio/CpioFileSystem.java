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

import java.io.*;
import java.util.Date;
import java.util.List;

import org.apache.commons.compress.archivers.cpio.CpioArchiveEntry;
import org.apache.commons.compress.archivers.cpio.CpioArchiveInputStream;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.FSUtilities.StreamCopyResult;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

@FileSystemInfo(type = "cpio", description = "CPIO", factory = CpioFileSystemFactory.class)
public class CpioFileSystem implements GFileSystem {
	private FSRLRoot fsFSRL;
	private FileSystemIndexHelper<CpioArchiveEntry> fsIndex;
	private FileSystemRefManager fsRefManager = new FileSystemRefManager(this);
	private ByteProvider provider;


	public CpioFileSystem(FSRLRoot fsFSRL, ByteProvider provider, TaskMonitor monitor)
			throws IOException {
		monitor.setMessage("Opening CPIO...");
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
	public String getInfo(GFile file, TaskMonitor monitor) {
		CpioArchiveEntry entry = fsIndex.getMetadata(file);
		if (entry == null) {
			return null;
		}
		StringBuilder buffer = new StringBuilder();
		try {
			buffer.append("Name: " + entry.getName() + "\n");
			buffer.append("Format: " + Long.toHexString(entry.getFormat()) + "\n");
			buffer.append("GID: " + Long.toHexString(entry.getGID()) + "\n");
			buffer.append("Inode: " + Long.toHexString(entry.getInode()) + "\n");
			buffer.append("Last Modified: " + entry.getLastModifiedDate() + "\n");
			buffer.append("Links: " + Long.toHexString(entry.getNumberOfLinks()) + "\n");
			buffer.append("Mode: " + Long.toHexString(entry.getMode()) + "\n");
			buffer.append("Size: " + Long.toHexString(entry.getSize()) + "\n");
			buffer.append("Time: " + new Date(entry.getTime()) + "\n");
			buffer.append("UID: " + Long.toHexString(entry.getUID()) + "\n");
		}
		catch (Exception e) {
			// ignore 
		}
		try {
			buffer.append("Device ID: " + Long.toHexString(entry.getDevice()) + "\n");
			buffer.append("Remote Device: " + Long.toHexString(entry.getRemoteDevice()) + "\n");
		}
		catch (Exception e) {
			// ignore old format missing exception
		}
		try {
			buffer.append("Checksum: " + Long.toHexString(entry.getChksum()) + "\n");
		}
		catch (Exception e) {
			// ignore new format missing exception
		}
		return buffer.toString();
	}

	@Override
	public InputStream getInputStream(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		ByteProvider bp = getByteProvider(file, monitor);
		return bp != null ? bp.getInputStream(0) : null;
	}

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
					return getByteProviderForEntry(cpioInputStream, file.getFSRL(), monitor);
				}
				FileUtilities.copyStreamToStream(cpioInputStream, OutputStream.nullOutputStream(),
					monitor);
			}
		}
		catch (IllegalArgumentException e) {
			throw new IOException(e);
		}
		throw new IOException("Unable to seek to entry: " + file.getName());
	}

	private ByteProvider getByteProviderForEntry(CpioArchiveInputStream cpioInputStream, FSRL fsrl,
			TaskMonitor monitor) throws CancelledException, IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		StreamCopyResult copyResult = FSUtilities.streamCopy(cpioInputStream, out, monitor);
		if (fsrl.getMD5() == null) {
			fsrl = fsrl.withMD5(NumericUtilities.convertBytesToString(copyResult.md5));
		}
		return new ByteArrayProvider(out.toByteArray(), fsrl);
	}
}
