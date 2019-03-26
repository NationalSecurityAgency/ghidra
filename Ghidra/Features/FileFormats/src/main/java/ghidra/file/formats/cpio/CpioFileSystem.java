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
import java.util.*;

import org.apache.commons.compress.archivers.cpio.CpioArchiveEntry;
import org.apache.commons.compress.archivers.cpio.CpioArchiveInputStream;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "cpio", description = "CPIO", factory = GFileSystemBaseFactory.class)
public class CpioFileSystem extends GFileSystemBase {

	private Map<GFile, CpioArchiveEntry> map = new HashMap<>();

	public CpioFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		byte[] signature = provider.readBytes(0, 0x10);
		return CpioArchiveInputStream.matches(signature, 0x10);
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {
		monitor.setMessage("Opening CPIO...");

		byte[] bytes = provider.readBytes(0, provider.length());
		InputStream inputStream = new ByteArrayInputStream(bytes);

		try (CpioArchiveInputStream cpioInputStream = new CpioArchiveInputStream(inputStream)) {
			while (!monitor.isCancelled()) {
				/* TODO is this check needed?
				if ( cpioInputStream.available() == 0 ) {
					break;
				}
				 */
				try {
					CpioArchiveEntry entry = cpioInputStream.getNextCPIOEntry();
					if (entry == null) {
						break;
					}
					readEntryContents(cpioInputStream, monitor);//ignore contents now, but it must be read from stream
					storeEntry(entry, monitor);
				}
				catch (EOFException e) {
					break;
				}
				catch (Exception e) {
					FSUtilities.displayException(this, null, "Error While Opening CPIO",
						e.getMessage(), e);
				}
			}
		}
	}

	@Override
	public void close() throws IOException {
		super.close();
		map.clear();
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
		CpioArchiveEntry entry = map.get(file);
		StringBuffer buffer = new StringBuffer();
		try {
			buffer.append("Name: " + entry.getName() + "\n");
			buffer.append("Checksum: " + Long.toHexString(entry.getChksum()) + "\n");
			buffer.append("Format: " + Long.toHexString(entry.getFormat()) + "\n");
			buffer.append("GID: " + Long.toHexString(entry.getGID()) + "\n");
			buffer.append("Inode: " + Long.toHexString(entry.getInode()) + "\n");
			buffer.append("Last Modified: " + entry.getLastModifiedDate() + "\n");
			buffer.append("Links: " + Long.toHexString(entry.getNumberOfLinks()) + "\n");
			buffer.append("Mode: " + Long.toHexString(entry.getMode()) + "\n");
			buffer.append("Remote Device: " + Long.toHexString(entry.getRemoteDevice()) + "\n");
			buffer.append("Size: " + Long.toHexString(entry.getSize()) + "\n");
			buffer.append("Time: " + new Date(entry.getTime()) + "\n");
			buffer.append("UID: " + Long.toHexString(entry.getUID()) + "\n");
			buffer.append("Device ID: " + Long.toHexString(entry.getDevice()) + "\n");
		}
		catch (Exception e) {
		}
		return buffer.toString();
	}

	@Override
	protected InputStream getData(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException, CryptoException {
		CpioArchiveEntry fileEntry = map.get(file);
		if (!fileEntry.isRegularFile()) {
			throw new IOException(file.getName() + " is not a regular file.");
		}
		byte[] bytes = provider.readBytes(0, provider.length());
		InputStream inputStream = new ByteArrayInputStream(bytes);
		CpioArchiveInputStream cpioInputStream = new CpioArchiveInputStream(inputStream);
		try {
			while (true) {
				if (monitor.isCancelled()) {
					break;
				}
				CpioArchiveEntry entry = cpioInputStream.getNextCPIOEntry();
				if (entry == null) {
					break;
				}
				byte[] entryBytes = readEntryContents(cpioInputStream, monitor);
				if (entry.equals(fileEntry)) {
					return new ByteArrayInputStream(entryBytes);
				}
			}
		}
		catch (IllegalArgumentException e) {//unknown MODES..
		}
		finally {
			cpioInputStream.close();
		}
		return null;
	}

	private void storeEntry(CpioArchiveEntry entry, TaskMonitor monitor) {
		monitor.setMessage(entry.getName());
		GFileImpl file = GFileImpl.fromPathString(this, root, entry.getName(), null,
			entry.isDirectory(), entry.getSize());
		storeFile(file, entry, monitor);
	}

	private void storeFile(GFile file, CpioArchiveEntry entry, TaskMonitor monitor) {
		if (monitor.isCancelled()) {
			return;
		}
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
		storeFile(parentFile, null, monitor);
	}

	private byte[] readEntryContents(CpioArchiveInputStream cpioInputStream, TaskMonitor monitor)
			throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		while (true) {
			if (monitor.isCancelled()) {
				return null;
			}
			int b = cpioInputStream.read();
			if (b == -1) {
				break;
			}
			out.write(b);
		}
		return out.toByteArray();
	}
}
