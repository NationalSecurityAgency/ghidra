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

import java.io.*;
import java.sql.Date;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * An alternative implementation of the zip file system, using java's built-in support
 * for zip files.
 * <p>
 * This class is used when the 7zip libraries fail to load, typically on a non-supported
 * platform.
 * <p>
 * The user will lose the ability to open password protected zip files when operating in this
 * mode, as well as the ability to use obfuscated temp files, which may allow a virusscanner
 * to mangle our temp files.
 * <p>
 * This class's name does not end in "FileSystem", so that it will not be found by the class searcher.
 * <p>
 * It also needs to duplicate the FileSystemInfo annotation to allow {@link GFileSystem#getType()}
 * and {@link GFileSystem#getDescription()} to operate in the default manner.
 */
@FileSystemInfo(type = "zip", description = "ZIP", factory = ZipFileSystemFactory.class, priority = FileSystemInfo.PRIORITY_HIGH)
public class ZipFileSystemBuiltin extends AbstractFileSystem<ZipEntry> {
	static final String TEMPFILE_PREFIX = "ghidra_tmp_zipfile";

	private ZipFile zipFile;

	public ZipFileSystemBuiltin(FSRLRoot fsFSRL, FileSystemService fsService) {
		super(fsFSRL, fsService);
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		if (zipFile != null) {
			zipFile.close();
			zipFile = null;
		}
		fsIndex.clear();
	}

	@Override
	public boolean isClosed() {
		return zipFile == null;
	}

	public void mount(File f, boolean deleteFileWhenDone, TaskMonitor monitor)
			throws CancelledException, IOException {

		// Just a little paranoia to ensure we don't delete a user's file.
		// The ZipFileSystemFactory knows to create temp files with this prefix.
		deleteFileWhenDone = deleteFileWhenDone && f.getName().startsWith(TEMPFILE_PREFIX);

		int openMode = deleteFileWhenDone
				? ZipFile.OPEN_READ | ZipFile.OPEN_DELETE
				: ZipFile.OPEN_READ;
		this.zipFile = new ZipFile(f, openMode);

		Enumeration<? extends ZipEntry> entries = zipFile.entries();
		while (entries.hasMoreElements()) {
			monitor.checkCancelled();
			ZipEntry currentEntry = entries.nextElement();
			fsIndex.storeFile(currentEntry.getName(), -1, currentEntry.isDirectory(),
				currentEntry.getSize(), currentEntry);
		}
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		ZipEntry zipEntry = fsIndex.getMetadata(file);
		if (zipEntry == null) {
			return null;
		}
		FileAttributes result = new FileAttributes();

		result.add(FileAttributeType.COMMENT_ATTR, zipEntry.getComment());
		result.add(FileAttributeType.SIZE_ATTR, zipEntry.getSize());
		Date date = new Date(zipEntry.getLastModifiedTime().toMillis());
		result.add(FileAttributeType.MODIFIED_DATE_ATTR, date);
		result.add(FileAttributeType.COMPRESSED_SIZE_ATTR, zipEntry.getCompressedSize());
		result.add("CRC", Long.toHexString(zipEntry.getCrc()));
		result.add("Compression Method", "0x" + Integer.toHexString(zipEntry.getMethod()));
		return result;
	}

	@Override
	public String toString() {
		return "ZipFilesystemBuiltin [ fsrl=" + fsFSRL + ", filename=" + zipFile.getName() + " ]";
	}

	@Override
	public InputStream getInputStream(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		ZipEntry zipEntry = fsIndex.getMetadata(file);
		return (zipEntry != null) ? zipFile.getInputStream(zipEntry) : null;
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		ZipEntry zipEntry = fsIndex.getMetadata(file);
		if (zipEntry == null) {
			return null;
		}
		return fsService.getDerivedByteProvider(
			fsFSRL.getContainer(),
			file.getFSRL(),
			zipEntry.getName(),
			zipEntry.getSize(),
			() -> zipFile.getInputStream(zipEntry),
			monitor);
	}
}
