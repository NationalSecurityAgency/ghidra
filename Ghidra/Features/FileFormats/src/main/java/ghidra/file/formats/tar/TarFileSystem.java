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
package ghidra.file.formats.tar;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.IOException;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TAR file system implementation.
 * <p>
 * The factory supports detecting both compressed (gz) and uncompressed tar files,
 * and keys both on the tar filename extension as well as the data in the file.
 * <p>
 */
@FileSystemInfo(type = "tar", description = "TAR", priority = FileSystemInfo.PRIORITY_HIGH, factory = TarFileSystemFactory.class)
public class TarFileSystem extends AbstractFileSystem<TarMetadata> {

	private ByteProvider provider;
	private int fileCount;

	/**
	 * Creates a new TarFileSystem instance.
	 *
	 * @param fsrl {@link FSRLRoot} of the new filesystem.
	 * @param provider {@link ByteProvider} container file
	 * @param fsService reference to the {@link FileSystemService}.
	 */
	public TarFileSystem(FSRLRoot fsrl, ByteProvider provider, FileSystemService fsService) {
		super(fsrl, fsService);

		this.provider = provider;
	}

	ByteProvider getProvider() {
		return provider;
	}

	void mount(TaskMonitor monitor) throws IOException, CancelledException {
		try (TarArchiveInputStream tarInput =
			new TarArchiveInputStream(provider.getInputStream(0))) {
			TarArchiveEntry tarEntry;
			while ((tarEntry = tarInput.getNextTarEntry()) != null) {
				monitor.setMessage(tarEntry.getName());
				monitor.checkCancelled();

				int fileNum = fileCount++;
				String linkName = tarEntry.getLinkName();
				GFile newFile = !tarEntry.isSymbolicLink()
						? fsIndex.storeFile(tarEntry.getName(), fileCount, tarEntry.isDirectory(),
							tarEntry.getSize(), new TarMetadata(tarEntry, fileNum))
						: fsIndex.storeSymlink(tarEntry.getName(), fileCount,
							linkName, linkName.length(), new TarMetadata(tarEntry, fileNum));

				if (!tarEntry.isSymbolicLink() &&
					tarEntry.getSize() < FileCache.MAX_INMEM_FILESIZE) {
					// because tar files are sequential access, we cache smaller files if they
					// will fit in a in-memory ByteProvider
					try (ByteProvider bp =
						fsService.getDerivedByteProvider(fsFSRL.getContainer(), newFile.getFSRL(),
							newFile.getPath(), tarEntry.getSize(), () -> tarInput, monitor)) {
						fsIndex.updateFSRL(newFile,
							newFile.getFSRL().withMD5(bp.getFSRL().getMD5()));
					}
				}
			}
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
		TarMetadata tmd = fsIndex.getMetadata(file);
		if (tmd == null) {
			return FileAttributes.EMPTY;
		}
		TarArchiveEntry blob = tmd.tarArchiveEntry;
		return FileAttributes.of(
			FileAttribute.create(NAME_ATTR, blob.getName()),
			FileAttribute.create(SIZE_ATTR, blob.getSize()),
			FileAttribute.create(MODIFIED_DATE_ATTR, blob.getLastModifiedDate()),
			FileAttribute.create(FILE_TYPE_ATTR, tarToFileType(blob)),
			FileAttribute.create(USER_NAME_ATTR, blob.getUserName()),
			FileAttribute.create(GROUP_NAME_ATTR, blob.getGroupName()),
			FileAttribute.create(USER_ID_ATTR, blob.getLongUserId()),
			FileAttribute.create(GROUP_ID_ATTR, blob.getLongGroupId()),
			FileAttribute.create(UNIX_ACL_ATTR, (long) blob.getMode()),
			blob.isSymbolicLink()
					? FileAttribute.create(SYMLINK_DEST_ATTR, blob.getLinkName())
					: null);
	}

	private FileType tarToFileType(TarArchiveEntry tae) {
		if (tae.isDirectory()) {
			return FileType.DIRECTORY;
		}
		if (tae.isSymbolicLink()) {
			return FileType.SYMBOLIC_LINK;
		}
		if (tae.isFile()) {
			return FileType.FILE;
		}
		return FileType.UNKNOWN;
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {

		GFile resolvedFile = fsIndex.resolveSymlinks(file);
		TarMetadata tmd = fsIndex.getMetadata(resolvedFile);
		if (tmd == null) {
			throw new IOException("Unknown file " + file);
		}

		ByteProvider fileBP = fsService.getDerivedByteProvider(provider.getFSRL(),
			resolvedFile.getFSRL(), resolvedFile.getPath(), tmd.tarArchiveEntry.getSize(), () -> {
				TarArchiveInputStream tarInput = new TarArchiveInputStream(provider.getInputStream(0));

				int fileNum = 0;
				TarArchiveEntry tarEntry;
				while ((tarEntry = tarInput.getNextTarEntry()) != null) {
					if (fileNum == tmd.fileNum) {
						if (!tmd.tarArchiveEntry.getName().equals(tarEntry.getName())) {
							throw new IOException(
								"Mismatch between filenum and tarEntry for " + resolvedFile);
						}
						return tarInput;
					}
					fileNum++;
				}
				throw new IOException("Could not find requested file " + resolvedFile);
			}, monitor);

		return fileBP;
	}
}

