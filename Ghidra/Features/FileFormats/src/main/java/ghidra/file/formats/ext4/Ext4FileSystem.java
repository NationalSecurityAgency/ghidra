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
package ghidra.file.formats.ext4;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;

import ghidra.app.util.bin.*;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.formats.gfilesystem.fileinfo.FileType;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "ext4", description = "EXT4", factory = Ext4FileSystemFactory.class)
public class Ext4FileSystem implements GFileSystem {

	public static final Charset EXT4_DEFAULT_CHARSET = StandardCharsets.UTF_8;

	private FileSystemIndexHelper<Ext4File> fsih;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);
	private FSRLRoot fsrl;
	private int blockSize;
	private ByteProvider provider;
	private String volumeName;
	private String uuid;
	private Ext4SuperBlock superBlock;

	public Ext4FileSystem(FSRLRoot fsrl, ByteProvider provider) {
		this.fsrl = fsrl;
		this.fsih = new FileSystemIndexHelper<>(this, fsrl);
		this.provider = provider;
	}

	public void mountFS(TaskMonitor monitor) throws IOException, CancelledException {
		BinaryReader reader = new BinaryReader(provider, true);
		reader.setPointerIndex(Ext4Constants.SUPER_BLOCK_START);
		this.superBlock = new Ext4SuperBlock(reader);
		this.volumeName = superBlock.getVolumeName();
		this.uuid = NumericUtilities.convertBytesToString(superBlock.getS_uuid());

		long blockCount = superBlock.getS_blocks_count();
		int s_log_block_size = superBlock.getS_log_block_size();
		this.blockSize = (int) Math.pow(2, (10 + s_log_block_size));

		int groupSize = blockSize * superBlock.getS_blocks_per_group();
		if (groupSize <= 0) {
			throw new IOException("Invalid groupSize: " + groupSize);
		}
		int numGroups = (int) (blockCount / superBlock.getS_blocks_per_group());
		if (blockCount % superBlock.getS_blocks_per_group() != 0) {
			numGroups++;
		}

		int groupDescriptorOffset = blockSize + (superBlock.getS_first_data_block() * blockSize);
		reader.setPointerIndex(groupDescriptorOffset);
		monitor.initialize(numGroups);
		monitor.setMessage("Reading inode tables");
		Ext4GroupDescriptor[] groupDescriptors = new Ext4GroupDescriptor[numGroups];
		for (int i = 0; i < numGroups; i++) {
			monitor.checkCanceled();
			groupDescriptors[i] = new Ext4GroupDescriptor(reader, superBlock.is64Bit());
			monitor.incrementProgress(1);
		}

		Ext4Inode[] inodes = getInodes(reader, groupDescriptors, monitor);

		// process entries in root directory
		Ext4Inode rootDirInode = inodes[Ext4Constants.EXT4_INODE_INDEX_ROOTDIR];
		if (!rootDirInode.isDir()) {
			throw new IOException("Unable to find root directory inode");
		}
		int usedInodeCount = superBlock.getS_inodes_count() - superBlock.getS_free_inodes_count();
		monitor.setMessage("Indexing files");
		monitor.initialize(usedInodeCount);

		BitSet processedInodes = new BitSet(inodes.length);
		processDirectory(inodes[Ext4Constants.EXT4_INODE_INDEX_ROOTDIR], fsih.getRootDir(), inodes,
			processedInodes, monitor);
		checkUnprocessedInodes(inodes, processedInodes);
	}

	private void checkUnprocessedInodes(Ext4Inode[] inodes, BitSet processedInodes) {
		int count = 0;
		for (int inodeNum = processedInodes
				.nextClearBit(superBlock.getS_first_ino()); inodeNum < inodes.length; inodeNum =
					processedInodes.nextClearBit(inodeNum + 1)) {
			if (!inodes[inodeNum].isUnused()) {
				count++;
			}
		}
		if (count > 0) {
			Msg.warn(this, "Unprocessed inodes: " + count);
		}
	}

	private void processDirectory(Ext4Inode inode, GFile dirFile, Ext4Inode[] inodes,
			BitSet processedInodes, TaskMonitor monitor) throws IOException, CancelledException {
		try (ByteProvider bp = getInodeByteProvider(inode, dirFile.getFSRL(), monitor)) {
			processDirectoryStream(bp, dirFile, inodes, processedInodes, monitor);
		}
	}

	private void processDirectoryStream(ByteProvider directoryStream, GFile dirGFile,
			Ext4Inode[] inodes, BitSet processedInodes, TaskMonitor monitor)
			throws CancelledException, IOException {
		boolean isdir2 = superBlock.isDirEntry2();
		BinaryReader reader = new BinaryReader(directoryStream, true /* LE */);
		Ext4DirEntry dirEnt;
		while ((dirEnt = isdir2 ? Ext4DirEntry2.read(reader) : Ext4DirEntry.read(reader)) != null) {
			monitor.checkCanceled();
			if (dirEnt.isUnused()) {
				continue;
			}
			processDirEntry(dirEnt, dirGFile, inodes, processedInodes, monitor);
			monitor.incrementProgress(1);
		}
	}

	private void processDirEntry(Ext4DirEntry dirEntry, GFile parentDir, Ext4Inode[] inodes,
			BitSet processedInodes, TaskMonitor monitor) throws IOException, CancelledException {
		int inodeNumber = dirEntry.getInode();
		if (inodeNumber <= 0 || inodeNumber >= inodes.length) {
			Msg.warn(this, "Invalid inode number: " + inodeNumber);
			return;
		}
		Ext4Inode inode = inodes[inodeNumber];
		if (inode == null || inode.isUnused()) {
			Msg.warn(this, "Reference to bad inode: " + inodeNumber);
			return;
		}
		if (!(inode.isDir() || inode.isFile() || inode.isSymLink())) {
			throw new IOException("Inode " + inode + " has unhandled file type: " +
				Integer.toHexString(inode.getFileType()));
		}

		String name = dirEntry.getName();
		if (".".equals(name) || "..".equals(name)) {
			// skip the ".", and ".." self-reference directories
			return;
		}

		GFile gfile = fsih.storeFileWithParent(name, parentDir, -1, inode.isDir(), inode.getSize(),
			new Ext4File(name, inode));
		if (processedInodes.get(inodeNumber)) {
			// this inode was already seen and handled earlier. adding a second filename to the fsih is
			// okay, but don't try to process as a directory, which shouldn't normally be possible
			// anyway.
			return;
		}
		processedInodes.set(inodeNumber);
		if (inode.isDir()) {
			processDirectory(inode, gfile, inodes, processedInodes, monitor);
		}
	}

	@Override
	public int getFileCount() {
		return fsih.getFileCount();
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsih.getListing(directory);
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		FileAttributes result = new FileAttributes();

		Ext4File ext4File = fsih.getMetadata(file);
		if (ext4File != null) {
			Ext4Inode inode = ext4File.getInode();
			result.add(NAME_ATTR, ext4File.getName());
			result.add(SIZE_ATTR, inode.getSize());
			result.add(FILE_TYPE_ATTR, inodeToFileType(inode));
			if (inode.isSymLink()) {
				String symLinkDest = "unknown";
				try {
					symLinkDest = readLink(file, ext4File, monitor);
				}
				catch (IOException e) {
					// fall thru with default value
				}
				result.add(SYMLINK_DEST_ATTR, symLinkDest);
			}
			result.add(MODIFIED_DATE_ATTR, new Date(inode.getI_mtime() * 1000));
			result.add(UNIX_ACL_ATTR, (long) (inode.getI_mode() & 0xFFF));
			result.add(USER_ID_ATTR, Short.toUnsignedLong(inode.getI_uid()));
			result.add(GROUP_ID_ATTR, Short.toUnsignedLong(inode.getI_gid()));
			result.add("Link Count", inode.getI_links_count());
		}
		return result;
	}

	FileType inodeToFileType(Ext4Inode inode) {
		if (inode.isDir()) {
			return FileType.DIRECTORY;
		}
		if (inode.isSymLink()) {
			return FileType.SYMBOLIC_LINK;
		}
		if (inode.isFile()) {
			return FileType.FILE;
		}
		return FileType.UNKNOWN;
	}

	private static final int MAX_SYMLINK_LOOKUP_COUNT = 100;

	private Ext4Inode resolveSymLink(GFile file, TaskMonitor monitor) throws IOException {
		int lookupCount = 0;
		GFile currentFile = file;
		StringBuilder symlinkDebugPath = new StringBuilder();
		while (true) {
			if (lookupCount++ > MAX_SYMLINK_LOOKUP_COUNT) {
				throw new IOException(
					"Symlink too long: " + file.getPath() + ", " + symlinkDebugPath);
			}
			Ext4File extFile = fsih.getMetadata(currentFile);
			if (extFile == null) {
				throw new IOException("Missing Ext4 metadata for " + currentFile.getPath());
			}
			Ext4Inode inode = extFile.getInode();
			if (!inode.isSymLink()) {
				return inode;
			}
			
			String symlinkDestPath = readLink(file, extFile, monitor);
			symlinkDebugPath.append(" -> ").append(symlinkDestPath);
			if (!symlinkDestPath.startsWith("/")) {
				if (currentFile.getParentFile() == null) {
					throw new IOException("No parent file for " + currentFile);
				}
				symlinkDestPath =
					FSUtilities.appendPath(currentFile.getParentFile().getPath(),
						symlinkDestPath);
			}

			currentFile = lookup(symlinkDestPath);
			if (currentFile == null) {
				throw new IOException("Missing symlink dest: " + file.getPath() +
					", broken symlink: " + symlinkDebugPath);
			}
		}
	}

	private String readLink(GFile file, Ext4File extFile, TaskMonitor monitor) throws IOException {
		try (ByteProvider bp = getInodeByteProvider(extFile.getInode(), file.getFSRL(), monitor)) {
			byte[] tmp = bp.readBytes(0, bp.length());
			return new String(tmp, StandardCharsets.UTF_8);
		}
	}

	private Ext4Inode getInodeFor(GFile file, TaskMonitor monitor) throws IOException {
		Ext4File extFile = fsih.getMetadata(file);
		if (extFile == null) {
			return null;
		}
		Ext4Inode inode = extFile.getInode();
		if (inode == null) {
			return null;
		}

		if (inode.isSymLink()) {
			inode = resolveSymLink(file, monitor);
		}
		return inode;
	}

	/**
	 * Returns a {@link ByteProvider} that supplies the bytes of the requested file.
	 * 
	 * @param file {@link GFile} to get
	 * @param monitor {@link TaskMonitor} to cancel
	 * @return {@link ByteProvider} containing the bytes of the requested file, caller is
	 * responsible for closing the ByteProvider
	 * @throws IOException if error
	 */
	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) throws IOException {
		Ext4Inode inode = getInodeFor(file, monitor);
		if (inode == null) {
			return null;
		}

		if (inode.isDir()) {
			throw new IOException(file.getName() + " is a directory.");
		}

		return getInodeByteProvider(inode, file.getFSRL(), monitor);
	}

	private ByteProvider getInodeByteProvider(Ext4Inode inode, FSRL inodeFSRL, TaskMonitor monitor)
			throws IOException {
		if (inode.isFlagExtents()) {
			return Ext4ExtentsHelper.getByteProvider(inode.getI_block(), provider, inode.getSize(),
				blockSize, inodeFSRL);
		}
		else if (inode.isFlagInlineData() || inode.isSymLink()) {
			byte[] data = inode.getInlineDataValue();
			return new ByteArrayProvider(data, inodeFSRL);
		}
		else {
			return Ext4BlockMapHelper.getByteProvider(inode.getI_block(), provider, inode.getSize(),
				blockSize, inodeFSRL);
		}
	}

	private Ext4Inode[] getInodes(BinaryReader reader, Ext4GroupDescriptor[] groupDescriptors,
			TaskMonitor monitor) throws IOException, CancelledException {

		int inodeCount = superBlock.getS_inodes_count();
		int inodesPerGroup = superBlock.getS_inodes_per_group();
		Ext4Inode[] inodes = new Ext4Inode[inodeCount + 1];
		int inodeIndex = 1;

		for (int i = 0; i < groupDescriptors.length; i++) {
			monitor.checkCanceled();
			long inodeTableBlockOffset = groupDescriptors[i].getBg_inode_table();
			long offset = inodeTableBlockOffset * blockSize;
			reader.setPointerIndex(offset);
			monitor.setMessage(
				"Reading inode table " + i + " of " + (groupDescriptors.length - 1) + "...");
			monitor.initialize(inodesPerGroup);
			for (int j = 0; j < inodesPerGroup; j++) {
				monitor.checkCanceled();
				monitor.incrementProgress(1);

				Ext4Inode inode = new Ext4Inode(reader, superBlock.getS_inode_size());
				offset = offset + superBlock.getS_inode_size();
				reader.setPointerIndex(offset);

				inodes[inodeIndex++] = inode;
			}
		}
		return inodes;
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		provider.close();
		provider = null;
		fsih.clear();
	}

	@Override
	public String getName() {
		return fsrl.getContainer().getName() + " - " + volumeName + " - " + uuid;
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsrl;
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsih.lookup(path);
	}

}
