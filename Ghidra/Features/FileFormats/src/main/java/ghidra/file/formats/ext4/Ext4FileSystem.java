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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
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

	public Ext4FileSystem(FSRLRoot fsrl, ByteProvider provider) {
		this.fsrl = fsrl;
		this.fsih = new FileSystemIndexHelper<>(this, fsrl);
		this.provider = provider;
	}

	public void mountFS(TaskMonitor monitor) throws IOException, CancelledException {
		BinaryReader reader = new BinaryReader(provider, true);
		reader.setPointerIndex(0x400);

		Ext4SuperBlock superBlock = new Ext4SuperBlock(reader);

		this.volumeName = superBlock.getVolumeName();

		this.uuid = NumericUtilities.convertBytesToString(superBlock.getS_uuid());

		int s_log_block_size = superBlock.getS_log_block_size();
		blockSize = (int) Math.pow(2, (10 + s_log_block_size));

		int groupSize = blockSize * superBlock.getS_blocks_per_group();
		if (groupSize <= 0) {
			throw new IOException("Invalid groupSize: " + groupSize);
		}
		int numGroups = (int) (provider.length() / groupSize);
		if (provider.length() % groupSize != 0) {
			numGroups++;
		}

		boolean is64Bit =
			(superBlock.getS_desc_size() > 32) && ((superBlock.getS_feature_incompat() & 0x80) > 0);

		int groupDescriptorOffset = blockSize;
		reader.setPointerIndex(groupDescriptorOffset);
		Ext4GroupDescriptor[] groupDescriptors = new Ext4GroupDescriptor[numGroups];
		for (int i = 0; i < numGroups; i++) {
			monitor.checkCanceled();
			groupDescriptors[i] = new Ext4GroupDescriptor(reader, is64Bit);
			monitor.incrementProgress(1);
		}

		Ext4Inode[] inodes = getInodes(reader, superBlock, groupDescriptors, is64Bit, monitor);

		int s_inodes_count = superBlock.getS_inodes_count();
		for (int i = 0; i < s_inodes_count; i++) {
			Ext4Inode inode = inodes[i];
			if (inode == null) {
				continue;
			}
			if ((inode.getI_mode() & Ext4Constants.I_MODE_MASK) == Ext4Constants.S_IFDIR) {
				processDirectory(reader, superBlock, inodes, i, null, null, monitor);
			}
			else if ((inode.getI_mode() & Ext4Constants.I_MODE_MASK) == Ext4Constants.S_IFREG) {
				processFile(reader, superBlock, inode, monitor);
			}
		}
	}

	private void processDirectory(BinaryReader reader, Ext4SuperBlock superBlock,
			Ext4Inode[] inodes, int index, String name, GFile parent, TaskMonitor monitor)
			throws IOException, CancelledException {

		if (name != null && (name.equals(".") || name.equals(".."))) {
			return;
		}
		Ext4Inode inode = inodes[index];
		if (name == null && parent == null) {
			parent = fsih.getRootDir();
		}
		else {
			if (parent == null) {
				parent = fsih.getRootDir();
			}
			parent = fsih.storeFileWithParent(name, parent, -1, true, inode.getSize(),
				new Ext4File(name, inode));
		}
		if ((inode.getI_flags() & Ext4Constants.EXT4_EXTENTS_FL) == 0) {
			return;
		}
		boolean isDirEntry2 =
			(superBlock.getS_feature_incompat() & Ext4Constants.INCOMPAT_FILETYPE) != 0;
		// if uses extents
		if ((inode.getI_flags() & Ext4Constants.EXT4_EXTENTS_FL) != 0) {
			Ext4IBlock i_block = inode.getI_block();
			processIBlock(reader, superBlock, inodes, parent, isDirEntry2, i_block, monitor);
		}
		else {
			throw new IOException("File system fails to use extents.");
		}
		inodes[index] = null;
	}

	private void processIBlock(BinaryReader reader, Ext4SuperBlock superBlock, Ext4Inode[] inodes,
			GFile parent, boolean isDirEntry2, Ext4IBlock i_block, TaskMonitor monitor)
			throws CancelledException, IOException {
		Ext4ExtentHeader header = i_block.getHeader();
		if (header.getEh_depth() == 0) {
			short numEntries = header.getEh_entries();
			List<Ext4Extent> entries = i_block.getExtentEntries();
			for (int i = 0; i < numEntries; i++) {
				monitor.checkCanceled();
				Ext4Extent extent = entries.get(i);
				long offset = extent.getExtentStartBlockNumber() * blockSize;
				reader.setPointerIndex(offset);
				if (isDirEntry2) {
					processDirEntry2(reader, superBlock, inodes, parent, monitor, extent, offset);
				}
				else {
					processDirEntry(reader, superBlock, inodes, parent, monitor, extent, offset);
				}
			}
		}
		else {
			//throw new IOException( "Unhandled extent tree depth > 0 for inode " + index );
			short numEntries = header.getEh_entries();
			List<Ext4ExtentIdx> entries = i_block.getIndexEntries();
			for (int i = 0; i < numEntries; i++) {
				monitor.checkCanceled();

				Ext4ExtentIdx extentIndex = entries.get(i);
				long lo = extentIndex.getEi_leaf_lo();
				long hi = extentIndex.getEi_leaf_hi();
				long physicalBlockOfNextLevel = (hi << 16) | lo;
				long offset = physicalBlockOfNextLevel * blockSize;

//				System.out.println( ""+physicalBlockOfNextLevel );
//				System.out.println( "" );

				reader.setPointerIndex(offset);
				Ext4IBlock intermediateBlock = new Ext4IBlock(reader, true);
				processIBlock(reader, superBlock, inodes, parent, isDirEntry2, intermediateBlock,
					monitor);
			}
		}
	}

	private void processDirEntry(BinaryReader reader, Ext4SuperBlock superBlock, Ext4Inode[] inodes,
			GFile parent, TaskMonitor monitor, Ext4Extent extent, long offset)
			throws CancelledException, IOException {

		while ((reader.getPointerIndex() - offset) < ((long) extent.getEe_len() * blockSize)) {
			monitor.checkCanceled();
			if (reader.peekNextInt() == 0) {
				return;
			}
			Ext4DirEntry dirEnt = new Ext4DirEntry(reader);
			int childIndex = dirEnt.getInode();
			Ext4Inode child = inodes[childIndex];
			if ((child.getI_mode() & Ext4Constants.I_MODE_MASK) == Ext4Constants.S_IFDIR) {
				String childName = dirEnt.getName();
				long readerOffset = reader.getPointerIndex();
				processDirectory(reader, superBlock, inodes, childIndex, childName, parent,
					monitor);
				reader.setPointerIndex(readerOffset);
			}
			else if ((child.getI_mode() & Ext4Constants.I_MODE_MASK) == Ext4Constants.S_IFREG ||
				(child.getI_mode() & Ext4Constants.I_MODE_MASK) == Ext4Constants.S_IFLNK) {
				storeFile(inodes, dirEnt, parent);
			}
			else {
				throw new IOException("Inode " + dirEnt.getInode() + " has unhandled file type: " +
					(child.getI_mode() & 0xF000));
			}
		}
	}

	private void processDirEntry2(BinaryReader reader, Ext4SuperBlock superBlock,
			Ext4Inode[] inodes, GFile parent, TaskMonitor monitor, Ext4Extent extent, long offset)
			throws CancelledException, IOException {

		while ((reader.getPointerIndex() - offset) < ((long) extent.getEe_len() * blockSize)) {
			monitor.checkCanceled();
			if (reader.peekNextInt() == 0) {
				return;
			}
			Ext4DirEntry2 dirEnt2 = new Ext4DirEntry2(reader);
			if (dirEnt2.getFile_type() == Ext4Constants.FILE_TYPE_DIRECTORY) {
				int childInode = dirEnt2.getInode();
				String childName = dirEnt2.getName();
				long readerOffset = reader.getPointerIndex();
				processDirectory(reader, superBlock, inodes, childInode, childName, parent,
					monitor);
				reader.setPointerIndex(readerOffset);
			}
			else if (dirEnt2.getFile_type() == Ext4Constants.FILE_TYPE_REGULAR_FILE ||
				dirEnt2.getFile_type() == Ext4Constants.FILE_TYPE_SYMBOLIC_LINK) {
				storeFile(inodes, dirEnt2, parent);
			}
			else {
				throw new IOException("Inode " + dirEnt2.getInode() + " has unhandled file type: " +
					dirEnt2.getFile_type());
			}
		}
	}

	private void storeFile(Ext4Inode[] inodes, Ext4DirEntry dirEnt, GFile parent) {
		int fileInodeNum = dirEnt.getInode();
		Ext4Inode fileInode = inodes[fileInodeNum];
		fsih.storeFileWithParent(dirEnt.getName(), parent, -1,
			(fileInode.getI_mode() & Ext4Constants.I_MODE_MASK) == Ext4Constants.S_IFDIR,
			fileInode.getSize(), new Ext4File(dirEnt.getName(), fileInode));
		inodes[fileInodeNum] = null;
	}

	private void storeFile(Ext4Inode[] inodes, Ext4DirEntry2 dirEnt2, GFile parent) {
		int fileInodeNum = dirEnt2.getInode();
		Ext4Inode fileInode = inodes[fileInodeNum];
		if (fileInode == null) {
			return;//TODO
		}
		fsih.storeFileWithParent(dirEnt2.getName(), parent, -1,
			dirEnt2.getFile_type() == Ext4Constants.FILE_TYPE_DIRECTORY, fileInode.getSize(),
			new Ext4File(dirEnt2.getName(), fileInode));
		inodes[fileInodeNum] = null;
	}

	private void processFile(BinaryReader reader, Ext4SuperBlock superBlock, Ext4Inode inode,
			TaskMonitor monitor) {

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
	public String getInfo(GFile file, TaskMonitor monitor) {
		Ext4File ext4File = fsih.getMetadata(file);
		if (ext4File == null) {
			return null;
		}
		Ext4Inode inode = ext4File.getInode();
		String info = "";
		long size = inode.getSize();
		if ((inode.getI_mode() & Ext4Constants.I_MODE_MASK) == Ext4Constants.S_IFLNK) {
			Ext4IBlock block = inode.getI_block();
			byte[] extra = block.getExtra();
			info = "Symlink to \"" + new String(extra).trim() + "\"\n";
		}
		else {
			info = "File size:  0x" + Long.toHexString(size);
		}
		return info;
	}

	@Override
	public InputStream getInputStream(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		ByteProvider bp = getByteProvider(file, monitor);
		return (bp != null) ? new ByteProviderInputStream(bp, 0, bp.length()) : null;
	}

	private static final int MAX_SYMLINK_LOOKUP_COUNT = 100;

	private Ext4Inode resolveSymLink(GFile file) throws IOException {
		int lookupCount = 0;
		while (file != null && lookupCount < MAX_SYMLINK_LOOKUP_COUNT) {
			Ext4File extFile = fsih.getMetadata(file);
			Ext4Inode inode = extFile.getInode();
			if ((inode.getI_mode() & Ext4Constants.I_MODE_MASK) != Ext4Constants.S_IFLNK) {
				return inode;
			}

			Ext4IBlock block = inode.getI_block();
			byte[] extra = block.getExtra();

			String symlinkDestPath = new String(extra).trim();
			if (!symlinkDestPath.startsWith("/")) {
				if (file.getParentFile() == null) {
					throw new IOException("Not parent file for " + file);
				}
				symlinkDestPath =
					FSUtilities.appendPath(file.getParentFile().getPath(), symlinkDestPath);
			}

			file = lookup(symlinkDestPath);
			lookupCount++;
		}
		return null;
	}

	private Ext4Inode getInodeFor(GFile file) throws IOException {
		Ext4File extFile = fsih.getMetadata(file);
		if (extFile == null) {
			return null;
		}
		Ext4Inode inode = extFile.getInode();
		if (inode == null) {
			return null;
		}

		if ((inode.getI_mode() & Ext4Constants.I_MODE_MASK) == Ext4Constants.S_IFLNK) {
			inode = resolveSymLink(file);
			if (inode == null) {
				throw new IOException(extFile.getName() + " is a broken symlink.");
			}
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
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) throws IOException {
		Ext4Inode inode = getInodeFor(file);
		if (inode == null) {
			return null;
		}

		if ((inode.getI_mode() & Ext4Constants.I_MODE_MASK) == Ext4Constants.S_IFDIR) {
			throw new IOException(file.getName() + " is a directory.");
		}

		boolean usesExtents = (inode.getI_flags() & Ext4Constants.EXT4_EXTENTS_FL) != 0;
		if (!usesExtents) {
			throw new IOException("Unsupported file storage: not EXT4_EXTENTS: " + file.getPath());
		}

		Ext4IBlock i_block = inode.getI_block();
		Ext4ExtentHeader header = i_block.getHeader();
		if (header.getEh_depth() != 0) {
			throw new IOException("Unsupported file storage: eh_depth: " + file.getPath());
		}

		long fileSize = inode.getSize();
		ExtentsByteProvider ebp = new ExtentsByteProvider(provider, file.getFSRL());
		for (Ext4Extent extent : i_block.getExtentEntries()) {
			long startPos = extent.getStreamBlockNumber() * blockSize;
			long providerOfs = extent.getExtentStartBlockNumber() * blockSize;
			long extentLen = extent.getExtentBlockCount() * blockSize;
			if (ebp.length() < startPos) {
				ebp.addSparseExtent(startPos - ebp.length());
			}
			if (ebp.length() + extentLen > fileSize) {
				// the last extent may have a trailing partial block
				extentLen = fileSize - ebp.length();
			}

			ebp.addExtent(providerOfs, extentLen);
		}
		if (ebp.length() < fileSize) {
			// trailing sparse.  not sure if possible.
			ebp.addSparseExtent(fileSize - ebp.length());
		}
		return ebp;
	}

	private Ext4Inode[] getInodes(BinaryReader reader, Ext4SuperBlock superBlock,
			Ext4GroupDescriptor[] groupDescriptors, boolean is64Bit, TaskMonitor monitor)
			throws IOException, CancelledException {

		int inodeCount = superBlock.getS_inodes_count();
		Ext4Inode[] inodes = new Ext4Inode[inodeCount + 1];
		int inodeIndex = 1;

		for (int i = 0; i < groupDescriptors.length; i++) {
			monitor.checkCanceled();
			long inodeTableBlockOffset = groupDescriptors[i].getBg_inode_table_lo() & 0xffffffffL;
			if (is64Bit) {
				inodeTableBlockOffset =
					(groupDescriptors[i].getBg_inode_table_hi() << 32) | inodeTableBlockOffset;
			}
			long offset = inodeTableBlockOffset * blockSize;
			reader.setPointerIndex(offset);
			int inodesPerGroup = superBlock.getS_inodes_per_group();
			monitor.setMessage(
				"Reading inode table " + i + " of " + (groupDescriptors.length - 1) + "...");
			monitor.setMaximum(inodesPerGroup);
			monitor.setProgress(0);
			for (int j = 0; j < inodesPerGroup; j++) {
				monitor.checkCanceled();
				monitor.incrementProgress(1);

				Ext4Inode inode = new Ext4Inode(reader);
				offset = offset + superBlock.getS_inode_size();
				reader.setPointerIndex(offset);

				inodes[inodeIndex++] = inode; //inodes[ inodesPerGroup * i + j ] = inode;
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
