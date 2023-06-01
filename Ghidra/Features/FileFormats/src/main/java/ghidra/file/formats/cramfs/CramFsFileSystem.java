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
package ghidra.file.formats.cramfs;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "cramfs", description = "CRAMFS", factory = GFileSystemBaseFactory.class)
public class CramFsFileSystem extends GFileSystemBase {

	private boolean isLittleEndian;
	private CramFsSuper cramFsSuper;

	private Map<GFile, CramFsInode> fileToInodeMap = new HashMap<>();

	private List<GFile> rootListing = new ArrayList<>();

	private Map<GFile, List<GFile>> directoryToChildMap = new HashMap<>();

	public CramFsFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		byte[] bytes = provider.readBytes(0, 4);
		DataConverter[] dataConverter =
			new DataConverter[] { new LittleEndianDataConverter(), new BigEndianDataConverter() };

		for (int i = 0; i < dataConverter.length; i++) {
			if (dataConverter[i].getInt(bytes) == CramFsConstants.MAGIC) {
				isLittleEndian = !dataConverter[i].isBigEndian();
				return true;
			}
		}

		return false;
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {
		BinaryReader reader = new BinaryReader(provider, isLittleEndian);
		cramFsSuper = new CramFsSuper(reader);
		if (cramFsSuper.isExtensionsBlockPointerFlagEnabled()) {
			throw new IOException("Extended Block Pointer flag is set, currently unsupported");
		}

		List<CramFsInode> childList = cramFsSuper.getChildList();
		Map<Long, CramFsInode> subDirectoryMap = new HashMap<>();

		GFile parent = root;

		for (CramFsInode cramFsInode : childList) {
			monitor.checkCancelled();

			if (cramFsInode.isDirectory()) {
				subDirectoryMap.put((long) cramFsInode.getOffsetAdjusted(), cramFsInode);
			}

			if (subDirectoryMap.containsKey(cramFsInode.getAddress())) {
				break;
			}

			GFileImpl iNodeFile = GFileImpl.fromPathString(this, parent, cramFsInode.getName(),
				null, cramFsInode.isDirectory(), cramFsInode.getSize());

			fileToInodeMap.put(iNodeFile, cramFsInode);

			rootListing.add(iNodeFile);
		}
	}

	/**
	 * Small utility to search childList for specific cramFsInode by name.
	 * @param targetName the name of the cramFsInode we are searching for.
	 * @return the target cramFs Inode.
	 */
	private CramFsInode getChildInodeByName(String targetName) {
		CramFsInode target = null;
		List<CramFsInode> childList = cramFsSuper.getChildList();

		for (CramFsInode cramFsInode : childList) {
			if (cramFsInode.getName().contentEquals(targetName)) {
				target = cramFsInode;
				break;
			}
		}
		return target;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {

		//Return listing for root directory, should be first listing returned anyway. 
		//Checking for null fixed some issues as well.
		if (directory == root || directory == null) {
			return rootListing;
		}

		if (directoryToChildMap.containsKey(directory)) {
			return directoryToChildMap.get(directory);
		}

		CramFsInode parentInode = getChildInodeByName(directory.getName());
		//Store current inode and size info in a counter.
		int directoryLength = parentInode.getSize();

		List<GFile> directoryListing = populateChildList(directory, parentInode, directoryLength);

		directoryToChildMap.put(directory, directoryListing);
		return directoryListing;
	}

	private List<GFile> populateChildList(GFile directory, CramFsInode parentInode,
			int directoryLength) {

		List<CramFsInode> childList = cramFsSuper.getChildList();

		List<GFile> directoryListing = new ArrayList<>();

		int startIndex = computeStartIndex(childList, parentInode);
		for (int i = startIndex; i < childList.size(); i++) {
			if (directoryLength <= 0) {
				break;
			}

			CramFsInode entryInode = childList.get(i);
			GFileImpl iNodeFile = GFileImpl.fromPathString(this, directory, entryInode.getName(),
				null, entryInode.isDirectory(), entryInode.getSize());

			directoryListing.add(iNodeFile);
			directoryLength -= (CramFsConstants.INODE_SIZE + (entryInode.getNamelen() * 4));
			fileToInodeMap.put(iNodeFile, entryInode);
		}

		return directoryListing;
	}

	/**
	 * Used to find the first entry in a directory from the list of child inodes.
	 * @param childList the list of child inodes.
	 * @param parentInode the parent cramFsInode.
	 * @return the start index in a directory.
	 */
	private int computeStartIndex(List<CramFsInode> childList, CramFsInode parentInode) {

		int startIndex = 0;

		//Iterate through full childlist until an inode address matches the directory offset.
		for (int i = 0; i < childList.size(); i++) {
			if (childList.get(i).getAddress() == parentInode.getOffsetAdjusted()) {
				startIndex = i;
				break;
			}
		}
		return startIndex;
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {

		CramFsInode childInode = fileToInodeMap.get(file);

		if (childInode.getSize() >= 0xffffff) {
			throw new IOException("File is larger than 16MB and was clipped, cannot open.");
		}

		ByteProvider fileBP = fsService.getDerivedByteProvider(provider.getFSRL(), file.getFSRL(),
			file.getPath(), childInode.getSize(), () -> {
				return new LazyCramFsInputStream(provider, childInode,
					cramFsSuper.isLittleEndian());
			}, monitor);

		return fileBP;
	}

}
