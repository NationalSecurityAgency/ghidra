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
package ghidra.file.formats.iso9660;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "iso9660", description = "ISO 9660", factory = GFileSystemBaseFactory.class)
public class ISO9660FileSystem extends GFileSystemBase {

	//Possible locations for magic number
	private static final long[] SIGNATURE_PROBE_OFFSETS = new long[] { 0x8000L, 0x8800L, 0x9000L };

	//Location where the magic number was found
	private long signatureOffset;

	//Set true if the root level directory has been processed
	private boolean lookedAtRoot = false;

	private short logicalBlockSize;

	private ISO9660Header header;

	private Map<GFile, ISO9660Directory> fileToDirectoryMap = new HashMap<>();

	public ISO9660FileSystem(String fileSystemName, ByteProvider provider) {

		super(fileSystemName, provider);
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		for (long probeOffset : SIGNATURE_PROBE_OFFSETS) {
			if (isMagicSignatureAt(probeOffset + 1)) {
				// signature is at +1 offset from the start of the volume offset
				signatureOffset = probeOffset;
				return true;
			}
		}
		return false;
	}

	private boolean isMagicSignatureAt(long offset) throws IOException {
		int magicLen = ISO9660Constants.MAGIC_BYTES.length;
		long providerLen = provider.length();
		return (providerLen > offset + magicLen) &&
			Arrays.equals(provider.readBytes(offset, magicLen), ISO9660Constants.MAGIC_BYTES);
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {
		BinaryReader reader = new BinaryReader(provider, true);

		//Set start of pointer index of beginning of primary volume descriptor
		reader.setPointerIndex(signatureOffset);

		header = new ISO9660Header(reader);
		ISO9660VolumeDescriptor pvd = header.getPrimaryVolumeDescriptor();
		logicalBlockSize = pvd.getLogicalBlockSizeBE();
		ISO9660Directory rootDir = header.getPrimaryDirectory();

		//Get the list containing all directories at the root level of the file system
		List<ISO9660Directory> topLevel =
			createDirectoryList(reader, rootDir, pvd.getLogicalBlockSizeLE(), monitor);

		try {

			//Entry point for the this recursive function to process all nested
			//directories
			createDirectories(reader, topLevel, pvd.getLogicalBlockSizeLE(), monitor);
		}

		catch (Exception e) {
			Msg.showError(this, null, "Directory Creation Error",
				"Failed to create archive directories");

		}

	}

	@Override
	public void close() throws IOException {
		super.close();
		header = null;
		fileToDirectoryMap.clear();
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		if (directory == null || directory.equals(root)) {
			List<GFile> roots = new ArrayList<>();
			for (GFile file : fileToDirectoryMap.keySet()) {
				if (file.getParentFile() == root || file.getParentFile().equals(root)) {
					roots.add(file);
				}
			}
			return roots;
		}
		List<GFile> tmp = new ArrayList<>();
		for (GFile file : fileToDirectoryMap.keySet()) {
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
	public String getInfo(GFile file, TaskMonitor monitor) {
		ISO9660Directory dir = fileToDirectoryMap.get(file);
		if (dir != null) {
			return dir.toString();
		}
		return null;
	}

	/*
	 * Returns the actual file data from a given Gfile(linked to directory)
	 */
	@Override
	protected InputStream getData(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException, CryptoException {

		ByteProvider bp = getByteProvider(file, monitor);
		return bp != null ? bp.getInputStream(0) : null;
	}

	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		ISO9660Directory dir = fileToDirectoryMap.get(file);
		return dir.getByteProvider(provider, logicalBlockSize, file.getFSRL());
	}

	/*
	 * From a given parent directory create each child directory
	 * under that parent directory and add them to a list
	 */
	private ArrayList<ISO9660Directory> createDirectoryList(BinaryReader reader,
			ISO9660Directory parentDir, long blockSize, TaskMonitor monitor) throws IOException {

		ArrayList<ISO9660Directory> directoryList = new ArrayList<>();
		ISO9660Directory childDir = null;
		long dirIndex;
		long endIndex;

		//Get location from parent into child directory
		dirIndex = parentDir.getLocationOfExtentLE() * blockSize;
		endIndex = dirIndex + parentDir.getDataLengthLE();

		//while there is still more data in the current directory level
		while (dirIndex < endIndex) {
			reader.setPointerIndex(dirIndex);

			//If the next byte is not zero then create the directory
			if (reader.peekNextByte() != 0) {
				if (!lookedAtRoot) {
					childDir = new ISO9660Directory(reader);
					addAndStoreDirectory(monitor, directoryList, childDir);

				}

				//Root level has already been looked at
				else {
					if (parentDir.getName() != null) {
						childDir = new ISO9660Directory(reader, parentDir);
						addAndStoreDirectory(monitor, directoryList, childDir);
					}
				}
			}

			//Otherwise there is a gap in the data so keep looking forward
			//while still under the end index and create directory when data is
			//reached
			else {
				readWhileZero(reader, endIndex);

				//Create the data once the reader finds the next position
				//and not reached end index
				if (reader.getPointerIndex() < endIndex) {
					if (!lookedAtRoot) {
						childDir = new ISO9660Directory(reader);
						addAndStoreDirectory(monitor, directoryList, childDir);
						dirIndex = childDir.getVolumeIndex();
					}
					else {
						if (parentDir.getName() != null) {
							childDir = new ISO9660Directory(reader, parentDir);
							addAndStoreDirectory(monitor, directoryList, childDir);
							dirIndex = childDir.getVolumeIndex();
						}
					}
				}

			}
			dirIndex += childDir.getDirectoryRecordLength();
		}

		lookedAtRoot = true;
		return directoryList;
	}

	private void readWhileZero(BinaryReader reader, long endIndex) throws IOException {
		while (reader.peekNextByte() == 0) {

			//keep reading if all zeros until non zero is met or
			//end index reached
			if (reader.getPointerIndex() < endIndex) {
				reader.readNextByte();
			}
			else {
				break;
			}
		}
	}

	private void addAndStoreDirectory(TaskMonitor monitor,
			ArrayList<ISO9660Directory> directoryList, ISO9660Directory childDir) {

		directoryList.add(childDir);

		if (childDir.getName() != null) {
			storeDirectory(childDir, monitor);
		}
	}

	/*
	 * Recurses though each level of a directory structure
	 * in a depth-first manner
	 * and creates each directory also marking them in the binary
	 */
	private void createDirectories(BinaryReader reader, List<ISO9660Directory> directoryList,
			long blockSize, TaskMonitor monitor) throws DuplicateNameException, Exception {

		for (ISO9660Directory dir : directoryList) {

			//If the directory is a new level of directories
			//recurse down into the next level
			if (dir.isDirectoryFlagSet() && dir.getName() != null) {
				List<ISO9660Directory> dirs;
				dirs = createDirectoryList(reader, dir, blockSize, monitor);
				createDirectories(reader, dirs, blockSize, monitor);
			}
		}
		return;
	}

	/*
	 * Stores a gFile after finding its parent and its matching directory
	 */
	private void storeDirectory(ISO9660Directory directory, TaskMonitor monitor) {

		String dirName = directory.getName();
		boolean isDirectory = directory.isDirectoryFlagSet();
		int length = directory.getDataLengthLE();
		GFileImpl gFile = null;

		//Map does not contain entries yet since root level needs to be processed
		if (!lookedAtRoot) {
			gFile = GFileImpl.fromFilename(this, root, dirName, isDirectory, length, null);
			storeFile(gFile, directory);
		}
		else {
			//Root has been processed, all other entries must have a parent
			String parentDirName = directory.getParentDirectory().getName();
			for (GFile currGFile : fileToDirectoryMap.keySet()) {
				//Find the parent and store the file
				if (parentDirName.equals(currGFile.getName())) {
					gFile =
						GFileImpl.fromFilename(this, currGFile, dirName, isDirectory, length, null);
					storeFile(gFile, directory);
					break;
				}
			}
		}
	}

	private void storeFile(GFile file, ISO9660Directory directory) {
		if (file == null) {
			return;
		}
		if (file.equals(root)) {
			return;
		}
		if (!fileToDirectoryMap.containsKey(file) || fileToDirectoryMap.get(file) == null) {
			fileToDirectoryMap.put(file, directory);
		}
		GFile parentFile = file.getParentFile();
		storeFile(parentFile, null);
	}

}
