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
package ghidra.file.formats.android.bootimg;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.formats.gfilesystem.fileinfo.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(
	type = "androidvendorbootimg",
	description = "Android Vendor Boot Images",
	factory = GFileSystemBaseFactory.class
)
public class VendorBootImageFileSystem extends GFileSystemBase {

	private VendorBootImageHeader header;
	private List<GFileImpl> ramdiskFileList = new ArrayList<>();
	private GFileImpl dtbFile;
	private List<GFileImpl> fileList = new ArrayList<>();

	public VendorBootImageFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		byte[] bytes = provider.readBytes(0, BootImageConstants.VENDOR_BOOT_MAGIC_SIZE);
		return Arrays.equals(bytes, BootImageConstants.VENDOR_BOOT_MAGIC.getBytes());
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {

		this.header = VendorBootImageHeaderFactory.getVendorBootImageHeader(provider, true);

		if (!header.getMagic().equals(BootImageConstants.VENDOR_BOOT_MAGIC)) {
			throw new IOException("Invalid Android boot image file!");
		}

		if ( header.getNestedVendorRamdiskCount() > 1) {
			for (int i = 0; i < header.getNestedVendorRamdiskCount(); ++i) {
				if (header.getNestedVendorRamdiskSize(i) > 0) {
					GFileImpl ramdiskFile = GFileImpl.fromFilename(
						this, root, BootImageConstants.RAMDISK + "_" + i,
						false, header.getNestedVendorRamdiskSize(i), null);
					fileList.add(ramdiskFile);
					ramdiskFileList.add(ramdiskFile);
				}
			}
		}
		else {
			if (header.getVendorRamdiskSize() > 0) {
				GFileImpl ramdiskFile = GFileImpl.fromFilename(this, root, BootImageConstants.RAMDISK, false,
					header.getVendorRamdiskSize(), null);
				fileList.add(ramdiskFile);
				ramdiskFileList.add(ramdiskFile);
			}
		}
		if (header.getDtbSize() > 0) {
			dtbFile = GFileImpl.fromFilename(this, root, BootImageConstants.DTB, false,
				header.getDtbSize(), null);
			fileList.add(dtbFile);
		}
	}

	@Override
	public void close() throws IOException {
		fileList.clear();
		ramdiskFileList.clear();
		dtbFile = null;
		header = null;
		super.close();
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return (directory == null || directory.equals(root)) ? new ArrayList<>(fileList)
				: Collections.emptyList();
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		for (int i = 0; i < ramdiskFileList.size(); ++i) {
			if (ramdiskFileList.get(i) == file) {
				return FileAttributes.of(
					FileAttribute.create(FileAttributeType.COMMENT_ATTR,
							"This is a ramdisk, it is a GZIP file containing a CPIO archive."));
			}
		}
		if (file == dtbFile) {
			return FileAttributes.of(
				FileAttribute.create(FileAttributeType.COMMENT_ATTR,
					"This is a DTB file. It appears unused at this time."));
		}
		return FileAttributes.EMPTY;
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {

		for (int i = 0; i < ramdiskFileList.size(); ++i) {
			if (ramdiskFileList.get(i) == file) {
				return new ByteProviderWrapper(provider, header.getNestedVendorRamdiskOffset(i),
					Integer.toUnsignedLong(header.getNestedVendorRamdiskSize(i)), file.getFSRL());
			}
		}

		if (file == dtbFile) {
			return new ByteProviderWrapper(provider, header.getDtbOffset(),
				Integer.toUnsignedLong(header.getDtbSize()), file.getFSRL());
		}

		return null;
	}

}
