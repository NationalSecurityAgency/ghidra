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

import java.io.*;
import java.util.*;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "androidbootimg", description = "Android Boot and Recovery Images", factory = GFileSystemBaseFactory.class)
public class BootImageFileSystem extends GFileSystemBase {

	private BootImage header;
	private GFileImpl kernelFile;
	private GFileImpl ramdiskFile;
	private GFileImpl secondStageFile;
	private List<GFileImpl> fileList = new ArrayList<>();

	public BootImageFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		byte[] bytes = provider.readBytes(0, BootImageConstants.BOOT_IMAGE_MAGIC_SIZE);
		return Arrays.equals(bytes, BootImageConstants.BOOT_IMAGE_MAGIC_BYTES);
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {
		this.header = new BootImage(provider);

		if (!header.getMagic().equals(BootImageConstants.BOOT_IMAGE_MAGIC)) {
			throw new IOException("Invalid Android boot image file!");
		}

		if (header.getKernelSize() > 0) {
			kernelFile = GFileImpl.fromFilename(this, root, BootImageConstants.KERNEL, false,
				header.getKernelSize(), null);
			fileList.add(kernelFile);
		}
		if (header.getRamDiskSize() > 0) {
			ramdiskFile = GFileImpl.fromFilename(this, root, BootImageConstants.RAMDISK, false,
				header.getKernelSize(), null);
			fileList.add(ramdiskFile);
		}
		if (header.getSecondStageSize() > 0) {
			secondStageFile = GFileImpl.fromFilename(this, root, BootImageConstants.SECOND_STAGE,
				false, header.getKernelSize(), null);
			fileList.add(secondStageFile);
		}
	}

	@Override
	public void close() throws IOException {
		kernelFile = null;
		ramdiskFile = null;
		secondStageFile = null;
		header = null;
		super.close();
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return (directory == null || directory.equals(root)) ? new ArrayList<>(fileList)
				: Collections.emptyList();
	}

	@Override
	public String getInfo(GFile file, TaskMonitor monitor) {
		if (file == kernelFile) {
			return "This is the actual KERNEL for the android device. You can analyze this file.";
		}
		else if (file == ramdiskFile) {
			return "This is a ramdisk, it is a GZIP file containing a CPIO archive.";
		}
		else if (file == secondStageFile) {
			return "This is a second stage loader file. It appears unused at this time.";
		}
		return null;
	}

	@Override
	protected InputStream getData(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException, CryptoException {
		if (file == kernelFile) {
			byte[] kernelBytes =
				provider.readBytes(header.getKernelOffset(), header.getKernelSize());
			return new ByteArrayInputStream(kernelBytes);
		}
		else if (file == ramdiskFile) {
			byte[] ramDiskBytes =
				provider.readBytes(header.getRamDiskOffset(), header.getRamDiskSize());
			return new ByteArrayInputStream(ramDiskBytes);
		}
		else if (file == secondStageFile) {
			byte[] secondStageBytes =
				provider.readBytes(header.getSecondStageOffset(), header.getSecondStageSize());
			return new ByteArrayInputStream(secondStageBytes);
		}
		return null;
	}

}
