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
package ghidra.file.formats.android.fbpk;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.*;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "androidbootloaderfbpk", // ([a-z0-9]+ only)
		description = "Android Boot Loader Image (FBPK)", factory = GFileSystemBaseFactory.class)

public class FBPK_FileSystem extends GFileSystemBase {
	private List<GFileImpl> fileList = new ArrayList<>();
	private Map<GFileImpl, FBPK_Partition> map = new HashMap<>();

	public FBPK_FileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		byte[] bytes = provider.readBytes(0, FBPK_Constants.FBPK.length());
		return FBPK_Constants.FBPK.equals(new String(bytes).trim());
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {
		BinaryReader reader = new BinaryReader(provider, true /*might not always be LE*/ );
		FBPK header = new FBPK(reader);
		List<FBPK_Partition> partitions = header.getPartitions();
		for (FBPK_Partition partition : partitions) {
			if (partition.isFile()) {
				GFileImpl file = GFileImpl.fromFilename(this, root, partition.getName(), false,
					partition.getDataSize(), null);
				fileList.add(file);
				map.put(file, partition);
			}
		}
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return new ArrayList<>(fileList);
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {

		FBPK_Partition partition = map.get(file);
		if (partition != null) {
			return new ByteProviderWrapper(provider, partition.getDataStartOffset(),
				Integer.toUnsignedLong(partition.getDataSize()), file.getFSRL());
		}
		return null;
	}

}
