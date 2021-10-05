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
package ghidra.file.formats.ios.ipsw;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.GFileSystemBase;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

/**
 *
 * IPSW is really just a ZIP file.
 * <p>
 * This implementation is currently unused (isValid always returns false).
 * <p>
 */
@FileSystemInfo(type = "ipsw", description = "iOS Firmware (IPSW)", factory = GFileSystemBaseFactory.class)
public class IpswFileSystem extends GFileSystemBase {

	public IpswFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		return false;
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {
		// does nothing yet
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return new ArrayList<>();
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) {
		return null;
	}

}
