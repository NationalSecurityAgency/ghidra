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
package ghidra.file.formats.sparseimage;

import java.io.*;
import java.util.*;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A pseudo filesystem that contains a single file that is the decompressed contents
 * of the sparse container file.
 */
@FileSystemInfo(type = "simg", description = "Android Sparse Image (simg)", factory = SparseImageFileSystemFactory.class)
public class SparseImageFileSystem implements GFileSystem {

	private final FSRLRoot fsFSRL;
	private final FSRL containerFSRL;
	private final FileSystemRefManager refManager = new FileSystemRefManager(this);
	private final FileSystemService fsService;

	private GFileImpl root;
	private GFileImpl payload;
	private long containerSize;

	public SparseImageFileSystem(FSRLRoot fsFSRL, FSRL containerFSRL, FileSystemService fsService,
			TaskMonitor monitor) throws CancelledException, IOException {
		this.fsFSRL = fsFSRL;
		this.fsService = fsService;
		this.root = GFileImpl.fromFilename(this, null, null, true, -1, fsFSRL.withPath("/"));
		this.containerFSRL = containerFSRL;

		File containerFile = fsService.getFile(containerFSRL, monitor);
		containerSize = containerFile.length();

		FileCacheEntry pli = getPayloadInfo(monitor);
		String payloadName = containerFSRL.getName() + ".raw";
		FSRL payloadFSRL = root.getFSRL().appendPath(payloadName).withMD5(pli.md5);
		this.payload =
			GFileImpl.fromFilename(this, root, payloadName, false, pli.file.length(), payloadFSRL);
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		payload = null;
	}

	@Override
	public boolean isClosed() {
		return payload == null;
	}

	@Override
	public String getName() {
		return fsFSRL.getContainer().getName();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsFSRL;
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

	@Override
	public GFileImpl lookup(String path) throws IOException {
		if (path == null || path.equals("/")) {
			return root;
		}
		else if (path.equals(payload.getFSRL().getPath())) {
			return payload;
		}
		return null;
	}

	private FileCacheEntry getPayloadInfo(TaskMonitor monitor)
			throws CancelledException, IOException {
		return fsService.getDerivedFilePush(containerFSRL, "sparse", os -> {
			try (ByteProvider provider = fsService.getByteProvider(containerFSRL, monitor)) {
				SparseImageDecompressor sid = new SparseImageDecompressor(provider, os);
				sid.decompress(monitor);
			}
		}, monitor);
	}

	@Override
	public InputStream getInputStream(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (payload.equals(file)) {
			FileCacheEntry pli = getPayloadInfo(monitor);
			return new FileInputStream(pli.file);
		}
		return null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		if (directory == null || root.equals(directory)) {
			return Arrays.asList(payload);
		}
		return Collections.emptyList();
	}

	@Override
	public String getInfo(GFile file, TaskMonitor monitor) {
		if (payload.equals(file)) {
			return FSUtilities.infoMapToString(getInfoMap());
		}
		return null;
	}

	public Map<String, String> getInfoMap() {
		Map<String, String> info = new LinkedHashMap<>();
		info.put("Name", payload.getName());
		info.put("Size", Long.toString(payload.getLength()));
		info.put("Compressed Size", Long.toString(containerSize));
		info.put("MD5", payload.getFSRL().getMD5());
		return info;
	}
}
