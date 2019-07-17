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
package ghidra.file.formats.ios.dmg;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

/**
 * A {@link GFileSystem} that uses an external DMG server process to parse DMG files
 * and presents the contents as a filesystem.
 * <p>
 * Uses stdin/stdout/stderr to communicate with the DMG server process.
 * <p>
 * If the server process dies during a call, the caller will tend to get an IOException and
 * a new process will be started at the next call.
 * <p>
 * The server's jvm memory size is set in a file in the DMG module/data directory called
 * "server_memory.cfg", and should consist of a single line with text string indicating
 * how many megabytes to allocate to the jvm... ie. "1024" for 1024mb.
 * <p>
 * DMG server process seems to leak memory.  Currently it is killed every N commands and
 * restarted.
 */
@FileSystemInfo(type = "dmg", description = "iOS Disk Image (DMG)", factory = DmgClientFileSystemFactory.class)
public class DmgClientFileSystem implements GFileSystem {

	private final FSRLRoot fsrl;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);
	private FileSystemIndexHelper<Object> fsih;
	private File decrypted_dmg_file;
	private DmgServerProcessManager processManager;
	private CancelledListener listener = () -> processManager.interruptCmd();
	private FileSystemService fsService;

	/**
	 * Creates a {@link DmgClientFileSystem} instance, using a decrypted dmg file and
	 * the filesystem's {@link FSRLRoot}.
	 *
	 * @param decrypted_dmg_file path to a decrypted DMG file.  The DmgClientFileSystemFactory
	 * takes care of decrypting for us.
	 * @param fsrl {@link FSRLRoot} of this filesystem.
	 */
	public DmgClientFileSystem(File decrypted_dmg_file, FSRLRoot fsrl,
			FileSystemService fsService) {
		this.fsrl = fsrl;
		this.fsih = new FileSystemIndexHelper<>(this, fsrl);
		this.decrypted_dmg_file = decrypted_dmg_file;
		this.fsService = fsService;
	}

	public void mount(TaskMonitor monitor) throws CancelledException, IOException {
		processManager =
			new DmgServerProcessManager(decrypted_dmg_file, fsrl.getContainer().getName());

		monitor.addCancelledListener(listener);
		try {
			UnknownProgressWrappingTaskMonitor upwtm =
				new UnknownProgressWrappingTaskMonitor(monitor, 1);
			recurseDirectories(fsih.getRootDir(), upwtm);
		}
		finally {
			monitor.removeCancelledListener(listener);
		}
		Msg.info(this,
			"Indexed " + fsih.getFileCount() + " files in " + fsrl.getContainer().getName());

	}

	@Override
	public void close() throws IOException {
		refManager.onClose();

		processManager.close();
		processManager = null;

		fsih.clear();
		fsih = null;
	}

	@Override
	public String getName() {
		return fsrl.getContainer().getName();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsrl;
	}

	@Override
	public boolean isClosed() {
		return processManager == null;
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

	@Override
	public InputStream getInputStream(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		monitor.addCancelledListener(listener);

		try {
			List<String> results = processManager.sendCmd("get_data " + file.getPath(), 1);
			File extractedFile = new File(results.get(0));

			// the DMG server process returns a path to a temporary file that
			// we need to copy to our own space to ensure its not deleted out from underneath
			// us.
			// Use the FileSystemService filecache to store the file even though
			// we are not accessing the file by its hash value later.
			if (!extractedFile.exists() || extractedFile.length() == 0) {
				return null;
			}
			try (FileInputStream fis = new FileInputStream(extractedFile)) {
				FileCacheEntry fce = fsService.addStreamToCache(fis, monitor);
				fis.close();
				extractedFile.delete();
				return new FileInputStream(fce.file);
			}
		}
		finally {
			monitor.removeCancelledListener(listener);
		}
	}

	private void recurseDirectories(GFile dir, TaskMonitor monitor)
			throws IOException, CancelledException {

		monitor.setMessage("Indexing " + dir.getName());
		List<GFile> files = getRawListing(dir);
		for (GFile f : files) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);

			// throw away the gfileimpl from getrawlisting(), create new gfile in rafi
			GFile newF = fsih.storeFileWithParent(f.getName(), dir, -1, f.isDirectory(),
				f.getLength(), null);
			if (newF.isDirectory()) {
				recurseDirectories(newF, monitor);
			}
		}
	}

	private List<GFile> getRawListing(GFile dir) throws IOException {
		List<String> childInfo = processManager.sendCmd("get_listing " + dir.getPath(),
			-3 /* 3 responses per result, unknown number of results*/);

		if (childInfo.size() % 3 != 0) {
			throw new IOException("Bad response for get_listing for directory " + dir);
		}

		List<GFile> results = new ArrayList<>();
		for (int i = 0; i < childInfo.size(); i += 3) {
			String name = childInfo.get(i + 0);
			boolean isDirectory = childInfo.get(i + 1).equals("true");
			long length = Long.parseLong(childInfo.get(i + 2));

			GFileImpl gFile = GFileImpl.fromFilename(this, dir, name, isDirectory, length, null);
			results.add(gFile);
		}
		return results;
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsih.lookup(path);
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsih.getListing(directory);
	}

	@Override
	public int getFileCount() {
		return fsih.getFileCount();
	}

	@Override
	public String getInfo(GFile gFile, TaskMonitor monitor) {
		monitor.addCancelledListener(listener);

		StringBuffer buffer = new StringBuffer();
		try {
			List<String> infoResults = processManager.sendCmd("get_info " + gFile.getPath(), -1);
			for (String s : infoResults) {
				buffer.append(s).append("\n");
			}
		}
		catch (Exception e) {
			Msg.showError(this, null, "DMG: Unable To Get Info", e.getMessage());
		}
		finally {
			monitor.removeCancelledListener(listener);
		}
		return buffer.toString();
	}

}
