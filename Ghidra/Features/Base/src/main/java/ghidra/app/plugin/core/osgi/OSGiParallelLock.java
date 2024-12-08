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
package ghidra.app.plugin.core.osgi;

import java.io.*;

import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.util.Msg;
import utilities.util.FileUtilities;

/**
 * A file-based lock used to protect modifications to OSGi shared resources from other
 * instances of Ghidra running in parallel 
 */
public class OSGiParallelLock implements Closeable {

	private static final String LOCK_NAME = "parallel.lock";

	private File lockFile;
	private FileOutputStream fos;

	/**
	 * Creates a new OSGi file-based lock
	 */
	public OSGiParallelLock() {
		File osgiDir = BundleHost.getOsgiDir().toFile();
		FileUtilities.mkdirs(osgiDir);
		lockFile = new File(osgiDir, LOCK_NAME);

		try {
			fos = new FileOutputStream(lockFile);
			fos.getChannel().lock();
		}
		catch (IOException e) {
			Msg.error(this, "Failed to open OSGi parallel lock: " + lockFile, e);
		}
	}

	@Override
	public void close() {
		FSUtilities.uncheckedClose(fos, "Failed to close OSGi parallel lock: " + lockFile);
	}
}
