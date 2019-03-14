/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package generic.util;

import java.io.*;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;

public class FileChannelLock {

	private final File lockFile;
	private FileOutputStream out;
	private FileChannel fc;
	private FileLock lock;

	/**
	 * A flag to signal that we are locked.  This is needed because we do not want to 'cleanup'
	 * lock files when we can't lock, as they may already be in use by another application 
	 * instance.
	 */
	private boolean isLocked;

	public FileChannelLock(File lockFile) {
		this.lockFile = new File(lockFile.getAbsolutePath() + "~");
	}

	boolean lock() {
		try {
			out = new FileOutputStream(lockFile, true);
			fc = out.getChannel();
			lock = fc.tryLock();
			isLocked = (lock != null);

			if (!isLocked) {
				release();
			}

			return isLocked;
		}
		catch (IOException e) {
			release();
		}
		return false;
	}

	void release() {
		if (lock != null) {
			try {
				lock.release();
			}
			catch (IOException e) {
				// we tried
			}
		}
		if (fc != null) {
			try {
				fc.close();
			}
			catch (IOException e) {
				// we tried
			}
		}
		if (out != null) {
			try {
				out.close();
			}
			catch (IOException e) {
				// we tried
			}
		}

		if (isLocked) {
			// only try to delete the lock file if we were able to lock
			lockFile.delete();
		}
	}
}
