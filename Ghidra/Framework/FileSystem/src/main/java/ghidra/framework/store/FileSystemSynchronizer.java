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
package ghidra.framework.store;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * This class is essentially a global flag used to track the long running file system synchronizing
 * operation.   This class is a workaround to avoid rewriting the complicated file system locking.
 */
public class FileSystemSynchronizer {

	private static AtomicBoolean isSynchronizing = new AtomicBoolean();

	/**
	 * Sets whether the synchronizing operation is running.
	 * @param b true if synchronizing
	 */
	public static void setSynchronizing(boolean b) {
		isSynchronizing.set(b);
	}

	/**
	 * Returns true the underlying file system is going through a long-running synchronization 
	 * operation while holding the {@code filesystem} lock.   Calling this method allows clients
	 * in the Swing thread to avoid  calling methods that require a file system lock, which would
	 * cause the UI to lock during the synchronizing operation.
	 * 
	 * @return true if synchronizing
	 */
	public static boolean isSynchronizing() {
		return isSynchronizing.get();
	}
}
