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
package ghidra.framework.store.local;

import java.io.File;

/**
 * 
 * Defines a file change listener interface.
 * 
 */
public interface FileChangeListener {
	
	/**
	 * Used to notify a listener that the specified file has been modified.
	 * If the file watcher was created with a lock file, the lock will be set
	 * on behalf of the caller.  This method should not attempt to alter the 
	 * lock.
	 * @param file the modified file.
	 */
	public void fileModified(File file);
	
	/**
	 * Used to notify a listener that the specified file has been removed.
	 * If the file watcher was created with a lock file, the lock will be set
	 * on behalf of the caller.  This method should not attempt to alter the 
	 * lock.
	 * @param file the removed file.
	 */
	public void fileRemoved(File file);

}
