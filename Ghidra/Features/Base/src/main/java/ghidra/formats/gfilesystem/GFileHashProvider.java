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
package ghidra.formats.gfilesystem;

import java.io.IOException;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * GFileSystem add-on interface that provides MD5 hashing for file located within the filesystem 
 */
public interface GFileHashProvider {
	/**
	 * Returns the MD5 hash of the specified file.
	 * 
	 * @param file the {@link GFile}
	 * @param required boolean flag, if true the hash will always be returned, even if it has to
	 * be calculated.  If false, the hash will be returned if easily available
	 * @param monitor {@link TaskMonitor}
	 * @return MD5 hash as a string
	 * @throws CancelledException if cancelled
	 * @throws IOException if error
	 */
	String getMD5Hash(GFile file, boolean required, TaskMonitor monitor)
			throws CancelledException, IOException;
}
