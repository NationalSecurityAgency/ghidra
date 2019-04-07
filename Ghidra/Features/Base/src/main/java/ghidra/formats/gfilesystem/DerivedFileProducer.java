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

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.*;

/**
 * Used by {@link FileSystemService#getDerivedFile(FSRL, String, DerivedFileProducer, TaskMonitor)}
 * to produce a derived file from a source file.
 * <p>
 * The {@link InputStream} returned from the method will be closed by the caller.
 */
public interface DerivedFileProducer {

	/**
	 * Callback method intended to be implemented by the caller to
	 * {@link FileSystemService#getDerivedFile(FSRL, String, DerivedFileProducer, TaskMonitor)}.
	 * <p>
	 * The implementation needs to return an {@link InputStream} that contains the bytes
	 * of the derived file.
	 * <p>
	 * @param srcFile {@link File} location of the source file (usually in the file cache)
	 * @return a new {@link InputStream} that will produce all the bytes of the derived file.
	 * @throws IOException if there is a problem while producing the InputStream.
	 * @throws CancelledException if the user canceled.
	 */
	public InputStream produceDerivedStream(File srcFile) throws IOException, CancelledException;
}
