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

import java.io.IOException;
import java.io.OutputStream;

/**
 * Used by {@link FileSystemService#getDerivedFilePush(FSRL, String, DerivedFilePushProducer, TaskMonitor)}
 * to produce a derived file from a source file.
 */
public interface DerivedFilePushProducer {
	/**
	 * Callback method intended to be implemented by the caller to
	 * {@link FileSystemService#getDerivedFilePush(FSRL, String, DerivedFilePushProducer, TaskMonitor)}.
	 * <p>
	 * The implementation needs to write bytes to the supplied {@link OutputStream}.
	 * <p>
	 * @param os {@link OutputStream} that the implementor should write the bytes to.  Do
	 * not close the stream when done.
	 * @throws IOException if there is a problem while writing to the OutputStream.
	 * @throws CancelledException if the user canceled.
	 */
	public void push(OutputStream os) throws IOException, CancelledException;
}
