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
package pdb.symbolserver;

import java.io.File;
import java.io.IOException;

import ghidra.util.task.TaskMonitor;

/**
 * A local writable {@link SymbolServer}.
 */
public interface SymbolStore extends SymbolServer {

	/**
	 * Returns the 'admin' directory of this SymbolStore, which allows files created here
	 * to be efficiently {@link #giveFile(SymbolFileInfo, File, String, TaskMonitor) given}
	 * to the store.
	 * <p>
	 * 
	 * @return directory 
	 */
	File getAdminDir();

	/**
	 * Returns an absolute {@link File} instance based on the specified relative path
	 * to a file inside the symbol store.
	 * <p>
	 * 
	 * @param path relative local path
	 * @return absolute {@link File} based on the specified relative path
	 */
	File getFile(String path);

	/**
	 * Offers the specified file to the SymbolStore.  The file should be
	 * located in the admin directory of the SymbolStore to ensure no problems
	 * with ingesting the file.
	 * <p>
	 * The file will be 'consumed' by this SymbolStore, and the caller's
	 * responsibility to the file ends.
	 * 
	 * @param symbolFileInfo {@link SymbolFileInfo} bag of information about the file
	 * @param file {@link File} to ingest
	 * @param filename real name of the ingested file
	 * @param monitor {@link TaskMonitor}
	 * @return relative raw local path to the newly ingested file
	 * @throws IOException if error
	 */
	String giveFile(SymbolFileInfo symbolFileInfo, File file, String filename, TaskMonitor monitor)
			throws IOException;

	/**
	 * Places the contents of the stream into a file in this SymbolStore.
	 * <p>
	 * 
	 * @param symbolFileInfo {@link SymbolFileInfo} bag of information about the file
	 * @param symbolServerInputStream the stream to ingest
	 * @param filename real name of the ingested file
	 * @param monitor {@link TaskMonitor}
	 * @return relative raw local path to the newly ingested file
	 * @throws IOException if error
	 */
	String putStream(SymbolFileInfo symbolFileInfo, SymbolServerInputStream symbolServerInputStream,
			String filename, TaskMonitor monitor) throws IOException;

	/**
	 * Returns true if the specified filename indicates that the file is a compressed
	 * cab file.
	 * 
	 * @param filename filename
	 * @return boolean true if filename indicates that the file is compressed
	 */
	public static boolean isCompressedFilename(String filename) {
		return filename.endsWith("_");
	}

}
