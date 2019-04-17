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
package ghidra.framework.store;

import java.io.*;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * <code>DataFileItem</code> corresponds to a private serialized
 * data file within a FileSystem.  Methods are provided for opening
 * the underlying file as an input or output stream.
 * <br>
 * NOTE: The use of DataFile is not encouraged and is not fully
 * supported.
 */
public interface DataFileItem extends FolderItem {
	
	/**
	 * Open the current version of this item for reading.
	 * @return input stream
	 * @throws FileNotFoundException
	 */
	InputStream getInputStream() throws FileNotFoundException;
	
	/**
	 * Open a new version of this item for writing.
	 * @return output stream.
	 * @throws FileNotFoundException
	 */
	OutputStream getOutputStream() throws FileNotFoundException;

	/**
	 * Open a specific version of this item for reading.
	 * @return input stream
	 * @throws FileNotFoundException
	 */
	InputStream getInputStream(int version) throws FileNotFoundException;
	
}
