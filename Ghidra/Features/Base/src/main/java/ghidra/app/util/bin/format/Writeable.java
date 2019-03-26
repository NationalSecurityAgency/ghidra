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
package ghidra.app.util.bin.format;

import ghidra.util.DataConverter;

import java.io.IOException;
import java.io.RandomAccessFile;

/**
 * An interface for writing out class state information.
 * 
 */
public interface Writeable {
	/**
	 * Writes this object to the specified random access file using
	 * the data converter to handle endianness.
	 * @param raf the random access file
	 * @param dc the data converter
	 * @throws IOException if an I/O error occurs
	 */
	public void write(RandomAccessFile raf, DataConverter dc) throws IOException;
}
