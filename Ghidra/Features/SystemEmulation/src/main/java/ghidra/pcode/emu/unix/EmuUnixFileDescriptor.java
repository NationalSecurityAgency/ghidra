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
package ghidra.pcode.emu.unix;

import ghidra.pcode.emu.sys.EmuIOException;

/**
 * A process's handle to a file (or other resource)
 *
 * @param <T> the type of values stored in the file
 */
public interface EmuUnixFileDescriptor<T> {
	/**
	 * The default file descriptor for stdin (standard input)
	 */
	int FD_STDIN = 0;
	/**
	 * The default file descriptor for stdout (standard output)
	 */
	int FD_STDOUT = 1;
	/**
	 * The default file descriptor for stderr (standard error output)
	 */
	int FD_STDERR = 2;

	/**
	 * Get the current offset of the file, or 0 if not applicable
	 * 
	 * @return the offset
	 */
	T getOffset();

	/**
	 * See to the given offset
	 * 
	 * @param offset the desired offset
	 * @throws EmuIOException if an error occurred
	 */
	void seek(T offset) throws EmuIOException;

	/**
	 * Read from the file opened by this handle
	 * 
	 * @param buf the destination buffer
	 * @return the number of bytes read
	 * @throws EmuIOException if an error occurred
	 */
	T read(T buf) throws EmuIOException;

	/**
	 * Read into the file opened by this handle
	 * 
	 * @param buf the source buffer
	 * @return the number of bytes written
	 * @throws EmuIOException if an error occurred
	 */
	T write(T buf) throws EmuIOException;

	/**
	 * Obtain the {@code stat} structure of the file opened by this handle
	 */
	EmuUnixFileStat stat();

	/**
	 * Close this descriptor
	 */
	void close();
}
