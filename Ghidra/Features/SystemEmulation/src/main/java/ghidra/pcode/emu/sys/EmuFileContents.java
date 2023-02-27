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
package ghidra.pcode.emu.sys;

/**
 * The content store to back a simulated file
 *
 * <p>
 * TODO: Could/should this just be the same interface as an execute state? If so, we'd need to
 * formalize the store interface and require one for each address space in the state. Sharing that
 * interface may not be a good idea.... I think implementors can use a common realization if that
 * suits them.
 * 
 * <p>
 * TODO: Actually, a better idea might be to introduce an address factory with custom spaces into
 * the emulator. Then a library/file could just create an address space and use the state to store
 * and retrieve the file contents. Better yet, when written down, those contents and markings could
 * appear in the user's trace.
 * 
 * @param <T> the type of values in the file
 */
public interface EmuFileContents<T> {
	/**
	 * Copy values from the file into the given buffer
	 * 
	 * @param offset the offset in the file to read
	 * @param buf the destination buffer, whose size must be known
	 * @param fileSize the size of the file
	 * @return the number of bytes (not necessarily concrete) read
	 */
	long read(long offset, T buf, long fileSize);

	/**
	 * Write values from the given buffer into the file
	 * 
	 * @param offset the offset in the file to write
	 * @param buf the source buffer, whose size must be known
	 * @param curSize the current size of the file
	 * @return the number of bytes (not necessarily concrete) written
	 */
	long write(long offset, T buf, long curSize);

	/**
	 * Erase the contents
	 * 
	 * <p>
	 * Note that the file's size will be set to 0, so actual erasure of the contents may not be
	 * necessary, but if the contents are expensive to store, they ought to be disposed.
	 */
	void truncate();
}
