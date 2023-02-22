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
import ghidra.pcode.exec.PcodeArithmetic;

/**
 * A simulated UNIX file
 *
 * <p>
 * Contrast this with {@link EmuUnixFileDescriptor}, which is a process's handle to an open file,
 * not the file itself.
 *
 * @param <T> the type of values stored in the file
 */
public interface EmuUnixFile<T> {

	/**
	 * Get the original pathname of this file
	 * 
	 * <p>
	 * Depending on the fidelity of the file system simulator, and the actions taken by the target
	 * program, the file may no longer actually exist at this path, but it ought be have been the
	 * pathname at some point in the file life.
	 * 
	 * @return the pathname
	 */
	String getPathname();

	/**
	 * Read contents from the file starting at the given offset into the given buffer
	 * 
	 * <p>
	 * This roughly follows the semantics of the UNIX {@code read()}. While the offset and return
	 * value may depend on the arithmetic, the actual contents read from the file should not.
	 * 
	 * @param arithmetic the arithmetic
	 * @param offset the offset
	 * @param buf the buffer
	 * @return the number of bytes read
	 */
	T read(PcodeArithmetic<T> arithmetic, T offset, T buf);

	/**
	 * Write contents into the file starting at the given offset from the given buffer
	 * 
	 * <p>
	 * This roughly follows the semantics of the UNIX {@code write()}. While the offset and return
	 * value may depend on the arithmetic, the actual contents written to the file should not.
	 * 
	 * @param arithmetic the arithmetic
	 * @param offset the offset
	 * @param buf the buffer
	 * @return the number of bytes written
	 */
	T write(PcodeArithmetic<T> arithmetic, T offset, T buf);

	/**
	 * Erase the contents of the file
	 */
	void truncate();

	/**
	 * Get the file's {@code stat} structure, as defined by the simulator.
	 * 
	 * @return the stat
	 */
	EmuUnixFileStat getStat();

	/**
	 * Check if the given user can read this file
	 * 
	 * @param user the user
	 * @return true if permitted, false otherwise
	 */
	default boolean isReadable(EmuUnixUser user) {
		return getStat().hasPermissions(EmuUnixFileStat.MODE_R, user);
	}

	/**
	 * Check if the given user can write this file
	 * 
	 * @param user the user
	 * @return true if permitted, false otherwise
	 */
	default boolean isWritable(EmuUnixUser user) {
		return getStat().hasPermissions(EmuUnixFileStat.MODE_W, user);
	}

	/**
	 * Require the user to have read permission on this file, throwing {@link EmuIOException} if not
	 * 
	 * @param user the user
	 */
	default void checkReadable(EmuUnixUser user) {
		if (!isReadable(user)) {
			throw new EmuIOException("The file " + getPathname() + " cannot be read.");
		}
	}

	/**
	 * Require the user to have write permission on this file, throwing {@link EmuIOException} if
	 * not
	 * 
	 * @param user the user
	 */
	default void checkWritable(EmuUnixUser user) {
		if (!isWritable(user)) {
			throw new EmuIOException("The file " + getPathname() + " cannot be written.");
		}
	}
}
