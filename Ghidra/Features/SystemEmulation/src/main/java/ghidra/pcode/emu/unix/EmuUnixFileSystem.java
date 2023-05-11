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

import java.util.*;

import ghidra.pcode.emu.sys.EmuIOException;

/**
 * A simulated UNIX file system
 *
 * @param <T> the type of values stored in the files
 */
public interface EmuUnixFileSystem<T> {
	/**
	 * Open flags as defined by the simulator
	 * 
	 * <p>
	 * See a UNIX manual for the exact meaning of each.
	 */
	enum OpenFlag {
		O_RDONLY,
		O_WRONLY,
		O_RDWR,
		O_CREAT,
		O_TRUNC,
		O_APPEND;

		/**
		 * Construct a set of flags
		 * 
		 * @param flags the flags
		 * @return the set
		 */
		public static Set<OpenFlag> set(OpenFlag... flags) {
			return set(Arrays.asList(flags));
		}

		/**
		 * Construct a set of flags
		 * 
		 * @param flags the flags
		 * @return the set
		 */
		public static Set<OpenFlag> set(Collection<OpenFlag> flags) {
			if (flags.contains(O_RDONLY) && flags.contains(O_WRONLY)) {
				throw new IllegalArgumentException("Cannot be read only and write only");
			}
			if (flags instanceof EnumSet) {
				return Collections.unmodifiableSet((EnumSet<OpenFlag>) flags);
			}
			return Collections.unmodifiableSet(EnumSet.copyOf(flags));
		}

		/**
		 * Check if the given flags indicate open for reading
		 * 
		 * @param flags the flags
		 * @return true for reading
		 */
		public static boolean isRead(Collection<OpenFlag> flags) {
			return flags.contains(OpenFlag.O_RDONLY) || flags.contains(OpenFlag.O_RDWR);
		}

		/**
		 * Check if the given flags indicate open for writing
		 * 
		 * @param flags the flags
		 * @return true for writing
		 */
		public static boolean isWrite(Collection<OpenFlag> flags) {
			return flags.contains(OpenFlag.O_WRONLY) || flags.contains(OpenFlag.O_RDWR);
		}
	}

	/**
	 * A factory for constructing a new file (without adding it to the file system)
	 * 
	 * @param pathname the path of the file
	 * @param the mode of the new file
	 * @return the new file
	 * @throws EmuIOException if the file cannot be constructed
	 */
	EmuUnixFile<T> newFile(String pathname, int mode) throws EmuIOException;

	/**
	 * Get the named file, creating it if it doesn't already exist
	 * 
	 * <p>
	 * This is accessed by the emulator user, not the target program.
	 * 
	 * @param pathname the pathname of the requested file
	 * @param mode the mode of a created file. Ignored if the file exists
	 * @return the file
	 * @throws EmuIOException if an error occurred
	 */
	EmuUnixFile<T> createOrGetFile(String pathname, int mode) throws EmuIOException;

	/**
	 * Get the named file
	 * 
	 * <p>
	 * This is accessed by the emulator user, not the target program.
	 * 
	 * @param pathname the pathname of the requested file
	 * @return the file, or {@code null} if it doesn't exist
	 * @throws EmuIOException if an error occurred
	 */
	EmuUnixFile<T> getFile(String pathname) throws EmuIOException;

	/**
	 * Place the given file at the given location
	 * 
	 * <p>
	 * This is accessed by the emulator user, not the target program. If the file already exists, it
	 * is replaced silently.
	 * 
	 * @param pathname the pathname of the file
	 * @param file the file, presumably having the same pathname
	 * @throws EmuIOException if an error occurred
	 */
	void putFile(String pathname, EmuUnixFile<T> file) throws EmuIOException;

	/**
	 * Remove the file at the given location
	 * 
	 * <p>
	 * TODO: Separate the user-facing routine from the target-facing routine.
	 * 
	 * <p>
	 * If the file does not exist, this has no effect.
	 * 
	 * @param pathname the pathname of the file to unlink
	 * @param user the user requesting the unlink
	 * @throws EmuIOException if an error occurred
	 */
	void unlink(String pathname, EmuUnixUser user) throws EmuIOException;

	/**
	 * Open the requested file according to the given flags and user
	 * 
	 * <p>
	 * This is generally accessed by the target program via a {@link DefaultEmuUnixFileHandle}.
	 * 
	 * @param pathname the pathname of the requested file
	 * @param flags the requested open flags
	 * @param user the user making the request
	 * @param mode the mode to assign the file, if created. Otherwise ignored
	 * @return the file
	 * @throws EmuIOException if an error occurred, e.g., file not found, or access denied
	 */
	EmuUnixFile<T> open(String pathname, Set<OpenFlag> flags, EmuUnixUser user, int mode)
			throws EmuIOException;
}
