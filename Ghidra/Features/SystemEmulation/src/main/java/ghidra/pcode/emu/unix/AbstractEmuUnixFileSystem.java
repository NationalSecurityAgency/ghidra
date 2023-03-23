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
 * An abstract emulated file system, exported to an emulated user-space program
 *
 * @param <T> the type of values stored in the file system
 */
public abstract class AbstractEmuUnixFileSystem<T> implements EmuUnixFileSystem<T> {
	protected final Map<String, EmuUnixFile<T>> filesByPath = new HashMap<>();

	@Override
	public abstract AbstractEmuUnixFile<T> newFile(String pathname, int mode) throws EmuIOException;

	@Override
	public synchronized EmuUnixFile<T> createOrGetFile(String pathname, int mode)
			throws EmuIOException {
		return filesByPath.computeIfAbsent(pathname, p -> newFile(p, mode));
	}

	@Override
	public synchronized EmuUnixFile<T> getFile(String pathname) throws EmuIOException {
		return filesByPath.get(pathname);
	}

	@Override
	public synchronized void putFile(String pathname, EmuUnixFile<T> file) throws EmuIOException {
		filesByPath.put(pathname, file);
	}

	@Override
	public synchronized EmuUnixFile<T> open(String pathname, Set<OpenFlag> flags, EmuUnixUser user,
			int mode) throws EmuIOException {
		EmuUnixFile<T> file =
			flags.contains(OpenFlag.O_CREAT) ? createOrGetFile(pathname, mode) : getFile(pathname);

		if (file == null) {
			throw new EmuIOException("File not found: " + pathname);
		}
		if (flags.contains(OpenFlag.O_RDONLY) || flags.contains(OpenFlag.O_RDWR)) {
			file.checkReadable(user);
		}
		if (flags.contains(OpenFlag.O_WRONLY) || flags.contains(OpenFlag.O_RDWR)) {
			file.checkWritable(user);
			if (flags.contains(OpenFlag.O_TRUNC)) {
				file.truncate();
			}
		}
		return file;
	}

	@Override
	public synchronized void unlink(String pathname, EmuUnixUser user) throws EmuIOException {
		filesByPath.remove(pathname);
	}
}
