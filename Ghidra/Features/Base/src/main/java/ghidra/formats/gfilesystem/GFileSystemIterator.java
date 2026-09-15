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

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.*;
import java.util.function.Predicate;

/**
 * Iterates over the {@link GFile}s in a {@link GFileSystem} depth-first
 */
public class GFileSystemIterator implements Iterator<GFile> {

	private Deque<GFile> fileDeque = new ArrayDeque<>();
	private Deque<GFile> dirDeque = new ArrayDeque<>();
	private Predicate<GFile> filter;

	/**
	 * Creates a new {@link GFileSystemIterator} at the root of the given {@link GFileSystem}
	 * 
	 * @param fs The {@link GFileSystem} to iterate over
	 */
	public GFileSystemIterator(GFileSystem fs) {
		this(fs.getRootDir());
	}

	/**
	 * Creates a new {@link GFileSystemIterator} at the given {@link GFile directory}
	 * 
	 * @param dir The {@link GFile directory} to start the iteration at
	 * @throws UncheckedIOException if {@code dir} is not a directory
	 */
	public GFileSystemIterator(GFile dir) throws UncheckedIOException {
		this(dir, file -> true);
	}

	/**
	 * Creates a new {@link GFileSystemIterator} at the given {@link GFile directory}
	 * 
	 * @param dir The {@link GFile directory} to start the iteration at
	 * @param fileFilter A filter to apply to the {@link GFile files} iterated over
	 * @throws UncheckedIOException if {@code dir} is not a directory
	 */
	public GFileSystemIterator(GFile dir, Predicate<GFile> fileFilter) throws UncheckedIOException {
		if (!dir.isDirectory()) {
			throw new UncheckedIOException(new IOException("Invalid starting directory!"));
		}
		this.dirDeque.push(dir);
		this.filter = fileFilter;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @throws UncheckedIOException if an IO-related error occurred on 
	 *   {@link GFileSystem#getListing(GFile)}
	 */
	@Override
	public boolean hasNext() {
		queueNextFiles();
		return !fileDeque.isEmpty();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @throws NoSuchElementException if the iteration has no more elements
	 * @throws UncheckedIOException if an IO-related error occurred on 
	 *   {@link GFileSystem#getListing(GFile)}
	 */
	@Override
	public GFile next() {
		queueNextFiles();
		return fileDeque.pop();
	}

	private void queueNextFiles() throws UncheckedIOException {
		while (fileDeque.isEmpty() && (!dirDeque.isEmpty())) {
			try {
				List<GFile> listing = dirDeque.pop().getListing();
				listing.stream()
						.filter(GFile::isDirectory)
						.sorted(Comparator.comparing(GFile::getName).reversed())
						.forEach(dirDeque::push);
				listing.stream()
						.filter(Predicate.not(GFile::isDirectory))
						.filter(filter)
						.sorted(Comparator.comparing(GFile::getName).reversed())
						.forEach(fileDeque::push);
			}
			catch (IOException e) {
				throw new UncheckedIOException(e);
			}
		}
	}
}
