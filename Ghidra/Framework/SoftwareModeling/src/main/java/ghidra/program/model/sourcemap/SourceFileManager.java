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
package ghidra.program.model.sourcemap;

import java.util.List;

import ghidra.framework.store.LockException;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.model.address.*;

/**
 * This interface defines methods for managing {@link SourceFile}s and {@link SourceMapEntry}s.
 */
public interface SourceFileManager {

	public static final SourceFileManager DUMMY = new DummySourceFileManager();

	/**
	 * Returns a sorted list of {@link SourceMapEntry}s associated with an address {@code addr}. 
	 * @param addr address
	 * @return line number
	 */
	public List<SourceMapEntry> getSourceMapEntries(Address addr);

	/**
	 * Adds a {@link SourceMapEntry} with {@link SourceFile} {@code sourceFile},
	 * line number {@code lineNumber}, and {@link AddressRange} {@code range} to the program 
	 * database.
	 * <p>
	 * Entries with non-zero lengths must either cover the same address range or be disjoint.
	 * @param sourceFile source file
	 * @param lineNumber line number
	 * @param range address range
	 * @return created SourceMapEntry
	 * @throws LockException if invoked without exclusive access
	 * @throws IllegalArgumentException if the range of the new entry intersects, but does
	 * not equal, the range of an existing entry or if sourceFile was not previously added
	 * to the program.
	 * @throws AddressOutOfBoundsException if the range of the new entry contains addresses
	 * that are not in a defined memory block
	 */
	public default SourceMapEntry addSourceMapEntry(SourceFile sourceFile, int lineNumber,
			AddressRange range) throws LockException {
		try {
			return addSourceMapEntry(sourceFile, lineNumber, range.getMinAddress(),
				range.getLength());
		}
		// can't happen
		catch (AddressOverflowException e) {
			throw new AssertionError("Address overflow with valid AddressRange");
		}
	}

	/**
	 * Creates a {@link SourceMapEntry} with {@link SourceFile} {@code sourceFile},
	 * line number {@code lineNumber}, and non-negative length {@code length} and
	 * adds it to the program database.
	 * <p>
	 * Entries with non-zero lengths must either cover the same address range or be disjoint.
	 * @param sourceFile source file
	 * @param lineNumber line number
	 * @param baseAddr minimum address of range 
	 * @param length number of addresses in range
	 * @return created SourceMapEntry
	 * @throws AddressOverflowException if baseAddr + length-1 overflows
	 * @throws LockException if invoked without exclusive access
	 * @throws IllegalArgumentException if the range of the new entry intersects, but does
	 * not equal, the range of an existing entry or if sourceFile was not previously added to the 
	 * program.
	 * @throws AddressOutOfBoundsException if the range of the new entry contains addresses
	 * that are not in a defined memory block
	 */
	public SourceMapEntry addSourceMapEntry(SourceFile sourceFile, int lineNumber, Address baseAddr,
			long length) throws AddressOverflowException, LockException;

	/**
	 * Returns {@code true} precisely when at least one {@link Address} in {@code addrs} has
	 * source map information.
	 * @param addrs addresses to check
	 * @return true when at least one address has source map info
	 */
	public boolean intersectsSourceMapEntry(AddressSetView addrs);

	/**
	 * Adds a {@link SourceFile} to this manager.  A SourceFile must be added before it can be 
	 * associated with any source map information.
	 * 
	 * @param sourceFile source file to add (can't be null)
	 * @return true if this manager did not already contain sourceFile
	 * @throws LockException if invoked without exclusive access
	 */
	public boolean addSourceFile(SourceFile sourceFile) throws LockException;

	/**
	 * Removes a {@link SourceFile} from this manager.  Any associated {@link SourceMapEntry}s will
	 * also be removed.
	 * @param sourceFile source file to remove
	 * @return true if sourceFile was in the manager
	 * @throws LockException if invoked without exclusive access
	 */
	public boolean removeSourceFile(SourceFile sourceFile) throws LockException;

	/**
	 * Returns true precisely when this manager contains {@code sourceFile}.
	 * @param sourceFile source file
	 * @return true if source file already added
	 */
	public boolean containsSourceFile(SourceFile sourceFile);

	/**
	 * Returns a {@link List} containing all {@link SourceFile}s of the program.
	 * @return source file list
	 */
	public List<SourceFile> getAllSourceFiles();

	/**
	 * Returns a {@link List} containing {@link SourceFile}s which are
	 * mapped to at least one address in the program
	 * @return mapped source file list
	 */
	public List<SourceFile> getMappedSourceFiles();

	/**
	 * Changes the source map so that any {@link SourceMapEntry} associated with {@code source}
	 * is associated with {@code target} instead. Any entries associated with
	 * {@code target} before invocation will still be associated with
	 * {@code target} after invocation.  {@code source} will not be associated
	 * with any entries after invocation (unless {@code source} and {@code target}
	 * are the same). Line number information is not changed.
	 * @param source source file to get info from
	 * @param target source file to move info to
	 * @throws LockException if invoked without exclusive access
	 * @throws IllegalArgumentException if source or target has not been added previously
	 */
	public void transferSourceMapEntries(SourceFile source, SourceFile target) throws LockException;

	/**
	 * Returns a {@link SourceMapEntryIterator} starting at {@code address}.
	 * 
	 * @param address starting address
	 * @param forward direction of iterator (true = forward)
	 * @return iterator
	 */
	public SourceMapEntryIterator getSourceMapEntryIterator(Address address, boolean forward);

	/**
	 * Returns the sorted list of {@link SourceMapEntry}s for {@code sourceFile} with line number
	 * between {@code minLine} and {@code maxLine}, inclusive.
	 * @param sourceFile source file
	 * @param minLine minimum line number
	 * @param maxLine maximum line number
	 * @return source map entries
	 */
	public List<SourceMapEntry> getSourceMapEntries(SourceFile sourceFile, int minLine,
			int maxLine);

	/**
	 * Returns the sorted list of {@link SourceMapEntry}s for {@code sourceFile} with line number 
	 * equal to {@code lineNumber}.
	 * @param sourceFile source file
	 * @param lineNumber line number
	 * @return source map entries
	 */
	public default List<SourceMapEntry> getSourceMapEntries(SourceFile sourceFile, int lineNumber) {
		return getSourceMapEntries(sourceFile, lineNumber, lineNumber);
	}

	/**
	 * Returns a sorted of list all {@link SourceMapEntry}s in the program corresponding to
	 * {@code sourceFile}.
	 * @param sourceFile source file
	 * @return source map entries
	 */
	public default List<SourceMapEntry> getSourceMapEntries(SourceFile sourceFile) {
		return getSourceMapEntries(sourceFile, 0, Integer.MAX_VALUE);
	}

	/**
	 * Removes a {@link SourceMapEntry} from this manager.
	 * @param entry entry to remove
	 * @return true if entry was in the manager
	 * @throws LockException if invoked without exclusive access
	 */
	public boolean removeSourceMapEntry(SourceMapEntry entry) throws LockException;

}
