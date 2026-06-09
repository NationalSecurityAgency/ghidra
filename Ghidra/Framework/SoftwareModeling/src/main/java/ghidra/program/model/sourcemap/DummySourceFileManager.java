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

import java.util.Collections;
import java.util.List;

import ghidra.framework.store.LockException;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;

/**
 * A "dummy" implementation of {@link SourceFileManager}.  
 */
public class DummySourceFileManager implements SourceFileManager {

	public DummySourceFileManager() {
		// nothing to do
	}

	@Override
	public List<SourceMapEntry> getSourceMapEntries(Address addr) {
		return Collections.emptyList();
	}

	@Override
	public SourceMapEntry addSourceMapEntry(SourceFile sourceFile, int lineNumber, Address baseAddr,
			long length) throws LockException {
		throw new UnsupportedOperationException("Cannot add source map entries with this manager");
	}

	@Override
	public boolean intersectsSourceMapEntry(AddressSetView addrs) {
		return false;
	}

	@Override
	public List<SourceFile> getAllSourceFiles() {
		return Collections.emptyList();
	}

	@Override
	public List<SourceFile> getMappedSourceFiles() {
		return Collections.emptyList();
	}

	@Override
	public void transferSourceMapEntries(SourceFile source, SourceFile target) {
		throw new UnsupportedOperationException(
			"Dummy source file manager cannot transfer map info");

	}

	@Override
	public SourceMapEntryIterator getSourceMapEntryIterator(Address address, boolean forward) {
		return SourceMapEntryIterator.EMPTY_ITERATOR;
	}

	@Override
	public List<SourceMapEntry> getSourceMapEntries(SourceFile sourceFile, int minLine,
			int maxLine) {
		return Collections.emptyList();
	}

	@Override
	public boolean addSourceFile(SourceFile sourceFile) throws LockException {
		throw new UnsupportedOperationException("cannot add source files to this manager");
	}

	@Override
	public boolean removeSourceFile(SourceFile sourceFile) throws LockException {
		throw new UnsupportedOperationException("cannot remove source files from this manager");
	}

	@Override
	public boolean containsSourceFile(SourceFile sourceFile) {
		return false;
	}

	@Override
	public boolean removeSourceMapEntry(SourceMapEntry entry) throws LockException {
		throw new UnsupportedOperationException(
			"cannot remove source map entries from this manager");
	}

}
