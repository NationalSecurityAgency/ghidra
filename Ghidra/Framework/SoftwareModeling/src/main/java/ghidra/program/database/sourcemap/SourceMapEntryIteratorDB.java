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
package ghidra.program.database.sourcemap;

import java.io.IOException;
import java.util.Iterator;
import java.util.NoSuchElementException;

import db.DBRecord;
import db.RecordIterator;
import ghidra.program.model.sourcemap.SourceMapEntry;
import ghidra.program.model.sourcemap.SourceMapEntryIterator;

/**
 * Database implementation of {@link SourceMapEntryIterator}
 */
public class SourceMapEntryIteratorDB implements SourceMapEntryIterator {

	private boolean forward;
	private RecordIterator recIter;
	private SourceFileManagerDB sourceManager;
	private SourceMapEntry nextEntry;

	/**
	 * Constructor
	 * @param sourceManager source manager
	 * @param recIter record iterator
	 * @param forward direction to iterate
	 */
	SourceMapEntryIteratorDB(SourceFileManagerDB sourceManager, RecordIterator recIter,
			boolean forward) {
		this.sourceManager = sourceManager;
		this.recIter = recIter;
		this.forward = forward;
		this.nextEntry = null;
	}

	@Override
	public boolean hasNext() {
		if (nextEntry != null) {
			return true;
		}
		sourceManager.lock.acquire();
		try {
			boolean recIterNext = forward ? recIter.hasNext() : recIter.hasPrevious();
			if (!recIterNext) {
				return false;
			}
			DBRecord rec = forward ? recIter.next() : recIter.previous();
			nextEntry = sourceManager.getSourceMapEntry(rec);
			return true;
		}
		catch (IOException e) {
			sourceManager.dbError(e);
			return false;
		}
		finally {
			sourceManager.lock.release();
		}
	}

	@Override
	public SourceMapEntry next() {
		if (hasNext()) {
			SourceMapEntry entryToReturn = nextEntry;
			nextEntry = null;
			return entryToReturn;
		}
		throw new NoSuchElementException();
	}

	@Override
	public Iterator<SourceMapEntry> iterator() {
		return this;
	}

	@Override
	public void remove() {
		throw new UnsupportedOperationException();
	}

}
