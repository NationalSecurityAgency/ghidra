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
import java.util.*;

import db.*;
import db.util.ErrorHandler;
import ghidra.framework.data.OpenMode;
import ghidra.framework.store.LockException;
import ghidra.program.database.ManagerDB;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.AddressMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.sourcemap.*;
import ghidra.program.util.ProgramEvent;
import ghidra.util.Lock;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Database Manager for managing source files and source map information.
 */
public class SourceFileManagerDB implements SourceFileManager, ManagerDB, ErrorHandler {

	private ProgramDB program;

	private SourceFileAdapter sourceFileTableAdapter;
	private SourceMapAdapter sourceMapTableAdapter;
	private AddressMapDB addrMap;

	protected final Lock lock;

	private Long lastKey;
	private SourceFile lastSourceFile;

	/**
	 * Constructor
	 * @param dbh database handle
	 * @param addrMap map longs to addresses
	 * @param openMode mode
	 * @param lock program synchronization lock
	 * @param monitor task monitor
	 * @throws VersionException if the database is incompatible with the current schema
	 */
	public SourceFileManagerDB(DBHandle dbh, AddressMapDB addrMap, OpenMode openMode, Lock lock,
			TaskMonitor monitor) throws VersionException {
		this.addrMap = addrMap;
		sourceFileTableAdapter = SourceFileAdapter.getAdapter(dbh, openMode, monitor);
		sourceMapTableAdapter = SourceMapAdapter.getAdapter(dbh, addrMap, openMode, monitor);
		this.lock = lock;
	}

	@Override
	public void setProgram(ProgramDB program) {
		this.program = program;
	}

	@Override
	public void programReady(OpenMode openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
		// nothing to do
	}

	@Override
	public void invalidateCache(boolean all) throws IOException {
		lastKey = null;
		lastSourceFile = null;
	}

	/**
	 * {@inheritDoc}<br>
	 * Note: this method will split any source map entries that <b>intersect</b> the address 
	 * range but are not entirely contained within it. Parts within the range to delete will
	 * be deleted.
	 * @param start first address in range
	 * @param end last address in range
	 * @param monitor task monitor
	 * @throws CancelledException if {@code monitor} is cancelled
	 */
	@Override
	public void deleteAddressRange(Address start, Address end, TaskMonitor monitor)
			throws CancelledException {

		AddressRange.checkValidRange(start, end);
		AddressRange rangeToDelete = new AddressRangeImpl(start, end);
		lock.acquire();
		try {

			RecordIterator recIter = sourceMapTableAdapter.getSourceMapRecordIterator(end, false);
			boolean sourceMapChanged = false;

			// Note: we iterate backwards since records are stored based on the start address.
			// We need to delete records stored before the beginning of the delete range that 
			// overlap the delete range, but we will never need to delete records that start after  
			// the delete range.
			List<SourceMapEntryData> entriesToCreate = new ArrayList<>();
			while (recIter.hasPrevious()) {
				monitor.checkCancelled();
				DBRecord rec = recIter.previous();
				Address recStart = getStartAddress(rec);
				long recLength = getLength(rec);

				if (recLength == 0) {
					// if length 0 entry is in range to delete, delete entry
					// otherwise ignore
					if (rangeToDelete.contains(recStart)) {
						recIter.delete();
					}
					continue;
				}

				Address recEnd = getEndAddress(recStart,recLength);

				if (!rangeToDelete.intersects(recStart, recEnd)) {
					// we've found an entry that does not touch the range to delete
					// this means we've handled all relevant entries and can stop
					break;
				}

				long fileAndLine = getFileAndLine(rec);
				long fileId = fileAndLine >> 32;
				int lineNum = (int) (fileAndLine & 0xffffffff);
				if (isLessInSameSpace(recStart, start)) {
					// rangeToDelete intersects (recStart,recEnd), so 
					// the entry must overlap the left endpoint of rangeToDelete
					long length = start.subtract(recStart);
					SourceMapEntryData data =
						new SourceMapEntryData(fileId, lineNum, recStart, length);
					entriesToCreate.add(data);
				}

				if (isLessInSameSpace(end, recEnd)) {
					// rangeToDelete intersects (recStart,recEnd)
					// entry must overlap right endpoint of rangeToDelete
					long length = recEnd.subtract(end);
					SourceMapEntryData data =
						new SourceMapEntryData(fileId, lineNum, end.add(1), length);
					entriesToCreate.add(data);
				}
				recIter.delete();
			}
			// add the new entries
			for (SourceMapEntryData data : entriesToCreate) {
				sourceMapTableAdapter.addMapEntry(data.sourceFileId, data.lineNumber,
					data.baseAddress, data.length);
			}
			if (sourceMapChanged) {
				program.setChanged(ProgramEvent.SOURCE_MAP_CHANGED, null, null);
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * {@inheritDoc}<br>
	 * Note: this method will move any source map entry which is entirely contained within the
	 * source address range.  Entries which also contain addresses outside of this range will 
	 * be split and parts within the range to move will be moved.
	 * @param fromAddr first address of range to be moved
	 * @param toAddr target address
	 * @param length number of addresses to move
	 * @param monitor task monitor
	 * @throws AddressOverflowException if overflow occurs when computing new addresses
	 * @throws CancelledException if {@code monitor} is cancelled
	 */
	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws AddressOverflowException, CancelledException {

		if (length < 0) {
			throw new IllegalArgumentException(
				"Invalid negative length for moveAddressRange: " + length);
		}

		if (length == 0) {
			return; // nothing to do
		}

		lock.acquire();

		try {
			Address rangeToMoveEnd = fromAddr.addNoWrap(length - 1);
			AddressRange rangeToMove = new AddressRangeImpl(fromAddr, rangeToMoveEnd);
			RecordIterator recIter =
				sourceMapTableAdapter.getSourceMapRecordIterator(rangeToMoveEnd, false);
			boolean mapChanged = false;

			// Note: we iterate backwards since records are stored based on the start address.
			// We need to move records stored before the beginning of rangeToMove that 
			// overlap rangeToMove but we will never need to move records that start after  
			// rangeToMove.
			List<SourceMapEntryData> entriesToCreate = new ArrayList<>();
			while (recIter.hasPrevious()) {
				monitor.checkCancelled();
				DBRecord rec = recIter.previous();
				long entryLength = getLength(rec);
				if (entryLength == 0) {
					continue; // nothing to check
				}
				Address recStart = getStartAddress(rec);
				Address recEnd = getEndAddress(recStart, entryLength);

				if (!rangeToMove.intersects(recStart, recEnd)) {
					// we've found an entry entirely before rangeToMove
					// this means we can stop looking
					break;
				}
				long fileAndLine = getFileAndLine(rec);
				long fileId = fileAndLine >> 32;
				int lineNum = (int) (fileAndLine & 0xffffffff);

				if (isLessInSameSpace(recStart, fromAddr) &&
					isLessInSameSpace(rangeToMoveEnd, recEnd)) {
					// entry extends over left and right endpoint of rangeToMove
					long newLength = fromAddr.subtract(recStart);
					SourceMapEntryData left =
						new SourceMapEntryData(fileId, lineNum, recStart, newLength);
					entriesToCreate.add(left);
					SourceMapEntryData middle =
						new SourceMapEntryData(fileId, lineNum, fromAddr, length);
					entriesToCreate.add(middle);
					newLength = recEnd.subtract(rangeToMoveEnd);
					SourceMapEntryData right =
						new SourceMapEntryData(fileId, lineNum, rangeToMoveEnd.add(1), newLength);
					entriesToCreate.add(right);
					recIter.delete();
					continue;
				}

				if (isLessInSameSpace(recStart, fromAddr)) {
					// entry extends before left endpoint (but not past right)
					long newLength = fromAddr.subtract(recStart);
					SourceMapEntryData left =
						new SourceMapEntryData(fileId, lineNum, recStart, newLength);
					entriesToCreate.add(left);
					newLength = recEnd.subtract(fromAddr) + 1;
					SourceMapEntryData middle =
						new SourceMapEntryData(fileId, lineNum, fromAddr, newLength);
					entriesToCreate.add(middle);
					recIter.delete();
					continue;
				}

				if (isLessInSameSpace(rangeToMoveEnd, recEnd)) {
					// entry extends past right endpoint (but not before left)
					long newLength = rangeToMoveEnd.subtract(recStart) + 1;
					SourceMapEntryData middle =
						new SourceMapEntryData(fileId, lineNum, recStart, newLength);
					entriesToCreate.add(middle);
					newLength = recEnd.subtract(rangeToMoveEnd);
					SourceMapEntryData right =
						new SourceMapEntryData(fileId, lineNum, rangeToMoveEnd.add(1), newLength);
					entriesToCreate.add(right);
					recIter.delete();
					continue;
				}
				// entry is entirely within range to move, no adjustment needed
				mapChanged = true;

			}

			// add the new entries
			for (SourceMapEntryData data : entriesToCreate) {
				sourceMapTableAdapter.addMapEntry(data.sourceFileId, data.lineNumber,
					data.baseAddress, data.length);
			}

			mapChanged = mapChanged || !entriesToCreate.isEmpty();
			sourceMapTableAdapter.moveAddressRange(fromAddr, toAddr, length, monitor);

			if (mapChanged) {
				program.setChanged(ProgramEvent.SOURCE_MAP_CHANGED, null, null);
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean addSourceFile(SourceFile sourceFile) throws LockException {
		Objects.requireNonNull(sourceFile, "sourceFile cannot be null");
		program.checkExclusiveAccess();
		lock.acquire();
		try {
			Long key = getKeyForSourceFile(sourceFile);
			if (key != null) {
				return false;
			}
			DBRecord dbRecord = sourceFileTableAdapter.createSourceFileRecord(sourceFile);
			updateLastSourceFileAndLastKey(dbRecord);
			program.setObjChanged(ProgramEvent.SOURCE_FILE_ADDED, null, null, sourceFile);
			return true;
		}
		catch (IOException e) {
			dbError(e);
			return false;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean removeSourceFile(SourceFile sourceFile) throws LockException {
		Objects.requireNonNull(sourceFile, "sourceFile cannot be null");
		boolean mapChanged = false;
		program.checkExclusiveAccess();
		lock.acquire();
		try {
			Long key = getKeyForSourceFile(sourceFile);
			if (key == null) {
				return false;
			}
			RecordIterator recIter =
				sourceMapTableAdapter.getRecordsForSourceFile(key, 0, Integer.MAX_VALUE);
			while (recIter.hasNext()) {
				recIter.next();
				recIter.delete();
				mapChanged = true;
			}
			sourceFileTableAdapter.removeSourceFileRecord(key);
			lastKey = null;
			lastSourceFile = null;
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		program.setObjChanged(ProgramEvent.SOURCE_FILE_REMOVED, null, sourceFile, null);
		if (mapChanged) {
			program.setChanged(ProgramEvent.SOURCE_MAP_CHANGED, sourceFile, null);
		}
		return true;
	}

	@Override
	public List<SourceMapEntry> getSourceMapEntries(Address addr) {

		List<SourceMapEntry> sourceMapEntries = new ArrayList<>();

		lock.acquire();
		try {
			RecordIterator recIter = sourceMapTableAdapter.getSourceMapRecordIterator(addr, false);
			boolean foundNonZeroLength = false;
			while (recIter.hasPrevious()) {
				DBRecord rec = recIter.previous();
				long entryLength = getLength(rec);
				Address entryBase = getStartAddress(rec);
				if (addr.equals(entryBase)) {
					sourceMapEntries.add(getSourceMapEntry(rec));
					if (entryLength != 0) {
						foundNonZeroLength = true;
					}
					continue;
				}
				if (entryLength == 0) {
					continue; // only want length zero entries if they are based at addr
				}
				if (!foundNonZeroLength &&
					isLessOrEqualInSameSpace(addr, getEndAddress(entryBase, entryLength))) {
					sourceMapEntries.add(getSourceMapEntry(rec));
					continue;  // continue in case there are additional entries at entryBase
				}
				break;
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		Collections.sort(sourceMapEntries);
		return sourceMapEntries;
	}

	@Override
	public SourceMapEntry addSourceMapEntry(SourceFile sourceFile, int lineNumber, Address baseAddr,
			long length) throws LockException, AddressOverflowException {
		if (lineNumber < 0) {
			throw new IllegalArgumentException("lineNumber cannot be negative");
		}
		if (length < 0) {
			throw new IllegalArgumentException("length cannot be negative");
		}
		Objects.requireNonNull(sourceFile, "sourceFile cannot be null");
		Objects.requireNonNull(baseAddr, "baseAddr cannot be null");
		MemoryBlock startBlock = program.getMemory().getBlock(baseAddr);
		if (startBlock == null) {
			throw new AddressOutOfBoundsException(baseAddr + " is not in a defined memory block");
		}
		program.checkExclusiveAccess();

		lock.acquire();
		try {
			Long sourceFileId = getKeyForSourceFile(sourceFile);
			if (sourceFileId == null) {
				throw new IllegalArgumentException(
					sourceFile.toString() + " not associated with program");
			}
			if (length == 0) {
				return addZeroLengthEntry(sourceFileId, lineNumber, baseAddr);
			}
			Address endAddr = baseAddr.addNoWrap(length - 1);

			// check that the entry's range is entirely contained within defined memory blocks
			if (!startBlock.contains(endAddr)) {
				if (!program.getMemory().contains(baseAddr, endAddr)) {
					throw new AddressOutOfBoundsException(
						baseAddr + "," + endAddr + " spans undefined memory");
				}
			}
			SourceMapEntryDB entry = null;

			RecordIterator recIter =
				sourceMapTableAdapter.getSourceMapRecordIterator(endAddr, false);
			while (recIter.hasPrevious()) {
				DBRecord rec = recIter.previous();
				long entryLength = getLength(rec);
				if (entryLength == 0) {
					continue; // length 0 entries can't conflict
				}
				Address entryBase = getStartAddress(rec);
				if (entryBase.equals(baseAddr)) {
					if (entryLength != length) {
						throw new IllegalArgumentException(
							"new entry must have the same length as existing entry");
					}
					if ((sourceFileId << 32 | lineNumber) == getFileAndLine(rec)) {
						return getSourceMapEntry(rec);  // entry is already in the DB
					}
					continue; // non-conflicting entry found, continue checking
				}
				if (isLessOrEqualInSameSpace(baseAddr, entryBase)) {
					throw new IllegalArgumentException(
						"new entry would overlap entry " + getSourceMapEntry(rec).toString());
				}
				if (isLessOrEqualInSameSpace(entryBase, baseAddr)) {
					if (getEndAddress(entryBase, entryLength).compareTo(baseAddr) >= 0) {
						throw new IllegalArgumentException(
							"new entry would overlap entry " + getSourceMapEntry(rec).toString());
					}
				}
				break; // safe to add new entry
			}
			DBRecord rec =
				sourceMapTableAdapter.addMapEntry(sourceFileId, lineNumber, baseAddr, length);
			entry = new SourceMapEntryDB(this, rec, addrMap);
			program.setChanged(ProgramEvent.SOURCE_MAP_CHANGED, null, entry);
			return entry;
		}
		catch (IOException e) {
			dbError(e);
			throw new AssertionError("addSourceMapEntry unsuccessful - possible database error");
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean intersectsSourceMapEntry(AddressSetView addrs) {
		if (addrs == null || addrs.isEmpty()) {
			return false;
		}
		lock.acquire();
		try {
			for (AddressRangeIterator rangeIter = addrs.getAddressRanges(); rangeIter.hasNext();) {
				AddressRange r = rangeIter.next();
				RecordIterator recIter =
					sourceMapTableAdapter.getSourceMapRecordIterator(r.getMaxAddress(), false);
				while (recIter.hasPrevious()) {
					DBRecord rec = recIter.previous();
					Address entryStart = getStartAddress(rec);
					if (r.contains(entryStart)) {
						return true;
					}
					long length = getLength(rec);
					if (length == 0) {
						continue;
					}
					if (r.intersects(entryStart, getEndAddress(entryStart, length))) {
						return true;
					}
					break;
				}
			}
			return false;
		}
		catch (IOException e) {
			dbError(e);
			return false;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void dbError(IOException e) throws RuntimeException {
		program.dbError(e);
	}

	@Override
	public List<SourceFile> getMappedSourceFiles() {
		List<SourceFile> sourceFiles = new ArrayList<>();
		lock.acquire();
		try {
			for (RecordIterator sourceFileRecordIter =
				sourceFileTableAdapter.getRecords(); sourceFileRecordIter
						.hasNext();) {
				DBRecord sourceFileRecord = sourceFileRecordIter.next();
				long key = sourceFileRecord.getKey();
				RecordIterator sourceMapEntryRecordIter =
					sourceMapTableAdapter.getRecordsForSourceFile(key, 0, Integer.MAX_VALUE);
				if (sourceMapEntryRecordIter.hasNext()) {
					updateLastSourceFileAndLastKey(sourceFileRecord);
					sourceFiles.add(lastSourceFile);
				}
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return sourceFiles;
	}

	@Override
	public List<SourceFile> getAllSourceFiles() {
		List<SourceFile> sourceFiles = new ArrayList<>();
		lock.acquire();
		try {
			for (RecordIterator recordIter = sourceFileTableAdapter.getRecords(); recordIter
					.hasNext();) {
				updateLastSourceFileAndLastKey(recordIter.next());
				sourceFiles.add(lastSourceFile);
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return sourceFiles;
	}

	@Override
	public void transferSourceMapEntries(SourceFile source, SourceFile target)
			throws LockException {
		program.checkExclusiveAccess();

		lock.acquire();
		try {
			Long srcKey = getKeyForSourceFile(source);
			if (srcKey == null) {
				throw new IllegalArgumentException(
					source.toString() + " is not associated with program");
			}
			Long targetKey = getKeyForSourceFile(target);
			if (targetKey == null) {
				throw new IllegalArgumentException(
					target.toString() + " is not associated with program");
			}
			if (source.equals(target)) {
				return; // transfer redundant
			}
			for (SourceMapEntry entry : getSourceMapEntries(source, 0, Integer.MAX_VALUE)) {
				addSourceMapEntry(target, entry.getLineNumber(), entry.getBaseAddress(),
					entry.getLength());
				removeSourceMapEntry(entry); // remove fires a SOURCE_MAP_CHANGED event
			}
		}
		catch (AddressOverflowException e) {
			// can't happen - entry ranges were validated upon insert
			throw new AssertionError("bad address range in source map entry table");
		}
		finally {
			lock.release();
		}
	}

	@Override
	public SourceMapEntryIterator getSourceMapEntryIterator(Address address, boolean forward) {
		try {
			return new SourceMapEntryIteratorDB(this,
				sourceMapTableAdapter.getSourceMapRecordIterator(address, forward), forward);
		}
		catch (IOException e) {
			dbError(e);
		}
		return SourceMapEntryIterator.EMPTY_ITERATOR;
	}

	@Override
	public boolean containsSourceFile(SourceFile sourceFile) {
		if (sourceFile == null) {
			return false;
		}
		lock.acquire();
		try {
			return getKeyForSourceFile(sourceFile) != null;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public List<SourceMapEntry> getSourceMapEntries(SourceFile sourceFile, int minLine,
			int maxLine) {
		if (minLine < 0) {
			throw new IllegalArgumentException("minLine cannot be negative; was " + minLine);
		}
		if (maxLine < 0) {
			throw new IllegalArgumentException("maxLine cannot be negative; was " + maxLine);
		}
		if (maxLine < minLine) {
			throw new IllegalArgumentException("maxLine cannot be less than minLine");
		}
		List<SourceMapEntry> entries = new ArrayList<>();
		lock.acquire();
		try {
			Long key = getKeyForSourceFile(sourceFile);
			if (key == null) {
				return entries;
			}
			try {
				RecordIterator recIter =
					sourceMapTableAdapter.getRecordsForSourceFile(key, minLine, maxLine);
				while (recIter.hasNext()) {
					DBRecord rec = recIter.next();
					entries.add(getSourceMapEntry(rec));
				}
			}
			catch (IOException e) {
				dbError(e);
			}
		}
		finally {
			lock.release();
		}
		Collections.sort(entries);
		return entries;
	}

	@Override
	public boolean removeSourceMapEntry(SourceMapEntry entry) throws LockException {
		Objects.requireNonNull(entry, "entry cannot be null");
		program.checkExclusiveAccess();
		lock.acquire();
		try {
			RecordIterator recIter =
				sourceMapTableAdapter.getSourceMapRecordIterator(entry.getBaseAddress(), true);
			while (recIter.hasNext()) {
				DBRecord rec = recIter.next();
				long length = getLength(rec);
				if (length != entry.getLength()) {
					continue;
				}
				long fileAndLine = getFileAndLine(rec);
				if (((int) (fileAndLine & 0xffffffff)) != entry.getLineNumber()) {
					continue;
				}
				if (!(entry.getSourceFile().equals(getSourceFileFromKey(fileAndLine >> 32)))) {
					continue;
				}
				sourceMapTableAdapter.removeRecord(rec.getKey());
				program.setChanged(ProgramEvent.SOURCE_MAP_CHANGED, entry, null);
				return true;

			}
		}
		catch (IOException e) {
			dbError(e);
			return false;
		}
		finally {
			lock.release();
		}
		return false;
	}

	SourceFile getSourceFile(long key) {
		lock.acquire();
		try {
			return getSourceFileFromKey(key);
		}
		finally {
			lock.release();
		}
	}

	SourceMapEntry getSourceMapEntry(DBRecord rec) {
		return new SourceMapEntryDB(this, rec, addrMap);
	}

	static boolean isLessOrEqualInSameSpace(Address addr1, Address addr2) {
		if (!addr1.hasSameAddressSpace(addr2)) {
			return false;
		}
		return addr1.compareTo(addr2) <= 0;
	}

	static boolean isLessInSameSpace(Address addr1, Address addr2) {
		if (!addr1.hasSameAddressSpace(addr2)) {
			return false;
		}
		return addr1.compareTo(addr2) < 0;
	}

	// acquire lock before invoking
	private SourceMapEntry addZeroLengthEntry(long sourceFileId, int lineNumber, Address baseAddr) {
		SourceMapEntry entry = null;
		try {
			RecordIterator recIter =
				sourceMapTableAdapter.getSourceMapRecordIterator(baseAddr, true);
			while (recIter.hasNext()) {
				DBRecord rec = recIter.next();
				Address recAddress = getStartAddress(rec);
				if (!recAddress.equals(baseAddr)) {
					break;
				}
				if (getLength(rec) != 0) {
					continue;
				}
				long fileAndLine = getFileAndLine(rec);
				if ((sourceFileId << 32 | lineNumber) != fileAndLine) {
					continue;
				}
				return getSourceMapEntry(rec);
			}
			DBRecord rec = sourceMapTableAdapter.addMapEntry(sourceFileId, lineNumber, baseAddr, 0);
			entry = new SourceMapEntryDB(this, rec, addrMap);
			program.setChanged(ProgramEvent.SOURCE_MAP_CHANGED, null, entry);
			return entry;
		}
		catch (IOException e) {
			dbError(e);
			throw new AssertionError("addZeroLengthEntry unsuccessful - possible database error");
		}
	}

	private long getLength(DBRecord rec) {
		return rec.getLongValue(SourceMapAdapter.LENGTH_COL);
	}

	private Address getStartAddress(DBRecord rec) {
		return addrMap.decodeAddress(rec.getLongValue(SourceMapAdapter.BASE_ADDR_COL));
	}

	private long getFileAndLine(DBRecord rec) {
		return rec.getLongValue(SourceMapAdapter.FILE_LINE_COL);
	}

	// assumes that start and length are from a valid SourceMapEntry
	// that is, start.add(length - 1) doesn't wrap and is in the same 
	// space
	private Address getEndAddress(Address start, long length) {
		if (length == 0) {
			return start;
		}
		try {
			return start.addNoWrap(length - 1);
		}
		catch (AddressOverflowException e) {
			// shouldn't happen, but return space max to prevent possibility of wrapping
			return start.getAddressSpace().getMaxAddress();
		}
	}

	// acquire lock before invoking
	private SourceFile getSourceFileFromKey(long key) {
		if (lastKey == null || lastKey.longValue() != key) {
			DBRecord dbRecord = null;
			try {
				dbRecord = sourceFileTableAdapter.getRecord(key);
			}
			catch (IOException e) {
				dbError(e);
				return null;
			}
			if (dbRecord == null) {
				return null;
			}
			updateLastSourceFileAndLastKey(dbRecord);
		}
		return lastSourceFile;
	}

	// acquire lock before invoking
	private Long getKeyForSourceFile(SourceFile sourceFile) {
		if (lastSourceFile == null || !sourceFile.equals(lastSourceFile)) {
			DBRecord dbRecord = null;
			try {
				dbRecord = sourceFileTableAdapter.getRecord(sourceFile);
			}
			catch (IOException e) {
				dbError(e);
				return null;
			}
			if (dbRecord == null) {
				return null;
			}
			updateLastSourceFileAndLastKey(dbRecord);
		}
		return lastKey;
	}

	private void updateLastSourceFileAndLastKey(DBRecord dbRecord) {
		lastKey = dbRecord.getKey();
		String path = dbRecord.getString(SourceFileAdapter.PATH_COL);
		SourceFileIdType idType =
			SourceFileIdType.getTypeFromIndex(dbRecord.getByteValue(SourceFileAdapter.ID_TYPE_COL));
		byte[] identifier = dbRecord.getBinaryData(SourceFileAdapter.ID_COL);
		lastSourceFile = new SourceFile(path, idType, identifier, false);
	}

	/**
	 * A record for storing information about new source map entries which must be created
	 * during {@link #moveAddressRange} or {@link #deleteAddressRange} 
	 */
	private record SourceMapEntryData(long sourceFileId, int lineNumber, Address baseAddress,
			long length) {}

}
