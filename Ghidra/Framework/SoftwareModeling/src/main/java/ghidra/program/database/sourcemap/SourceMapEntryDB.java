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

import java.util.Objects;

import db.DBRecord;
import ghidra.program.database.map.AddressMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.sourcemap.SourceMapEntry;

/**
 * Database implementation of {@link SourceMapEntry} interface.
 * <p>
 * Note: clients should drop and reacquire all SourceMapEntryDB objects upon undo/redo, 
 * ProgramEvent.SOURCE_MAP_CHANGED, and ProgramEvent.SOURCE_FILE_REMOVED.
 */
public class SourceMapEntryDB implements SourceMapEntry {

	private int lineNumber;
	private SourceFile sourceFile;
	private Address baseAddress;
	private long length;
	private AddressRange range = null;

	/**
	 * Creates a new SourceMapEntryDB
	 * @param manager source file manager
	 * @param record backing record
	 * @param addrMap address map
	 */
	SourceMapEntryDB(SourceFileManagerDB manager, DBRecord record, AddressMapDB addrMap) {
		manager.lock.acquire();
		try {
			long fileAndLine = record.getLongValue(SourceMapAdapter.FILE_LINE_COL);
			lineNumber = (int) (fileAndLine & 0xffffffff);
			sourceFile = manager.getSourceFile(fileAndLine >> 32);
			long encodedAddress = record.getLongValue(SourceMapAdapter.BASE_ADDR_COL);
			baseAddress = addrMap.decodeAddress(encodedAddress);
			length = record.getLongValue(SourceMapAdapter.LENGTH_COL);
			if (length != 0) {
				Address max;
				try {
					max = baseAddress.addNoWrap(length - 1);
				}
				catch (AddressOverflowException e) {
					// shouldn't happen, but return space max to prevent possibility of wrapping
					max = baseAddress.getAddressSpace().getMaxAddress();
				}
				range = new AddressRangeImpl(baseAddress, max);
			}
		}
		finally {
			manager.lock.release();
		}
	}

	@Override
	public int getLineNumber() {
		return lineNumber;
	}

	@Override
	public SourceFile getSourceFile() {
		return sourceFile;
	}

	@Override
	public Address getBaseAddress() {
		return baseAddress;
	}

	@Override
	public AddressRange getRange() {
		return range;
	}

	@Override
	public long getLength() {
		return length;
	}

	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer(getSourceFile().toString());
		sb.append(":");
		sb.append(getLineNumber());
		sb.append(" @ ");
		sb.append(getBaseAddress().toString());
		sb.append(" (");
		sb.append(Long.toString(getLength()));
		sb.append(")");
		return sb.toString();
	}

	@Override
	public int compareTo(SourceMapEntry o) {
		int sourceFileCompare = getSourceFile().compareTo(o.getSourceFile());
		if (sourceFileCompare != 0) {
			return sourceFileCompare;
		}
		int lineCompare = Integer.compare(getLineNumber(), o.getLineNumber());
		if (lineCompare != 0) {
			return lineCompare;
		}
		int addrCompare = getBaseAddress().compareTo(o.getBaseAddress());
		if (addrCompare != 0) {
			return addrCompare;
		}
		return Long.compareUnsigned(getLength(), o.getLength());
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof SourceMapEntry otherEntry)) {
			return false;
		}
		if (lineNumber != otherEntry.getLineNumber()) {
			return false;
		}
		if (!sourceFile.equals(otherEntry.getSourceFile())) {
			return false;
		}
		if (!baseAddress.equals(otherEntry.getBaseAddress())) {
			return false;
		}
		if (length != otherEntry.getLength()) {
			return false;
		}
		if (!Objects.equals(range, otherEntry.getRange())) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		int hashCode = lineNumber;
		hashCode = 31 * hashCode + sourceFile.hashCode();
		hashCode = 31 * hashCode + baseAddress.hashCode();
		hashCode = 31 * hashCode + Long.hashCode(length);
		return hashCode;
	}

}
