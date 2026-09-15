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
package ghidra.app.util.bin.format.dwarf;

import java.io.IOException;
import java.util.*;
import java.util.function.Function;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Handles a grouping of {@link DWARFIndirectTableHeader}s that specify how to look up a
 * certain type of item (per CU).
 */
public class DWARFIndirectTable {
	public interface CheckedIOFunction<T, R> {
		R apply(T value) throws IOException;
	}

	private final BinaryReader reader;
	private final List<DWARFIndirectTableHeader> headers = new ArrayList<>();
	private final List<Long> headerOffsets = new ArrayList<>();
	private final Function<DWARFCompilationUnit, Long> baseOffsetFunc;

	/**
	 * Creates a {@link DWARFIndirectTable}
	 * 
	 * @param reader {@link BinaryReader} containing the {@link DWARFIndirectTableHeader}s
	 * @param baseOffsetFunc a function that will return the baseoffset value for a
	 * {@link DWARFCompilationUnit}.
	 */
	public DWARFIndirectTable(BinaryReader reader,
			Function<DWARFCompilationUnit, Long> baseOffsetFunc) {
		this.reader = reader;
		this.baseOffsetFunc = baseOffsetFunc;
	}

	/**
	 * Populates this instance will all {@link DWARFIndirectTableHeader} instances that can be
	 * read from the stream.
	 * 
	 * @param msg String message to use for the taskmonitor
	 * @param headerReader a function that reads the specific table header type from the stream
	 * @param monitor {@link TaskMonitor}
	 * @throws CancelledException if cancelled
	 * @throws IOException if error reading a header
	 */
	public void bootstrap(String msg,
			CheckedIOFunction<BinaryReader, ? extends DWARFIndirectTableHeader> headerReader,
			TaskMonitor monitor) throws CancelledException, IOException {
		if (reader == null) {
			return;
		}
		reader.setPointerIndex(0);
		monitor.initialize(reader.length(), msg);
		while (reader.hasNext()) {
			monitor.checkCancelled();
			monitor.setProgress(reader.getPointerIndex());
			monitor.setMessage(msg + " #" + headerOffsets.size());

			DWARFIndirectTableHeader header = headerReader.apply(reader);
			if (header != null) {
				headers.add(header);
				headerOffsets.add(header.getFirstElementOffset());
			}
		}
	}

	/**
	 * Returns the offset of an item, based on its index in a particular header (which is found
	 * by the controlling CU)
	 * 
	 * @param index index of the item
	 * @param cu {@link DWARFCompilationUnit}
	 * @return long offset of the item.  Caller responsible for reading the item themselves
	 * @throws IOException if error reading table data
	 */
	public long getOffset(int index, DWARFCompilationUnit cu) throws IOException {

		// offset to/into a indirect table, from which the index applies.  Some indirect table types
		// (addr, string) allow the base to point anywhere in a table, others (loclist, rangelist)
		// specify that the base must be the first element of one of the tables
		long baseOffset = baseOffsetFunc.apply(cu);

		// calculate which header object contains the base offset
		int baseHeaderIndex = Collections.binarySearch(headerOffsets, baseOffset);
		if (baseHeaderIndex < 0) {
			baseHeaderIndex = ~baseHeaderIndex - 1;
		}
		if (baseHeaderIndex < 0) {
			throw new IOException(
				"Invalid base %d for compUnit %x".formatted(baseOffset, cu.getStartOffset()));
		}
		DWARFIndirectTableHeader header = headers.get(baseHeaderIndex);

		return header.getOffset(index, baseOffset, reader);
	}

	public void clear() {
		headers.clear();
		headerOffsets.clear();
	}

}
