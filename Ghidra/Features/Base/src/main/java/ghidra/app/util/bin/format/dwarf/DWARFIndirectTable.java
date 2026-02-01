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
import java.util.HashMap;
import java.util.Map;
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
	private final Map<Long, DWARFIndirectTableHeader> lookupMap = new HashMap<>();
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
			monitor.setMessage(msg + " #" + lookupMap.size());

			DWARFIndirectTableHeader header = headerReader.apply(reader);
			if (header != null) {
				lookupMap.put(header.getFirstElementOffset(), header);
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
		long base = baseOffsetFunc.apply(cu);
		DWARFIndirectTableHeader header = lookupMap.get(base);
		if (header == null) {
			throw new IOException(
				"Invalid base %d for compUnit %x".formatted(base, cu.getStartOffset()));
		}
		return header.getOffset(index, reader);
	}

	public void clear() {
		lookupMap.clear();
	}

}
