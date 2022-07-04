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
package ghidra.file.formats.dump.pagedump;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.dump.DumpFileReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class PhysicalMemoryDescriptor implements StructConverter {

	public final static String NAME = "PAGEDUMP_PHYS_MEMORY_DESCRIPTOR";

	private int numberOfRuns;
	private long numberOfPages;
	private PhysicalMemoryRun[] runs;

	private DumpFileReader reader;
	private long index;

	PhysicalMemoryDescriptor(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		int nruns = (int) reader.readNextPointer();
		if (nruns == Pagedump.SIGNATURE) {
			setNumberOfRuns(0);
			return;
		}
		setNumberOfRuns(nruns);
		setNumberOfPages(reader.readNextPointer());
		runs = new PhysicalMemoryRun[numberOfRuns];
		for (int i = 0; i < numberOfRuns; i++) {
			setRuns(new PhysicalMemoryRun(reader, reader.getPointerIndex()), i);
		}
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(DWORD, 4, "NumberOfRuns", null);
		struct.add(DWORD, 4, "NumberOfPages", null);
		DataType t = runs[0].toDataType();
		ArrayDataType a = new ArrayDataType(t, numberOfRuns, t.getLength());
		struct.add(a, a.getLength(), "Runs", null);

		struct.setCategoryPath(new CategoryPath("/PDMP"));

		return struct;
	}

	public int getNumberOfRuns() {
		return numberOfRuns;
	}

	public void setNumberOfRuns(int numberOfRuns) {
		this.numberOfRuns = numberOfRuns;
	}

	public long getNumberOfPages() {
		return numberOfPages;
	}

	public void setNumberOfPages(long numberOfPages) {
		this.numberOfPages = numberOfPages;
	}

	public PhysicalMemoryRun[] getRuns() {
		return runs;
	}

	public void setRuns(PhysicalMemoryRun run, int index) {
		this.runs[index] = run;
	}
}
