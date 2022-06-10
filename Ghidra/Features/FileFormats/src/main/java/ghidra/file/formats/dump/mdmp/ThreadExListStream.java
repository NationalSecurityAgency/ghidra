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
package ghidra.file.formats.dump.mdmp;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.dump.DumpFileReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class ThreadExListStream implements StructConverter {

	public final static String NAME = "MINIDUMP_THREAD_EX_LIST";

	private int numberOfThreads;
	private ThreadEx[] threads;

	private DumpFileReader reader;
	private long index;

	ThreadExListStream(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setNumberOfThreads(reader.readNextInt());
		threads = new ThreadEx[numberOfThreads];
		for (int i = 0; i < numberOfThreads; i++) {
			setThread(new ThreadEx(reader, reader.getPointerIndex()), i);
		}
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(DWORD, 4, "NumberOfThreads", null);
		DataType t = threads[0].toDataType();
		ArrayDataType a = new ArrayDataType(t, numberOfThreads, t.getLength());
		struct.add(a, a.getLength(), "Threads", null);

		struct.setCategoryPath(new CategoryPath("/MDMP"));

		return struct;
	}

	public int getNumberOfThreads() {
		return numberOfThreads;
	}

	public void setNumberOfThreads(int numberOfThreads) {
		this.numberOfThreads = numberOfThreads;
	}

	public ThreadEx getThread(int idx) {
		return threads[idx];
	}

	public void setThread(ThreadEx thread, int index) {
		this.threads[index] = thread;
	}
}
