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
package ghidra.app.util.bin.format.macho.threadcommand;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class ThreadStateHeader implements StructConverter {
	private int flavor;
	private int count;

	static ThreadStateHeader createThreadStateHeader(FactoryBundledWithBinaryReader reader)
			throws IOException {
		ThreadStateHeader threadStateHeader =
			(ThreadStateHeader) reader.getFactory().create(ThreadStateHeader.class);
		threadStateHeader.initThreadStateHeader(reader);
		return threadStateHeader;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public ThreadStateHeader() {
	}

	private void initThreadStateHeader(FactoryBundledWithBinaryReader reader) throws IOException {
		flavor = reader.readNextInt();
		count = reader.readNextInt();
	}

	/**
	 * Returns the flavor of thread state.
	 * @return the flavor of thread state
	 */
	public int getFlavor() {
		return flavor;
	}

	/**
	 * Returns the count of longs in thread state.
	 * @return the count of longs in thread state
	 */
	public int getCount() {
		return count;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("thread_state_hdr", 0);
		struct.add(DWORD, "flavor", null);
		struct.add(DWORD, "count", null);
		return struct;
	}
}
