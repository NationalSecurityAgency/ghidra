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

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a _STRUCT_ARM_THREAD_STATE64 structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/osfmk/mach/arm/_structs.h.auto.html">mach/arm/_structs.h</a> 
 */
public class ThreadStateARM_64 extends ThreadState {

	public static final int ARM64_THREAD_STATE = 6;

	public long x0;
	public long x1;
	public long x2;
	public long x3;
	public long x4;
	public long x5;
	public long x6;
	public long x7;
	public long x8;
	public long x9;
	public long x10;
	public long x11;
	public long x12;
	public long x13;
	public long x14;
	public long x15;
	public long x16;
	public long x17;
	public long x18;
	public long x19;
	public long x20;
	public long x21;
	public long x22;
	public long x23;
	public long x24;
	public long x25;
	public long x26;
	public long x27;
	public long x28;
	public long fp;
	public long lr;
	public long sp;
	public long pc;
	public int cpsr;
	public int pad;

	static ThreadStateARM_64 createThreadStateARM_64(FactoryBundledWithBinaryReader reader)
			throws IOException {
		ThreadStateARM_64 threadStateARM_64 =
			(ThreadStateARM_64) reader.getFactory().create(ThreadStateARM_64.class);
		threadStateARM_64.initThreadStateARM_64(reader);
		return threadStateARM_64;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public ThreadStateARM_64() {
	}

	private void initThreadStateARM_64(FactoryBundledWithBinaryReader reader) throws IOException {
		x0 = reader.readNextLong();
		x1 = reader.readNextLong();
		x2 = reader.readNextLong();
		x3 = reader.readNextLong();
		x4 = reader.readNextLong();
		x5 = reader.readNextLong();
		x6 = reader.readNextLong();
		x7 = reader.readNextLong();
		x8 = reader.readNextLong();
		x9 = reader.readNextLong();
		x10 = reader.readNextLong();
		x11 = reader.readNextLong();
		x12 = reader.readNextLong();
		x13 = reader.readNextLong();
		x14 = reader.readNextLong();
		x15 = reader.readNextLong();
		x16 = reader.readNextLong();
		x17 = reader.readNextLong();
		x18 = reader.readNextLong();
		x19 = reader.readNextLong();
		x20 = reader.readNextLong();
		x21 = reader.readNextLong();
		x22 = reader.readNextLong();
		x23 = reader.readNextLong();
		x24 = reader.readNextLong();
		x25 = reader.readNextLong();
		x26 = reader.readNextLong();
		x27 = reader.readNextLong();
		x28 = reader.readNextLong();
		fp = reader.readNextLong();
		lr = reader.readNextLong();
		sp = reader.readNextLong();
		pc = reader.readNextLong();
		cpsr = reader.readNextInt();
		pad = reader.readNextInt();
	}

	@Override
	public long getInstructionPointer() {
		return pc;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("ARM64_THREAD_STATE", 0);
		for (int i = 0; i <= 28; i++) {
			struct.add(QWORD, "x" + i, null);
		}
		struct.add(QWORD, "fp", null);
		struct.add(QWORD, "lr", null);
		struct.add(QWORD, "sp", null);
		struct.add(QWORD, "pc", null);
		struct.add(DWORD, "cpsr", null);
		struct.add(DWORD, "pad", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
