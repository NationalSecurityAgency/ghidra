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
import ghidra.util.Conv;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a _STRUCT_ARM_THREAD_STATE structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/osfmk/mach/arm/_structs.h.auto.html">mach/arm/_structs.h</a> 
 */
public class ThreadStateARM extends ThreadState {
	public final static int ARM_THREAD_STATE = 1;
	public final static int ARM_VFP_STATE = 2;
	public final static int ARM_EXCEPTION_STATE = 3;
	public final static int ARM_DEBUG_STATE = 4;
	public final static int THREAD_STATE_NONE = 5;

	public int r0;
	public int r1;
	public int r2;
	public int r3;
	public int r4;
	public int r5;
	public int r6;
	public int r7;
	public int r8;
	public int r9;
	public int r10;
	public int r11;
	public int r12;
	public int sp;
	public int lr;
	public int pc;
	public int cpsr;

	static ThreadStateARM createThreadStateARM(FactoryBundledWithBinaryReader reader)
			throws IOException {
		ThreadStateARM threadStateARM =
			(ThreadStateARM) reader.getFactory().create(ThreadStateARM.class);
		threadStateARM.initThreadStateARM(reader);
		return threadStateARM;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public ThreadStateARM() {
	}

	private void initThreadStateARM(FactoryBundledWithBinaryReader reader) throws IOException {
		r0 = reader.readNextInt();
		r1 = reader.readNextInt();
		r2 = reader.readNextInt();
		r3 = reader.readNextInt();
		r4 = reader.readNextInt();
		r5 = reader.readNextInt();
		r6 = reader.readNextInt();
		r7 = reader.readNextInt();
		r8 = reader.readNextInt();
		r9 = reader.readNextInt();
		r10 = reader.readNextInt();
		r11 = reader.readNextInt();
		r12 = reader.readNextInt();
		sp = reader.readNextInt();
		lr = reader.readNextInt();
		pc = reader.readNextInt();
		cpsr = reader.readNextInt();
	}

	@Override
	public long getInstructionPointer() {
		return Conv.intToLong(pc);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("ARM_THREAD_STATE", 0);
		struct.add(DWORD, "r0", null);
		struct.add(DWORD, "r1", null);
		struct.add(DWORD, "r2", null);
		struct.add(DWORD, "r3", null);
		struct.add(DWORD, "r4", null);
		struct.add(DWORD, "r5", null);
		struct.add(DWORD, "r6", null);
		struct.add(DWORD, "r7", null);
		struct.add(DWORD, "r8", null);
		struct.add(DWORD, "r9", null);
		struct.add(DWORD, "r10", null);
		struct.add(DWORD, "r11", null);
		struct.add(DWORD, "r12", null);
		struct.add(DWORD, "sp", null);
		struct.add(DWORD, "lr", null);
		struct.add(DWORD, "pc", null);
		struct.add(DWORD, "cpsr", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
