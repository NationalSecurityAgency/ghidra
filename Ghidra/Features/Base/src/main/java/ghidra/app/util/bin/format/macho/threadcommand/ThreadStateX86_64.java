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
 * Represents a _STRUCT_X86_THREAD_STATE64 structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/osfmk/mach/i386/_structs.h.auto.html">mach/i386/_structs.h</a> 
 */
public class ThreadStateX86_64 extends ThreadStateX86 {
	public long rax;
	public long rbx;
	public long rcx;
	public long rdx;
	public long rdi;
	public long rsi;
	public long rbp;
	public long rsp;
	public long r8;
	public long r9;
	public long r10;
	public long r11;
	public long r12;
	public long r13;
	public long r14;
	public long r15;
	public long rip;
	public long rflags;
	public long cs;
	public long fs;
	public long gs;

	static ThreadStateX86_64 createThreadStateX86_64(FactoryBundledWithBinaryReader reader)
			throws IOException {
		ThreadStateX86_64 threadStateX86_64 =
			(ThreadStateX86_64) reader.getFactory().create(ThreadStateX86_64.class);
		threadStateX86_64.initThreadStateX86_64(reader);
		return threadStateX86_64;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public ThreadStateX86_64() {
	}

	private void initThreadStateX86_64(FactoryBundledWithBinaryReader reader) throws IOException {
		rax = reader.readNextLong();
		rbx = reader.readNextLong();
		rcx = reader.readNextLong();
		rdx = reader.readNextLong();
		rdi = reader.readNextLong();
		rsi = reader.readNextLong();
		rbp = reader.readNextLong();
		rsp = reader.readNextLong();
		r8 = reader.readNextLong();
		r9 = reader.readNextLong();
		r10 = reader.readNextLong();
		r11 = reader.readNextLong();
		r12 = reader.readNextLong();
		r13 = reader.readNextLong();
		r14 = reader.readNextLong();
		r15 = reader.readNextLong();
		rip = reader.readNextLong();
		rflags = reader.readNextLong();
		cs = reader.readNextLong();
		fs = reader.readNextLong();
		gs = reader.readNextLong();
	}

	@Override
	public long getInstructionPointer() {
		return rip;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("x86_THREAD_STATE64", 0);
		struct.add(QWORD, "rax", null);
		struct.add(QWORD, "rbx", null);
		struct.add(QWORD, "cx", null);
		struct.add(QWORD, "rdx", null);
		struct.add(QWORD, "rdi", null);
		struct.add(QWORD, "rsi", null);
		struct.add(QWORD, "rbp", null);
		struct.add(QWORD, "rsp", null);
		struct.add(QWORD, "r8", null);
		struct.add(QWORD, "r9", null);
		struct.add(QWORD, "r10", null);
		struct.add(QWORD, "r11", null);
		struct.add(QWORD, "r12", null);
		struct.add(QWORD, "r13", null);
		struct.add(QWORD, "r14", null);
		struct.add(QWORD, "r15", null);
		struct.add(QWORD, "rip", null);
		struct.add(QWORD, "rflags", null);
		struct.add(QWORD, "cs", null);
		struct.add(QWORD, "fs", null);
		struct.add(QWORD, "gs", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
