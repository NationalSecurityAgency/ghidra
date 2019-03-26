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
 * Represents a _STRUCT_X86_THREAD_STATE32 structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/osfmk/mach/i386/_structs.h.auto.html">mach/i386/_structs.h</a> 
 */
public class ThreadStateX86_32 extends ThreadStateX86 {
	public int eax;
	public int ebx;
	public int ecx;
	public int edx;
	public int edi;
	public int esi;
	public int ebp;
	public int esp;
	public int ss;
	public int eflags;
	public int eip;
	public int cs;
	public int ds;
	public int es;
	public int fs;
	public int gs;

	static ThreadStateX86_32 createThreadStateX86_32(FactoryBundledWithBinaryReader reader)
			throws IOException {
		ThreadStateX86_32 threadStateX86_32 =
			(ThreadStateX86_32) reader.getFactory().create(ThreadStateX86_32.class);
		threadStateX86_32.initThreadStateX86_32(reader);
		return threadStateX86_32;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public ThreadStateX86_32() {
	}

	private void initThreadStateX86_32(FactoryBundledWithBinaryReader reader) throws IOException {
		eax = reader.readNextInt();
		ebx = reader.readNextInt();
		ecx = reader.readNextInt();
		edx = reader.readNextInt();
		edi = reader.readNextInt();
		esi = reader.readNextInt();
		ebp = reader.readNextInt();
		esp = reader.readNextInt();
		ss = reader.readNextInt();
		eflags = reader.readNextInt();
		eip = reader.readNextInt();
		cs = reader.readNextInt();
		ds = reader.readNextInt();
		es = reader.readNextInt();
		fs = reader.readNextInt();
		gs = reader.readNextInt();
	}

    @Override
    public long getInstructionPointer() {
		return Conv.intToLong(eip);
    }

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("x86_THREAD_STATE32", 0);
		struct.add(DWORD, "eax", null);
		struct.add(DWORD, "ebx", null);
		struct.add(DWORD, "ecx", null);
		struct.add(DWORD, "edx", null);
		struct.add(DWORD, "edi", null);
		struct.add(DWORD, "esi", null);
		struct.add(DWORD, "ebp", null);
		struct.add(DWORD, "esp", null);
		struct.add(DWORD, "ss", null);
		struct.add(DWORD, "eflags", null);
		struct.add(DWORD, "eip", null);
		struct.add(DWORD, "cs", null);
		struct.add(DWORD, "ds", null);
		struct.add(DWORD, "es", null);
		struct.add(DWORD, "fs", null);
		struct.add(DWORD, "gs", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
