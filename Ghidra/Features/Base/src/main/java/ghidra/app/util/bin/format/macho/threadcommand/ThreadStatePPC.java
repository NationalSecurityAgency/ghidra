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

public class ThreadStatePPC extends ThreadState {
	public final static int PPC_THREAD_STATE = 1;
	public final static int PPC_FLOAT_STATE = 2;
	public final static int PPC_EXCEPTION_STATE = 3;
	public final static int PPC_VECTOR_STATE = 4;
	public final static int PPC_THREAD_STATE64 = 5;
	public final static int PPC_EXCEPTION_STATE64 = 6;
	public final static int THREAD_STATE_NONE = 7;

	/** Instruction address register (PC) */
	public long srr0;
	/** Machine state register (supervisor) */
	public long srr1;
	public long r0;
	public long r1;
	public long r2;
	public long r3;
	public long r4;
	public long r5;
	public long r6;
	public long r7;
	public long r8;
	public long r9;
	public long r10;
	public long r11;
	public long r12;
	public long r13;
	public long r14;
	public long r15;
	public long r16;
	public long r17;
	public long r18;
	public long r19;
	public long r20;
	public long r21;
	public long r22;
	public long r23;
	public long r24;
	public long r25;
	public long r26;
	public long r27;
	public long r28;
	public long r29;
	public long r30;
	public long r31;
	/** Condition register */
	public int cr;
	/** User's integer exception register */
	public long xer;
	/** Link register */
	public long lr;
	/** Count register */
	public long ctr;
	/** MQ register (601 only) */
	public long mq;
	/** Vector Save Register */
	public long vrsave;

	static ThreadStatePPC createThreadStatePPC(FactoryBundledWithBinaryReader reader,
			boolean is32bit) throws IOException {
		ThreadStatePPC threadStatePPC =
			(ThreadStatePPC) reader.getFactory().create(ThreadStatePPC.class);
		threadStatePPC.initThreadStatePPC(reader, is32bit);
		return threadStatePPC;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public ThreadStatePPC() {
	}

	private void initThreadStatePPC(FactoryBundledWithBinaryReader reader, boolean is32bit)
			throws IOException {
		srr0 = read(reader, is32bit);
		srr1 = read(reader, is32bit);
		r0 = read(reader, is32bit);
		r1 = read(reader, is32bit);
		r2 = read(reader, is32bit);
		r3 = read(reader, is32bit);
		r4 = read(reader, is32bit);
		r5 = read(reader, is32bit);
		r6 = read(reader, is32bit);
		r7 = read(reader, is32bit);
		r8 = read(reader, is32bit);
		r9 = read(reader, is32bit);
		r10 = read(reader, is32bit);
		r11 = read(reader, is32bit);
		r12 = read(reader, is32bit);
		r13 = read(reader, is32bit);
		r14 = read(reader, is32bit);
		r15 = read(reader, is32bit);
		r16 = read(reader, is32bit);
		r17 = read(reader, is32bit);
		r18 = read(reader, is32bit);
		r19 = read(reader, is32bit);
		r20 = read(reader, is32bit);
		r21 = read(reader, is32bit);
		r22 = read(reader, is32bit);
		r23 = read(reader, is32bit);
		r24 = read(reader, is32bit);
		r25 = read(reader, is32bit);
		r26 = read(reader, is32bit);
		r27 = read(reader, is32bit);
		r28 = read(reader, is32bit);
		r29 = read(reader, is32bit);
		r30 = read(reader, is32bit);
		r31 = read(reader, is32bit);
		cr = reader.readNextInt();
		xer = read(reader, is32bit);
		lr = read(reader, is32bit);
		ctr = read(reader, is32bit);
		mq = read(reader, is32bit);
		vrsave = read(reader, is32bit);
	}

	private long read(FactoryBundledWithBinaryReader reader, boolean is32bit) throws IOException {
		if (is32bit) {
			return reader.readNextInt() & 0xffffffffL;
		}
		return reader.readNextLong();
	}

	@Override
	public long getInstructionPointer() {
		return srr0;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("PPC_THREAD_STATE", 0);
		struct.add(DWORD, "srr0", null);
		struct.add(DWORD, "srr1", null);
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
		struct.add(DWORD, "r13", null);
		struct.add(DWORD, "r14", null);
		struct.add(DWORD, "r15", null);
		struct.add(DWORD, "r16", null);
		struct.add(DWORD, "r17", null);
		struct.add(DWORD, "r18", null);
		struct.add(DWORD, "r19", null);
		struct.add(DWORD, "r20", null);
		struct.add(DWORD, "r21", null);
		struct.add(DWORD, "r22", null);
		struct.add(DWORD, "r23", null);
		struct.add(DWORD, "r24", null);
		struct.add(DWORD, "r25", null);
		struct.add(DWORD, "r26", null);
		struct.add(DWORD, "r27", null);
		struct.add(DWORD, "r28", null);
		struct.add(DWORD, "r29", null);
		struct.add(DWORD, "r30", null);
		struct.add(DWORD, "r31", null);
		struct.add(DWORD, "cr", null);
		struct.add(DWORD, "xer", null);
		struct.add(DWORD, "lr", null);
		struct.add(DWORD, "ctr", null);
		struct.add(DWORD, "mq", null);
		struct.add(DWORD, "vrsave", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
