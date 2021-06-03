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
package ghidra.app.plugin.core.select.flow;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.*;

public class FollowFlowProgramBuilder extends ProgramBuilder {

	DataConverter dataConverter;
	AddressFactory addressFactory;

	public FollowFlowProgramBuilder() throws Exception {
		super("SelectByFlow", ProgramBuilder._X86);
		setupProgram();
	}

	/*
	
	function(A, 0x00, 0x2f)
	00	nop
	01	nop
	06	conditional jump UU    [2]
	08	unconditional jump A1  [2]
	0a	UU nop
	0b	nop
	0c	unconditional jump VV  [2]
	0e	A1 nop
	0f	VV nop
	10	nop
	11	unconditional call B   [5]
	16	nop
	17	nop
	18	nop
	19	nop
	1a	nop
	1b	nop
	1c	conditional call C     [5]
	21	nop
	22	nop
	23	computed jump XX       [2]
	25	nop
	26	XX nop
	27	nop
	28	computed call D        [5]
	2d	conditional jump XX    [2]
	2f	ret

	function(B, 0x30, 0x5f)
	30	nop
	31	nop
	36	conditional jump WW    [2]
	38	unconditional jump B1  [2]
	3a	WW nop
	3b	nop
	3c	unconditional jump YY  [2]
	3e	B1 nop
	3f	YY nop
	40	nop
	41	unconditional call E   [5]
	46	nop
	47	nop
	48	nop
	49	nop
	4a	nop
	4b	nop
	4c	conditional call F     [5]
	51	computed jump ZZ       [2]
	53	nop
	54	ZZ nop
	55	computed call G        [5]
	5a	conditional call A     [5]
	5f	ret

	function(C, 0x60, 0x8f)
	60	nop
	61	nop
	66	conditional jump UU    [2]
	68	unconditional jump C1  [2]
	6a	UU nop
	6b	nop
	6c	unconditional jump VV  [2]
	6e	C1 nop
	6f	VV nop
	70	nop
	71	unconditional call H   [5]
	76	nop
	77	nop
	78	nop
	79	nop
	7a	nop
	7b	nop
	7c	conditional call I     [5]
	81	nop
	82	nop
	83	computed jump XX       [2]
	85	nop
	86	XX nop
	87	nop
	88	nop
	89	nop
	8a	computed call J        [5]
	8f	ret

	function(D, 0x90, 0xbf)
	90	nop
	91	nop
	96	conditional jump QQ    [2]
	98	unconditional jump PP  [2]
	9a	QQ nop
	9b	nop
	9c	unconditional jump RR  [2]
	9e	PP nop
	9f	RR nop
	a0	nop
	a1	unconditional call K   [5]
	a6	nop
	a7	nop
	a8	nop
	a9	nop
	aa	nop
	ab	nop
	ac	conditional call L     [5]
	b1	nop
	b2	nop
	b3	computed jump SS       [2]
	b5	nop
	b6	SS nop
	b7	nop
	b8	nop
	b9	nop
	ba	computed call M        [5]
	bf	ret
	
	function(E, 0x130, 0x131)
	function(F, 0x160, 0x161)
	function(G, 0x190, 0x191)
	function(H, 0x230, 0x231)
	function(I, 0x260, 0x261)
	function(J, 0x290, 0x291)
	function(K, 0x330, 0x331)
	function(L, 0x360, 0x361)
	function(M, 0x390, 0x391)
	
	pointer(0x5000, 0x60)
	pointer(0x5004, 0x190)
	pointer(0x5008, 0x330)
	pointer(0x500c, 0x5000)
	
	struct(MyStruct, 0x5020) {
		float
		pointer(0x5024, 0x90)
		??
		??
		??
		??
	}
	struct(AnotherStruct, 0x5030) {
		float
		pointer(0x5034, 0x5004)
		??
		??
		??
		??
	}
	struct(Struct2, 0x5040) {
		float
		pointer(0x5044, 0x5008)
		pointer(0x5048, 0x230)
	}

	indirectRef(0x290, 0x5034)
	indirectRef(0x390, 0x5040)
	
	*/

	private void setupProgram() throws Exception {

		dataConverter = DataConverter.getInstance(getProgram().getMemory().isBigEndian());

		createMemory(".text", "0x0", 0x1000);
		createMemory(".data", "0x5000", 0x1000);

		createFunction("A", 0x0, 0x2f);
		createFunction("B", 0x30, 0x5f);
		createFunction("C", 0x60, 0x8f);
		createFunction("D", 0x90, 0xbf);
		createFunction("E", 0x130, 0x131);
		createFunction("F", 0x160, 0x161);
		createFunction("G", 0x190, 0x191);
		createFunction("H", 0x230, 0x231);
		createFunction("I", 0x260, 0x261);
		createFunction("J", 0x290, 0x291);
		createFunction("K", 0x330, 0x331);
		createFunction("L", 0x360, 0x361);
		createFunction("M", 0x390, 0x391);
		createPointer(0x5000, 0x60);
		createPointer(0x5004, 0x190);
		createPointer(0x5008, 0x330);
		createPointer(0x500c, 0x5000);
		createStructureWithPointer("MyStruct", 0x5020, 0x90);
		createStructureWithPointer("AnotherStruct", 0x5030, 0x5004);
		createStructureWith2Pointers("Struct2", 0x5040, 0x5008, 0x230);

		// Setup flows in Function A
		conditionalJump(0x06, 0x0a);
		unconditionalJump(0x08, 0x0e);
		unconditionalJump(0x0c, 0x0f);
		unconditionalCall(0x11, 0x30); // Unconditional call to B
		conditionalCall(0x1c, 0x60);   // Conditional call to C
		computedJump(0x23, 0x26);      // Computed jump
		computedCall(0x28, 0x90);      // Computed call to D
		conditionalJump(0x2d, 0x26);

		// Setup flows in Function B
		conditionalJump(0x36, 0x3a);
		unconditionalJump(0x38, 0x3e);
		unconditionalJump(0x3c, 0x3f);
		unconditionalCall(0x41, 0x130); // Unconditional call to E
		conditionalCall(0x4c, 0x160);   // Conditional call to F
		computedJump(0x51, 0x54);       // Computed jump
		computedCall(0x55, 0x190);      // Computed call to G
		conditionalCall(0x5a, 0x0);     // Conditional call to A

		// Setup flows in Function C
		conditionalJump(0x66, 0x6a);
		unconditionalJump(0x68, 0x6e);
		unconditionalJump(0x6c, 0x6f);
		unconditionalCall(0x71, 0x230); // Unconditional call to H
		conditionalCall(0x7c, 0x260);   // Conditional call to I
		computedJump(0x83, 0x86);       // Computed jump
		computedCall(0x8a, 0x290);      // Computed call to J

		// Setup flows in Function D
		conditionalJump(0x96, 0x9a);
		unconditionalJump(0x98, 0x9e);
		unconditionalJump(0x9c, 0x9f);
		unconditionalCall(0xa1, 0x330); // Unconditional call to K
		conditionalCall(0xac, 0x360);   // Conditional call to L
		computedJump(0xb3, 0xb6);       // Computed jump
		computedCall(0xba, 0x390);      // Computed call to M

		createMemoryReference("0x290", "0x5034", RefType.INDIRECTION, SourceType.ANALYSIS, 0);
		createMemoryReference("0x390", "0x5040", RefType.INDIRECTION, SourceType.ANALYSIS, 0);

	}

	private int unconditionalCall(int from, int to) throws Exception {
		int thisInstructionsSize = 5;

		String fromString = "0x" + Integer.toHexString(from);
		String toString = "0x" + Integer.toHexString(to);
		String endString = "0x" + Integer.toHexString(from + thisInstructionsSize - 1);

		int distance = to - from - thisInstructionsSize;

		byte[] bytes = new byte[thisInstructionsSize];
		bytes[0] = (byte) 0xe8; // Unconditional Call.
		dataConverter.getBytes(distance, bytes, 1);
		clearCodeUnits(fromString, endString, false);
		setBytes(fromString, bytes, true);
		createMemoryReference(fromString, toString, RefType.UNCONDITIONAL_CALL,
			SourceType.ANALYSIS, 0);

		return thisInstructionsSize; // instruction size in bytes.
	}

	private int conditionalCall(int from, int to) throws Exception {
		int thisInstructionsSize = 5;

		String fromString = "0x" + Integer.toHexString(from);
		String toString = "0x" + Integer.toHexString(to);
		String endString = "0x" + Integer.toHexString(from + thisInstructionsSize - 1);

		int distance = to - from - thisInstructionsSize;

		byte[] bytes = new byte[thisInstructionsSize];
		bytes[0] = (byte) 0xe8; // Unconditional Call. (and just force conditional call ref type.)
		dataConverter.getBytes(distance, bytes, 1);
		clearCodeUnits(fromString, endString, false);
		setBytes(fromString, bytes, true);
		createMemoryReference(fromString, toString, RefType.CONDITIONAL_CALL, SourceType.ANALYSIS,
			0);

		return thisInstructionsSize; // instruction size in bytes.
	}

	private int computedCall(int from, int to) throws Exception {
		int thisInstructionsSize = 5;

		String fromString = "0x" + Integer.toHexString(from);
		String toString = "0x" + Integer.toHexString(to);
		String endString = "0x" + Integer.toHexString(from + thisInstructionsSize - 1);

		int distance = to - from - thisInstructionsSize;

		byte[] bytes = new byte[thisInstructionsSize];
		bytes[0] = (byte) 0xe8; // Unconditional Call. (and just force computed call ref type.)
		dataConverter.getBytes(distance, bytes, 1);
		clearCodeUnits(fromString, endString, false);
		setBytes(fromString, bytes, true);
		createMemoryReference(fromString, toString, RefType.COMPUTED_CALL, SourceType.ANALYSIS, 0);

		return thisInstructionsSize; // instruction size in bytes.
	}

	private int conditionalJump(int from, int to) throws Exception {
		int thisInstructionsSize = 2;

		String fromString = "0x" + Integer.toHexString(from);
		String toString = "0x" + Integer.toHexString(to);
		String endString = "0x" + Integer.toHexString(from + thisInstructionsSize - 1);

		int distance = to - from - thisInstructionsSize;

		byte[] bytes = new byte[thisInstructionsSize];
		bytes[0] = (byte) 0x74; // Conditional Jump.(jump short if equal)
		bytes[1] = (byte) distance;
		clearCodeUnits(fromString, endString, false);
		setBytes(fromString, bytes, true);
		createMemoryReference(fromString, toString, RefType.CONDITIONAL_JUMP, SourceType.ANALYSIS,
			0);

		return thisInstructionsSize; // instruction size in bytes.
	}

	private int unconditionalJump(int from, int to) throws Exception {
		int thisInstructionsSize = 2;

		String fromString = "0x" + Integer.toHexString(from);
		String toString = "0x" + Integer.toHexString(to);
		String endString = "0x" + Integer.toHexString(from + thisInstructionsSize - 1);

		int distance = to - from - thisInstructionsSize;

		byte[] bytes = new byte[thisInstructionsSize];
		bytes[0] = (byte) 0xeb; // Unconditional Jump.
		bytes[1] = (byte) distance;
		clearCodeUnits(fromString, endString, false);
		setBytes(fromString, bytes, true);
		createMemoryReference(fromString, toString, RefType.UNCONDITIONAL_JUMP,
			SourceType.ANALYSIS, 0);

		return thisInstructionsSize; // instruction size in bytes.
	}

	private int computedJump(int from, int to) throws Exception {
		int thisInstructionsSize = 2;

		String fromString = "0x" + Integer.toHexString(from);
		String toString = "0x" + Integer.toHexString(to);
		String endString = "0x" + Integer.toHexString(from + thisInstructionsSize - 1);

		int distance = to - from - thisInstructionsSize;

		byte[] bytes = new byte[thisInstructionsSize];
		bytes[0] = (byte) 0xeb; // Unconditional Jump. (and just force computed jump ref type.)
		bytes[1] = (byte) distance;
		clearCodeUnits(fromString, endString, false);
		setBytes(fromString, bytes, true);
		createMemoryReference(fromString, toString, RefType.COMPUTED_JUMP, SourceType.ANALYSIS, 0);

		return thisInstructionsSize; // instruction size in bytes.
	}

	private void setDefaultFunctionBytes(int start, int end) throws Exception {
		int numNoOpBytes = end - start;
		// Initialize the function to no-ops and a return.
		byte[] bytes = new byte[end - start];
		for (int i = 0; i < numNoOpBytes; i++) {
			bytes[i] = (byte) 0x90; // no-op.
		}
		setBytes("0x" + Integer.toHexString(start), bytes);
		setBytes("0x" + Integer.toHexString(end), "c3"); // return.
	}

	private void createFunction(String name, int start, int end) throws Exception {
		int size = end - start + 1;
		setDefaultFunctionBytes(start, end);
		createEmptyFunction(name, "0x" + Integer.toHexString(start), size, DataType.DEFAULT);
		disassemble(new AddressSet(addr(start), addr(end)));
	}

	private int createPointer(int from, int to) throws Exception {
		int thisPointerSize = 4;

		byte[] bytes = new byte[thisPointerSize];
		dataConverter.getBytes(to, bytes);

		String fromString = "0x" + Integer.toHexString(from);
		String endString = "0x" + Integer.toHexString(from + thisPointerSize - 1);

		clearCodeUnits(fromString, endString, false);
		setBytes(fromString, bytes, false);
		startTransaction();
		Listing listing = getProgram().getListing();
		listing.createData(addr(from), new Pointer32DataType());
		endTransaction();

		return thisPointerSize; // pointer size in bytes.
	}

	private int createStructureWithPointer(String name, int startOfStruct, int to) throws Exception {
		int thisStructureSize = 12;
		int thisPointerSize = 4;
		int pointerOffset = 4;

		byte[] bytes = new byte[thisPointerSize];
		dataConverter.getBytes(to, bytes);

		String structureStart = "0x" + Integer.toHexString(startOfStruct);
		String pointerStart = "0x" + Integer.toHexString(startOfStruct + pointerOffset);
		String structureEnd = "0x" + Integer.toHexString(startOfStruct + thisStructureSize - 1);
		String toAddress = "0x" + Integer.toHexString(to);

		clearCodeUnits(structureStart, structureEnd, false);
		setBytes(pointerStart, bytes, false);
		startTransaction();
		ProgramDB program = getProgram();
		Listing listing = program.getListing();
		Structure struct = new StructureDataType(name, thisStructureSize, program.getDataTypeManager());
		struct.replaceAtOffset(0, new FloatDataType(), 4, null, null);
		struct.replaceAtOffset(pointerOffset, new Pointer32DataType(), 4, null, null);
		listing.createData(addr(startOfStruct), struct);
		createMemoryReference(pointerStart, toAddress, RefType.DATA, SourceType.ANALYSIS, 0);
		endTransaction();

		return thisPointerSize; // pointer size in bytes.
	}

	private int createStructureWith2Pointers(String name, int startOfStruct, int to, int secondTo)
			throws Exception {
		int thisStructureSize = 12;
		int pointerSize = 4;
		int pointerOffset = 4;

		byte[] bytes = new byte[pointerSize];
		dataConverter.getBytes(to, bytes);

		String structureStart = "0x" + Integer.toHexString(startOfStruct);
		String pointerStart = "0x" + Integer.toHexString(startOfStruct + pointerOffset);
		String pointer2Start =
			"0x" + Integer.toHexString(startOfStruct + pointerOffset + pointerSize);
		String structureEnd = "0x" + Integer.toHexString(startOfStruct + thisStructureSize - 1);
		String toAddress = "0x" + Integer.toHexString(to);
		String toAddress2 = "0x" + Integer.toHexString(secondTo);

		clearCodeUnits(structureStart, structureEnd, false);
		setBytes(pointerStart, bytes, false);
		dataConverter.getBytes(secondTo, bytes);
		setBytes(pointerStart + pointerSize, bytes, false);
		startTransaction();
		ProgramDB program = getProgram();
		Listing listing = program.getListing();
		Structure struct = new StructureDataType(name, thisStructureSize, program.getDataTypeManager());
		struct.replaceAtOffset(0, new FloatDataType(), 4, null, null);
		struct.replaceAtOffset(pointerOffset, new Pointer32DataType(), 4, null, null);
		struct.replaceAtOffset(pointerOffset + pointerSize, new Pointer32DataType(), 4, null, null);
		listing.createData(addr(startOfStruct), struct);
		createMemoryReference(pointerStart, toAddress, RefType.DATA, SourceType.ANALYSIS, 0);
		createMemoryReference(pointer2Start, toAddress2, RefType.DATA, SourceType.ANALYSIS, 0);
		endTransaction();

		return pointerSize; // pointer size in bytes.
	}

	Address addr(int addr) {
		return addr("0x" + Integer.toHexString(addr));
	}
}
