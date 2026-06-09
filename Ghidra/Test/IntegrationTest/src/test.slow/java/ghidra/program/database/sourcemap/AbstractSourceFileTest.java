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
package ghidra.program.database.sourcemap;

import org.junit.Before;

import generic.test.AbstractGenericTest;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.sourcemap.SourceFileManager;
import ghidra.test.ToyProgramBuilder;

public class AbstractSourceFileTest extends AbstractGenericTest {

	protected Program program;
	protected ToyProgramBuilder builder;
	protected int baseOffset = 0x1001000;
	protected Address baseAddress;
	protected SourceFile source1;
	protected SourceFile source2;
	protected SourceFile source3;
	protected Instruction ret2_1;
	protected Instruction ret2_2;
	protected Instruction ret2_3;
	protected Instruction nop1_1;
	protected Instruction nop1_2;
	protected Instruction nop1_3;
	protected Instruction ret2_4;
	protected Instruction nop1_4;
	protected String path1 = "/test1";
	protected String path2 = "/test2/test2";
	protected String path3 = "/test3/test3/test3";
	protected String path4 = "/test4/test4/test4/test4";
	protected SourceFileManager sourceManager;

	@Before
	public void setUp() throws Exception {
		builder = new ToyProgramBuilder("testprogram", true, false, this);
		int txID = builder.getProgram().startTransaction("create source map test program");
		long currentOffset = baseOffset;
		try {
			builder.createMemory(".text", Integer.toHexString(baseOffset), 64).setExecute(true);
			builder.addBytesReturn(currentOffset);
			currentOffset += 2;
			builder.addBytesNOP(currentOffset++, 1);
			builder.addBytesReturn(currentOffset);
			currentOffset += 2;
			builder.addBytesNOP(currentOffset++, 1);
			builder.addBytesReturn(currentOffset);
			currentOffset += 2;
			builder.addBytesNOP(currentOffset++, 1);
			builder.addBytesReturn(currentOffset);
			currentOffset += 2;
			builder.addBytesNOP(currentOffset++, 1);
			builder.disassemble(Integer.toHexString(baseOffset),
				(int) (currentOffset - baseOffset));
		}
		finally {
			builder.getProgram().endTransaction(txID, true);
		}
		program = builder.getProgram();
		baseAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(baseOffset);
		InstructionIterator instIter = program.getListing().getInstructions(baseAddress, true);
		ret2_1 = instIter.next();
		nop1_1 = instIter.next();
		ret2_2 = instIter.next();
		nop1_2 = instIter.next();
		ret2_3 = instIter.next();
		nop1_3 = instIter.next();
		ret2_4 = instIter.next();
		nop1_4 = instIter.next();
		sourceManager = program.getSourceFileManager();

		source1 = new SourceFile(path1);
		source2 = new SourceFile(path2);
		source3 = new SourceFile(path3);
		//leave path4 as String without a corresponding source file

		txID = program.startTransaction("adding source files");
		try {
			sourceManager.addSourceFile(source1);
			sourceManager.addSourceFile(source2);
			sourceManager.addSourceFile(source3);
		}
		finally {
			program.endTransaction(txID, true);
		}
		builder.dispose();
	}

	protected AddressRange getBody(CodeUnit cu) {
		return new AddressRangeImpl(cu.getMinAddress(), cu.getMaxAddress());
	}

}
