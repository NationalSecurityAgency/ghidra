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
package ghidra.bitpatterns.info;

import static org.junit.Assert.*;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import generic.jar.ResourceFile;
import generic.test.AbstractGenericTest;
import ghidra.framework.Application;

public class InstructionSequenceTest extends AbstractGenericTest {

	private FileBitPatternInfoReader fReader;

	@Before
	public void setUp() throws IOException {
		ResourceFile resourceFile = Application.getModuleDataSubDirectory("BytePatterns", "test");
		fReader = new FileBitPatternInfoReader(resourceFile.getFile(false));
	}

	@Test
	public void basicTest() {
		List<InstructionSequence> instSeqs =
			InstructionSequence.getInstSeqs(fReader, PatternType.FIRST, null);
		assertEquals(instSeqs.size(), 32);
		instSeqs = InstructionSequence.getInstSeqs(fReader, PatternType.PRE, null);
		assertEquals(instSeqs.size(), 30);
		instSeqs = InstructionSequence.getInstSeqs(fReader, PatternType.RETURN, null);
		assertEquals(instSeqs.size(), 34);
	}

	@Test
	public void testFilteredFirstInstructions() {
		ContextRegisterFilter cRegFilter = new ContextRegisterFilter();
		cRegFilter.addRegAndValueToFilter("cReg2", new BigInteger("1"));
		cRegFilter.addRegAndValueToFilter("cReg3", new BigInteger("3"));
		cRegFilter.addRegAndValueToFilter("cReg4", new BigInteger("7"));
		List<InstructionSequence> seqs =
			InstructionSequence.getInstSeqs(fReader, PatternType.FIRST, cRegFilter);
		//should be 4 copies of the same sequence
		assertEquals(4, seqs.size());
		for (InstructionSequence seq : seqs) {
			assertEquals(seq, seqs.get(0));
		}
		InstructionSequence seq = seqs.get(0);
		Integer[] sizes = seq.getSizes();
		assertEquals(0, Integer.compare(1, sizes[0]));
		assertEquals(0, Integer.compare(3, sizes[1]));
		assertEquals(0, Integer.compare(1, sizes[2]));
		assertEquals(0, Integer.compare(4, sizes[3]));

		String completeDis = seq.getCompleteDisassembly(true);
		assertEquals(" PUSH:1(RBP)  MOV:3(RBP,RSP)  PUSH:1(RBX)  SUB:4(RSP,0x38) ", completeDis);

		String partialDis = seq.getDisassembly(2, true);
		assertEquals(" PUSH:1(RBP)  MOV:3(RBP,RSP) ", partialDis);

		String[] instructions = seq.getInstructions();
		assertEquals("PUSH", instructions[0]);
		assertEquals("MOV", instructions[1]);
		assertEquals("PUSH", instructions[2]);
		assertEquals("SUB", instructions[3]);
	}

	@Test
	public void testFilteredPreInstructions() {
		ContextRegisterFilter cRegFilter = new ContextRegisterFilter();
		//no pre-instructions for function at address 0 in test data,
		//should only return data for function at address 8
		cRegFilter.addRegAndValueToFilter("cReg2", new BigInteger("0"));
		cRegFilter.addRegAndValueToFilter("cReg3", new BigInteger("0"));
		cRegFilter.addRegAndValueToFilter("cReg4", new BigInteger("0"));
		List<InstructionSequence> seqs =
			InstructionSequence.getInstSeqs(fReader, PatternType.PRE, cRegFilter);
		//should be 2 copies of the same sequence
		assertEquals(2, seqs.size());
		for (InstructionSequence seq : seqs) {
			assertEquals(seq, seqs.get(0));
		}
		InstructionSequence seq = seqs.get(0);
		Integer[] sizes = seq.getSizes();
		assertEquals(0, Integer.compare(1, sizes[0]));
		assertEquals(0, Integer.compare(1, sizes[1]));
		assertEquals(0, Integer.compare(1, sizes[2]));

		String completeDis = seq.getCompleteDisassembly(false);
		assertEquals(" POP:1(RBX)  LEAVE:1()  RET:1() ", completeDis);

		String partialDis = seq.getDisassembly(2, false);
		assertEquals(" LEAVE:1()  RET:1() ", partialDis);

		String[] instructions = seq.getInstructions();
		assertEquals("RET", instructions[0]);
		assertEquals("LEAVE", instructions[1]);
		assertEquals("POP", instructions[2]);
	}

	@Test
	public void testFilteredReturnInstructions() {
		ContextRegisterFilter cRegFilter = new ContextRegisterFilter();
		//no pre-instructions for function at address 0 in test data,
		//should only return data for function at address 8
		cRegFilter.addRegAndValueToFilter("cReg2", new BigInteger("1"));
		cRegFilter.addRegAndValueToFilter("cReg3", new BigInteger("3"));
		cRegFilter.addRegAndValueToFilter("cReg4", new BigInteger("7"));
		List<InstructionSequence> seqs =
			InstructionSequence.getInstSeqs(fReader, PatternType.RETURN, cRegFilter);
		//function in test data has 2 returns at address f
		//should be six sequences in total
		assertEquals(6, seqs.size());
	}
}
