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
package ghidra.app.plugin.core.decompile;

import static org.junit.Assert.*;

import java.math.BigInteger;

import org.apache.commons.lang3.ArrayUtils;
import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.core.analysis.*;
import ghidra.framework.cmd.Command;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.program.util.SymbolicPropogator.Value;
import ghidra.test.TestEnv;
import ghidra.util.TaskUtilities;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;
import junit.framework.AssertionFailedError;

/**
 * Test of DecompilerSwitchAnalyzer
 */
public class DecompilerSwitchAnalyzerTest extends AbstractGenericTest {

	private ProgramBuilder builder;
	private Program program;
	
	private DecompilerSwitchAnalyzer analyzer;

	public DecompilerSwitchAnalyzerTest() {
		super();
	}

	protected void setAnalysisOptions(String optionName) {
		int txId = program.startTransaction("Analyze");
		Options analysisOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);
		analysisOptions.setBoolean(optionName, false);
		program.endTransaction(txId, true);
	}
	
	@Test
	public void testDefaultSwitchLabelAndFlow() throws Exception {

		builder = new ProgramBuilder("SwitchDefaultTest", "x86:LE:64:default", "gcc", null);

		// 
		//		void main(undefined4 param_1)
		//
		//		{
		//		  switch(param_1) {
		//		  case 0:
		//		    puts("case 0");
		//		    break;
		//		  case 1:
		//		    puts("case 1");
		//		    break;
		//		  case 2:
		//		    puts("case 2");
		//		    break;
		//		  case 3:
		//		    puts("case 3");
		//		    break;
		//		  case 4:
		//		    puts("case 4");
		//		    break;
		//		  case 5:
		//		    puts("case 5");
		//		    break;
		//		  case 6:
		//		    puts("case 6");
		//		    break;
		//		  case 7:
		//		    puts("case 7");
		//		    break;
		//		  case 8:
		//		    puts("case 8");
		//		    break;
		//		  case 9:
		//		    puts("case 9");
		//		    break;
		//		  default:
		//		    puts("default");
		//		  }
		//		                    /* WARNING: Subroutine does not return */
		//		  exit(0);
		//		}
		
		builder.setBytes("0x101169",
			"f30f1efa554889" + 
			"e54883ec10897dfc488975f0837dfc09" + 
			"0f87d70000008b45fc488d1485000000" + 
			"00488d05bc0e00008b04024898488d15" + 
			"b00e00004801d03effe0488d05530e00" + 
			"004889c7e8a7feffffe9ae000000488d" + 
			"05460e00004889c7e893feffffe99a00" + 
			"0000488d05390e00004889c7e87ffeff" + 
			"ffe986000000488d052c0e00004889c7" + 
			"e86bfeffffeb75488d05220e00004889" + 
			"c7e85afeffffeb64488d05180e000048" + 
			"89c7e849feffffeb53488d050e0e0000" + 
			"4889c7e838feffffeb42488d05040e00" + 
			"004889c7e827feffffeb31488d05fa0d" + 
			"00004889c7e816feffffeb20488d05f0" + 
			"0d00004889c7e805feffffeb0f488d05" + 
			"e60d00004889c7e8f4fdffffbf000000" + 
			"00e8fafdffff");

		// switch table
		builder.setBytes("0x102054",
			"56f1ffff6af1ffff7ef1ffff" + 
			"92f1ffffa3f1ffffb4f1ffffc5f1ffff" + 
			"d6f1ffffe7f1fffff8f1ffff011b033b");

		builder.disassemble("0x101169", 64);
		
		builder.createFunction("0x101169");

		analyzer = new DecompilerSwitchAnalyzer();

		program = builder.getProgram();
		program.startTransaction("Test");

		Address codeStart = addr("0x101169");
		Listing listing = program.getListing();
		assertNotNull("Bad instruction disassembly", listing.getInstructionAt(codeStart));

		AddressSet addressSet = new AddressSet(codeStart, codeStart.add(0x200));
		analyze(addressSet);
		
		Symbol primarySymbol = program.getSymbolTable().getPrimarySymbol(addr("0x0010125d"));
		assertEquals("Default label set", primarySymbol.getName(), "default");
		assertEquals("Switch space set", primarySymbol.getParentNamespace().getName(), "switchD_001011a7");
		
		primarySymbol = program.getSymbolTable().getPrimarySymbol(addr("0x0010124c"));
		assertEquals("Case label set", primarySymbol.getName(), "caseD_9");
		assertEquals("Switch space set", primarySymbol.getParentNamespace().getName(), "switchD_001011a7");

		Instruction instr = listing.getInstructionAt(addr("0x001011a7"));
		assertNoOperandReference(0, instr);
		assertNoOperandReference(1, instr);
		assertNumMnemonicReferences(instr, 10);
		assertMnemonicReferenceTo(instr, addr("0x001011aa"));
		assertMnemonicReferenceTo(instr, addr("0x001011be"));
		assertMnemonicReferenceTo(instr, addr("0x001011d2"));
		assertMnemonicReferenceTo(instr, addr("0x001011e6"));
		assertMnemonicReferenceTo(instr, addr("0x001011f7"));
		assertMnemonicReferenceTo(instr, addr("0x00101208"));
		assertMnemonicReferenceTo(instr, addr("0x00101219"));
		assertMnemonicReferenceTo(instr, addr("0x0010122a"));
		assertMnemonicReferenceTo(instr, addr("0x0010123b"));
		assertMnemonicReferenceTo(instr, addr("0x0010124c"));
		
	}
	
	private void assertNoOperandReference(int opIndex, Instruction instr) {
		Reference[] refs = instr.getOperandReferences(opIndex);
		assertEquals("No reference on operand " + opIndex, 0, refs.length);
	}
	
	private void assertNumOperandReferences(int opIndex, Instruction instr, int num) {
		Reference[] refs = instr.getOperandReferences(opIndex);
		assertEquals("Operand " + opIndex + " num refs", num, refs.length);
	}
	
	private void assertNumMnemonicReferences(Instruction instr, int num) {
		Reference[] refs = instr.getMnemonicReferences();
		assertEquals("Mnemonic num refs", num, refs.length);
	}

	private void assertMnemonicReferenceTo(Instruction instr, Address to) {
		Reference[] refs = instr.getMnemonicReferences();
		boolean found = false;
		for (Reference reference : refs) {
			if (reference.getToAddress().equals(to)) {
				found = true;
				break;
			}
		}
		assertTrue("Missing Mnemonic Reference " + to + " on " + instr, found);
	}
	
	private void assertOperandReferenceTo(int opIndex, Instruction instr, Address to) {
		Reference[] refs = instr.getOperandReferences(opIndex);
		boolean found = false;
		for (Reference reference : refs) {
			if (reference.getToAddress().equals(to)) {
				found = true;
				break;
			}
		}
		assertTrue("Missing Reference " + to + " on " + instr, found);
	}

	private void analyze(AddressSet addrs) throws Exception {
		analyzer.added(program, addrs, TaskMonitor.DUMMY, null);
	}

	private Address addr(String address) {
		return builder.addr(address);
	}
}
