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
package ghidra.app.plugin.assembler.sleigh;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedConstructor;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;

public class x86AssemblyTest extends AbstractAssemblyTest {
	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("x86:LE:64:default");
	}

	@Test
	public void testReasonableErrorMessageLength() throws AssemblySemanticException {
		Assembler assembler = Assemblers.getAssembler(lang);
		Address addr = lang.getDefaultSpace().getAddress(DEFAULT_ADDR);
		try {
			assembler.assembleLine(addr, "UNLIKELY qword ptr [RAX],RBX");
			fail(); // The exception must be thrown
		}
		catch (AssemblySyntaxException e) {
			Msg.info(this, "Got expected syntax error: " + e);
			assertTrue(e.getMessage().length() < 1000);
		}
	}

	@Test
	public void testAssemble_ADD_m0x12_RAXm_RBX() {
		// Again, a little odd. Imm8 does not have the I+R form.
		try {
			assertOneCompatRestExact("ADD qword ptr [RAX + 0x12],RBX", "48:01:98:12:00:00:00");
		}
		catch (DisassemblyMismatchException e) {
			Msg.warn(this, "Swapping to test case with [I+R] form");
			assertOneCompatRestExact("ADD qword ptr [0x12 + RAX],RBX", "48:01:98:12:00:00:00");
		}
	}

	@Test
	public void testAssemble_ADD_m0x1234_RAXm_RBX() {
		// Once the operand order is changed back, the catch case will not be necessary
		try {
			assertOneCompatRestExact("ADD qword ptr [RAX + 0x1234],RBX", "48:01:98:34:12:00:00");
		}
		catch (DisassemblyMismatchException e) {
			Msg.warn(this, "Swapping to test case with [I+R] form");
			assertOneCompatRestExact("ADD qword ptr [0x1234 + RAX],RBX", "48:01:98:34:12:00:00");
		}
	}

	//@Test
	//@Ignore("Can no longer isolate Imm8 case as [R+I]")
	public void testAssemble_ADD_mRAX_0x1234m_RBX() {
		// The spec is a little odd: only imm8 has R+I form. Others are I+R.
		assertAllSemanticErrors("ADD qword ptr [RAX+0x1234],RBX");
	}

	@Test
	public void testAssemble_ADD_mRAX_0x12m_RBX() {
		assertOneCompatRestExact("ADD qword ptr [RAX + 0x12],RBX", "48:01:58:12");
	}

	@Test
	public void testAssemble_ADD_mRAX_127m_EBX() {
		assertOneCompatRestExact("ADD dword ptr [RAX+127], EBX", "01:58:7f",
			"ADD dword ptr [RAX + 0x7f],EBX");
	}

	@Test
	public void testAssemble_ADD_mRAX_127m_RBX() {
		assertOneCompatRestExact("ADD qword ptr [RAX+127], RBX", "48:01:58:7f",
			"ADD qword ptr [RAX + 0x7f],RBX");
	}

	//@Test
	//@Ignore("Can no longer isolate Imm8 case as [R+I]")
	public void testAssemble_ADD_mRAX_128m_RBX() {
		assertAllSemanticErrors("ADD qword ptr [RAX+128],RBX");
	}

	@Test
	public void testAssemble_ADD_mRAX_n0x12m_RBX() {
		assertOneCompatRestExact("ADD qword ptr [RAX + -0x12],RBX", "48:01:58:ee");
	}

	@Test
	public void testAssemble_ADD_mRAX_nx0x12m_RBX() {
		assertAllSyntaxErrors("ADD [RAX-0x12],RBX");
	}

	@Test
	public void testAssemble_ADD_mRAXm_RBX() {
		assertOneCompatRestExact("ADD qword ptr [RAX],RBX", "48:01:18");
	}

	@Test
	public void testAssemble_ADD_mRBXm_BL() {
		assertOneCompatRestExact("ADD byte ptr [RBX],BL", "48:00:1b");
	}

	@Test
	public void testAssemble_ADD_mRDX_RSI__0x04m_EBX() {
		assertOneCompatRestExact("ADD dword ptr [RDX+RSI*4], EBX", "01:1c:b2",
			"ADD dword ptr [RDX + RSI*0x4],EBX");
	}

	@Test
	public void testAssemble_ADD_RAX_mRDI_RDX__0x08m() {
		assertOneCompatRestExact("ADD RAX, qword ptr [RDI+RDX*8]", "48:03:04:d7",
			"ADD RAX,qword ptr [RDI + RDX*0x8]");
	}

	@Test
	public void testAssemble_ADD_RSP_0x8() {
		assertOneCompatRestExact("ADD RSP,0x8", "48:83:c4:08");
	}

	@Test
	public void testAssemble_AND_EAX_0x80808080() {
		assertOneCompatRestExact("AND EAX,0x80808080", "25:80:80:80:80");
	}

	@Test
	public void testAssemble_AND_RSP_n0x10() {
		assertOneCompatRestExact("AND RSP,-0x10", "48:83:e4:f0");
	}

	@Test
	public void testAssemble_CMP_byte_ptr_m0x006dbeefm_0() {
		assertOneCompatRestExact("CMP byte ptr [0x006dbeef],0", "80:3d:e8:be:6d:c0:00",
			"CMP byte ptr [0x006dbeef],0x0");
	}

	@Test
	public void testAssemble_CMP_byte_ptr_mRBPm_0x0() {
		assertOneCompatRestExact("CMP byte ptr [RBP],0x0", "80:7d:00:00");
	}

	@Test
	public void testAssemble_JG_0x00400047() {
		assertOneCompatRestExact("JG 0x00400047", "7f:45", 0x00400000);
	}

	@Test
	public void testAssemble_JMP_0x34() {
		assertOneCompatRestExact("JMP 0x34", "e9:2f:00:00:c0", "JMP 0x00000034");
	}

	@Test
	public void testAssemble_MOV_RAX_FSm0x28m() {
		// 1823[1834[3232[1141[970[944,928[845]]],774]]]
		assertOneCompatRestExact("MOV RAX,qword ptr FS:[0x28]", "64:48:8b:04:25:28:00:00:00");
	}

	@Test
	public void testAssemble_MOV_RBX_mRSP_0x8m() {
		assertOneCompatRestExact("MOV RBX,qword ptr [RSP + 0x8]", "48:8b:5c:24:08");
	}

	@Test
	public void testAssemble_MOV_RCX_mR12m() {
		assertOneCompatRestExact("MOV RCX,qword ptr [R12]", "49:8b:0c:24");
	}

	@Test
	public void testAssemble_MOV_mRBXm_R14W() {
		/*
		 * Constructor Line #'s: instruction(1825), instruction(1835), MOV(3221), rm16(1128),
		 * Mem(969), segWide(939), addr64(918), Rmr64(791), Reg16(771)
		 */
		assertOneCompatRestExact("MOV word ptr [RBX],R14W", "66:44:89:33");
	}

	@Test
	public void testAssemble_MOV_mRSP_n0x10m_RBX() {
		assertOneCompatRestExact("MOV qword ptr [RSP + -0x10],RBX", "48:89:5c:24:f0");
	}

	@Test
	public void testAssemble_NOP() {
		assertOneCompatRestExact("NOP", "90");
	}

	@Test
	public void testAssemble_NOP_CS_mRAX_RAX__0x1m() {
		assertOneCompatRestExact("NOP word ptr CS:[RAX + RAX*0x1]",
			"66:2e:0f:1f:84:00:00:00:00:00");
	}

	@Test
	public void testAssemble_PUSH_RAX() {
		assertOneCompatRestExact("PUSH RAX", "50");
	}

	public void testAssemble_POP_RBX() {
		assertOneCompatRestExact("POP RBX", "5b");
	}

	@Test
	public void testAssembly_SAR_RBX_1() {
		assertOneCompatRestExact("SAR RBX,1", "48:d1:fb", "SAR RBX,1", "SAR RBX,0x1");
	}

	@Test
	public void testAssembly_SAR_DL_1() {
		assertOneCompatRestExact("SAR DL,1", "d0:fa", "SAR DL,1", "SAR DL,0x1");
	}

	@Test
	public void testAssemble_SCASB_RDI() {
		assertOneCompatRestExact("SCASB RDI", "ae");
	}

	@Test
	public void testAssemble_SCASB_REPE_RDI() {
		assertOneCompatRestExact("SCASB.REPE RDI", "f3:ae");
	}

	@Test
	public void testAssemble_SCASB_REPNE_RDI() {
		assertOneCompatRestExact("SCASB.REPNE RDI", "f2:ae");
	}

	@Test
	public void testAssembly_SHR_R13D_1() {
		assertOneCompatRestExact("SHR R13D,1", "41:d1:ed", "SHR R13D,1", "SHR R13D,0x1");
	}

	@Test
	public void testAssemble_SUB_RSP_0x8() {
		assertOneCompatRestExact("SUB RSP,0x8", "48:83:ec:08");
	}

	@Test
	public void testAssemble_CVTSI2SD_XMM12_EDX() {
		assertOneCompatRestExact("CVTSI2SD XMM12,EDX", "f2:44:0f:2a:e2");
	}

	@Test
	public void testAssembly_CALL_0x0041bb80() {
		assertOneCompatRestExact("CALL 0x0041bb80", "e8:5f:ba:01:00", 0x0040011c);
	}

	@Test
	public void testAssembly_AND_mRBP_n0x8m_0xffff0000() {
		assertOneCompatRestExact("AND qword ptr [RBP + -0x8],-0x10000",
			"48:81:65:f8:00:00:ff:ff");
	}

	//@Ignore("This is a demonstration of an issue with signedness and scalar print pieces.")
	//@Test
	public void testAssembly_AND_mRBP_n0x8m_0x80()
			throws AssemblySyntaxException, AddressOutOfBoundsException, InsufficientBytesException,
			UnknownInstructionException, AddressOverflowException, MemoryAccessException {
		Assembler assembler = Assemblers.getAssembler(lang);
		Address at = lang.getDefaultSpace().getAddress(0x00400000);
		for (AssemblyResolution rr : assembler.resolveLine(at, "AND [RBP + -0x8],-0x80")) {
			if (rr.isError()) {
				//AssemblyResolvedError err = (AssemblyResolvedError) rr;
				//System.out.println(err.getError());
			}
			else {
				AssemblyResolvedConstructor rc = (AssemblyResolvedConstructor) rr;
				System.out.print(rc.getInstruction().fillMask());
				System.out.print("    ");
				System.out.println(disassemble(0x00400000, rc.getInstruction().getVals(),
					assembler.getContextAt(at).getVals()));
			}
		}
	}

	@Test
	public void testSuggest_ADD() {
		assertAllSyntaxErrors("ADD");
		assertAllSyntaxErrors("ADD ");
		assertAllSyntaxErrors("ADD [");
	}
}
