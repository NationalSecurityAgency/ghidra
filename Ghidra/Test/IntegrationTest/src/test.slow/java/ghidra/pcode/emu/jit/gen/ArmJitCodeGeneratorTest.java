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
package ghidra.pcode.emu.jit.gen;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.util.Map;

import org.junit.Test;

import ghidra.app.plugin.assembler.AssemblyBuffer;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;

public class ArmJitCodeGeneratorTest extends AbstractJitCodeGeneratorTest {
	protected static final LanguageID ID_ARMv8LE = new LanguageID("ARM:LE:32:v8");

	@Override
	protected LanguageID getLanguageID() {
		return ID_ARMv8LE;
	}

	@Test
	public void testArmThumbFunc() throws Exception {
		AssemblyBuffer asm = createBuffer(getLanguageID(), 0x00400000);

		Language language = asm.getAssembler().getLanguage();
		Register regCtx = language.getContextBaseRegister();
		Register regT = language.getRegister("T");
		RegisterValue rvDefault = new RegisterValue(regCtx,
			asm.getAssembler().getContextAt(asm.getNext()).toBigInteger(regCtx.getNumBytes()));
		RegisterValue rvArm = rvDefault.assign(regT, BigInteger.ZERO);
		RegisterValue rvThumb = rvDefault.assign(regT, BigInteger.ONE);

		AssemblyPatternBlock ctxThumb = AssemblyPatternBlock.fromRegisterValue(rvThumb);

		asm.assemble("mov r1, #456");
		Address addrBlx = asm.getNext();
		asm.assemble("blx 0x0");
		Address addrRet = asm.getNext(); // The address where we expect to return
		asm.assemble("bx lr"); // Follows CALL, so principally, must be here, but not decoded
		Address addrThumb = asm.getNext();
		asm.assemble("add r0, r1", ctxThumb);
		asm.assemble("bx lr", ctxThumb);

		asm.assemble(addrBlx, "blx 0x%s".formatted(addrThumb));

		Translation tr = translateBuffer(asm, asm.getEntry(), Map.of());

		assertEquals(Map.ofEntries(
			tr.entryPrototype(asm.getEntry(), rvArm, 0),
			tr.entryPrototype(addrThumb, rvThumb, 1)),
			tr.passageCls().getBlockEntries());

		/**
		 * The blx will be a direct branch, so that will get executed in the bytecode. However, the
		 * bx lr (from THUMB) will be an indirect jump, causing a passage exit, so we should expect
		 * the return value to be the address immediately after the blx. Of course, that's not all
		 * that convincing.... So, we'll assert that r0 was set, too.
		 */
		assertEquals(addrRet.getOffset(), tr.runClean());
		assertEquals(456, tr.getLongRegVal("r0"));
	}

	@Test
	public void testExitAsThumb() throws Exception {
		Translation tr = translateLang(getLanguageID(), 0x00400000, """
				blx 0x00500000
				""", Map.of());
		Language language = tr.state().getLanguage();
		Register regCtx = language.getContextBaseRegister();
		Register regT = language.getRegister("T");

		tr.runDecodeErr(0x00500000);
		RegisterValue actualCtx = tr.getRegVal(regCtx);
		RegisterValue expectedCtx = actualCtx.assign(regT, BigInteger.ONE);
		assertEquals(expectedCtx, actualCtx);
	}

	@Test
	public void testCtxHazardousFallthrough() throws Exception {
		Translation tr = translateLang(getLanguageID(), 0x00400000, """
				mov r0,#6
				mov r1,#7
				""", Map.ofEntries(
			Map.entry(0x00400000L, """
					setISAMode(1:1);
					emu_exec_decoded();
					""")));

		tr.runClean();
		assertEquals(6, tr.getLongRegVal("r0"));
		// Should not execute second instruction, because of injected ctx change
		assertEquals(0, tr.getLongRegVal("r1"));
	}

	@Test
	public void testCtxMaybeHazardousFallthrough() throws Exception {
		/**
		 * For this test to produce the "MAYBE" case, the multiple paths have to be
		 * <em>internal</em> to an instruction (or inject). All that logic is only applied on an
		 * instruction-by-instruction basis.
		 */
		Translation tr = translateLang(getLanguageID(), 0x00400000, """
				mov r0,#6
				mov r1,#7
				""", Map.ofEntries(
			Map.entry(0x00400000L, """
					if (!ZR) goto <skip>;
					  ISAModeSwitch = 1;
					  setISAMode(ISAModeSwitch);
					<skip>
					emu_exec_decoded();
					""")));

		tr.setLongRegVal("r1", 0); // Reset
		tr.setLongRegVal("ZR", 0);
		// Since ctx wasn't touched at runtime, we fall out of program
		tr.runDecodeErr(0x00400008);
		assertEquals(6, tr.getLongRegVal("r0"));
		assertEquals(7, tr.getLongRegVal("r1"));
		assertEquals(0, tr.getLongRegVal("ISAModeSwitch"));

		tr.setLongRegVal("r1", 0); // Reset
		tr.setLongRegVal("ZR", 1);
		// Hazard causes exit before 2nd instruction
		tr.runClean();
		assertEquals(6, tr.getLongRegVal("r0"));
		assertEquals(0, tr.getLongRegVal("r1"));
		assertEquals(1, tr.getLongRegVal("ISAModeSwitch"));
	}
}
