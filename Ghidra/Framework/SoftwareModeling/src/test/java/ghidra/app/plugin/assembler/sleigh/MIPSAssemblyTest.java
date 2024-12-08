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

import java.math.BigInteger;

import org.junit.Test;

import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.RegisterValue;

public class MIPSAssemblyTest extends AbstractAssemblyTest {

	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("MIPS:BE:32:R6");
	}

	@Test
	public void testAssemble_jal_0x00420fa0() {
		assertOneCompatRestExact("jal 0x00420fa0", "0c:10:83:e8", 0x00400d4);
	}

	@Test
	public void testAssembly_restore_0x1b8_ra_s0_s1() {
		RegisterValue ctxVal = new RegisterValue(lang.getContextBaseRegister());
		ctxVal = ctxVal.assign(lang.getRegister("ISA_MODE"), BigInteger.ONE);
		ctxVal = ctxVal.assign(lang.getRegister("PAIR_INSTRUCTION_FLAG"), BigInteger.ZERO);
		ctxVal = ctxVal.assign(lang.getRegister("RELP"), BigInteger.ONE);
		assertOneCompatRestExact("restore 0x1b8,ra,s0-s1", "f0:30:64:77",
			AssemblyPatternBlock.fromRegisterValue(ctxVal).fillMask().toString(), 0x0040000,
			"restore 0x1b8,ra,s0-s1");
	}
}
