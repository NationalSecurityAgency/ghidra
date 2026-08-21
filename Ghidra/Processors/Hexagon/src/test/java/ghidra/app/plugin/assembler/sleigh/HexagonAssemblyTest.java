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

public class HexagonAssemblyTest extends AbstractAssemblyTest {

	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("Hexagon:LE:32:default");
	}

	String makeCtx(int packetOffset, long packetBits) {
		RegisterValue ctxVal = new RegisterValue(lang.getContextBaseRegister());
		ctxVal = ctxVal.assign(lang.getRegister("packetOffset"), BigInteger.valueOf(packetOffset));
		ctxVal = ctxVal.assign(lang.getRegister("packetBits"), BigInteger.valueOf(packetBits));
		return AssemblyPatternBlock.fromRegisterValue(ctxVal).fillMask().toString();
	}

	@Test
	public void testAssemble_memb_R0_mR1() {
		assertOneCompatRestExact("memb R0,(R1)", "00:40:01:91", 0x000c0000);
	}

	@Test
	public void testAssemble_jump_if_t_cmp_eq_mR0new_n0_0xc0010() {
		assertOneCompatRestExact("jump.if:t cmp.eq(R0.new,#0x0),0x000c0010", "0b:e0:02:24",
			makeCtx(1, 0x40000000), 0x000c0000,
			"jump.if:t cmp.eq(R0.new,#0x0),0x000c0010");
	}

	@Test
	public void testAssemble_assign_R0_P0() {
		assertOneCompatRestExact("assign R0,P0", "00:40:40:89", 0x000c0000);
	}

	@Test
	public void testAssemble_cmp_gtu_P0_R1_n0x9__jump_if_P0new_t_0xc0010() {
		assertOneCompatRestExact("cmp.gtu P0,R1,#0x9 ; jump.if(P0.new):t 0x000c0010", "0b:69:01:11",
			makeCtx(1, 0x40000000), 0x000c0000,
			"cmp.gtu P0,R1,#0x9 ; jump.if(P0.new):t 0x000c0010");
	}

	@Test
	public void testAssemble_memw_mSP_n0x4_R0new() {
		assertOneCompatRestExact("memw (SP+#0x4),R0.new", "01:d4:bd:a1",
			makeCtx(2, 0x50000000), 0x000c0000,
			"memw (SP+#0x4),R0.new");
	}
}
