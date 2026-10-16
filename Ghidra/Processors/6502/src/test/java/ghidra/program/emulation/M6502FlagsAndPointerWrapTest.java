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
package ghidra.program.emulation;

import java.util.*;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.AbstractEmulationEquivalenceTest;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;

/**
 * Regression guards for 6502 semantics that were previously wrong: ADC losing a carry-out that
 * arises solely from the carry-in, ADC setting V to the unsigned carry rather than signed
 * overflow, SBC reporting C with inverted polarity, and the (zp,X) / (zp),Y pointer fetch not
 * wrapping within zero page when the pointer sits at $FF. The expected values match the
 * hardware-derived SingleStepTests/65x02 suite.
 */
public class M6502FlagsAndPointerWrapTest extends AbstractEmulationEquivalenceTest {
	static final LanguageID LANG_ID_6502 = new LanguageID("6502:LE:16:default");

	static SleighLanguage M6502;

	@Before
	public void setup6502() throws Exception {
		if (M6502 == null) {
			M6502 = (SleighLanguage) DefaultLanguageService.getLanguageService()
					.getLanguage(LANG_ID_6502);
		}
	}

	@Override
	protected long getEntryOffset() {
		return 0x0200; // 16-bit address space; keep clear of zero page and the stack
	}

	/**
	 * Assemble {@code lines} at the entry, execute all of them, and assert {@code regs}. PC is
	 * asserted automatically as the address following the last assembled instruction.
	 */
	private void run(List<String> lines, Map<String, String> regs) throws Exception {
		Map<String, String> expected = new HashMap<>(regs);
		doTestEquiv(M6502, Map.of(), buf -> {
			for (String line : lines) {
				buf.assemble(line);
			}
			expected.put("PC", Long.toHexString(buf.getNext().getOffset()));
		}, lines.size(), expected);
	}

	/** $FF + $00 + C=1 must carry out, even though the carry arises only from the carry-in. */
	@Test
	public void testAdcCarryOutFromCarryInOnly() throws Exception {
		run(List.of("LDA #0xff", "SEC", "ADC #0x00"),
			Map.of("A", "0", "C", "1", "Z", "1", "N", "0", "V", "0"));
	}

	/** $50 + $50 overflows the signed byte range: V=1 while C=0. */
	@Test
	public void testAdcSignedOverflowIsNotCarry() throws Exception {
		run(List.of("LDA #0x50", "CLC", "ADC #0x50"),
			Map.of("A", "a0", "C", "0", "Z", "0", "N", "1", "V", "1"));
	}

	/** SBC leaves C=1 when no borrow occurred. */
	@Test
	public void testSbcCarrySetWhenNoBorrow() throws Exception {
		run(List.of("LDA #0x05", "SEC", "SBC #0x03"),
			Map.of("A", "2", "C", "1", "Z", "0", "N", "0", "V", "0"));
	}

	/** SBC clears C when a borrow occurred. */
	@Test
	public void testSbcCarryClearOnBorrow() throws Exception {
		run(List.of("LDA #0x03", "SEC", "SBC #0x05"),
			Map.of("A", "fe", "C", "0", "Z", "0", "N", "1", "V", "0"));
	}

	/**
	 * Seeds a pointer at $FF whose high byte must come from $00 (zero-page wrap), never from
	 * $0100. $00=$12 and $0100=$56 make the two candidate targets ($1234 vs $5634)
	 * distinguishable; only the correct one holds $AA.
	 */
	private static final List<String> SEED_WRAPPED_POINTER = List.of(
		"LDA #0x34", "STA 0xff",
		"LDA #0x12", "STA 0x00",
		"LDA #0x56", "STA 0x0100",
		"LDA #0xaa", "STA 0x1234");

	private static List<String> withSeed(String... lines) {
		List<String> all = new ArrayList<>(SEED_WRAPPED_POINTER);
		all.addAll(List.of(lines));
		return all;
	}

	@Test
	public void testIndirectYPointerWrapsWithinZeroPage() throws Exception {
		run(withSeed("LDY #0x00", "LDA (0xff),Y"),
			Map.of("A", "aa", "Y", "0", "Z", "0", "N", "1"));
	}

	@Test
	public void testIndexedIndirectXPointerWrapsWithinZeroPage() throws Exception {
		run(withSeed("LDX #0x01", "LDA (0xfe,X)"),
			Map.of("A", "aa", "X", "1", "Z", "0", "N", "1"));
	}
}
