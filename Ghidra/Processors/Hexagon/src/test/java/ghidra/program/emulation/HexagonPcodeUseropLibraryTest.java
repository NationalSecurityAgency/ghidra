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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertNotNull;

import java.util.Map;

import org.hamcrest.Matchers;
import org.junit.*;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.*;
import ghidra.program.emulation.HexagonPcodeUseropLibraryFactory.HexagonPcodeUseropLibrary;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;

public class HexagonPcodeUseropLibraryTest extends AbstractEmulationEquivalenceTest {
	static final LanguageID LANGI_ID_HEXAGON = new LanguageID("Hexagon:LE:32:default");

	static SleighLanguage HEXAGON;

	@Before
	public void setupHexagon() throws Exception {
		if (HEXAGON == null) {
			HEXAGON = (SleighLanguage) DefaultLanguageService.getLanguageService()
					.getLanguage(LANGI_ID_HEXAGON);
		}
	}

	@Test
	public void testFoundById() {
		PcodeUseropLibrary<byte[]> lib = PcodeUseropLibraryFactory
				.createUseropLibraryFromId("hexagon", HEXAGON,
					BytesPcodeArithmetic.forLanguage(HEXAGON));
		assertThat(lib, Matchers.instanceOf(HexagonPcodeUseropLibrary.class));
	}

	@Test
	public void testFoundByLang() {
		PcodeUseropLibrary<byte[]> lib = PcodeUseropLibraryFactory
				.createUseropLibraryForLanguage(HEXAGON, BytesPcodeArithmetic.forLanguage(HEXAGON));
		assertNotNull(lib.getUserops().get("dfmpyfix"));
		assertNotNull(lib.getUserops().get("dfmpyhh"));
	}

	@Test
	public void testDfClass() throws Exception {
		doTestEquiv(HEXAGON,
			Map.ofEntries(
				Map.entry("P3", "ffff"), // Kind of hacky, but Pd2 &= result
				Map.entry("R1R0", "3ff0000000000000")),
			buf -> buf.assemble("dfclass P3,R1R0,#0x2"), 1,
			Map.ofEntries(
				Map.entry("P3", "ff"),
				Map.entry("PC", "400004"),
				Map.entry("P0.new", "ff"),
				Map.entry("P1.new", "ff"),
				Map.entry("P2.new", "ff"),
				Map.entry("P3.new", "ff"),
				Map.entry("R1R0", "3ff0000000000000")));
	}

	@Test
	public void testVMux() throws Exception {
		doTestEquiv(HEXAGON,
			Map.ofEntries(
				Map.entry("P0", "96"),
				Map.entry("R1R0", "aaaaaaaaaaaaaaaa"),
				Map.entry("R9R8", "bbbbbbbbbbbbbbbb")),
			buf -> buf.assemble("vmux R1R0,P0,R1R0,R9R8"), 1,
			Map.ofEntries(
				Map.entry("R1R0_", "aabbbbaabbaaaabb"),
				Map.entry("P0", "96"),
				Map.entry("PC", "400004"),
				Map.entry("P0.new", "ff"),
				Map.entry("P1.new", "ff"),
				Map.entry("P2.new", "ff"),
				Map.entry("P3.new", "ff"),
				Map.entry("R1R0", "aaaaaaaaaaaaaaaa"),
				Map.entry("R9R8", "bbbbbbbbbbbbbbbb")));
	}

	static final long DF_ANY = 0x3f80_0000_0000_0000L;
	static final long DF_HEX_NAN = -1L;
	static final long DF_MAX = Double.doubleToRawLongBits(Double.MAX_VALUE);
	static final long DF_MIN = Double.doubleToRawLongBits(Double.MIN_NORMAL);
	static final long DF_NEG_ONE = Double.doubleToRawLongBits(-1.0);
	static final long DF_NEG_ZERO = Double.doubleToRawLongBits(-0.0);
	static final long DF_ONE = Double.doubleToRawLongBits(1.0);
	static final long DF_ONE_HH = 0x3ff0_01ff_8000_0000L;
	static final long DF_QNAN = 0x7ff8_0000_0000_0000L;
	static final long DF_SNAN = 0x7ff7_0000_0000_0000L;
	static final long DF_ZERO = Double.doubleToRawLongBits(0.0);

	protected void runTestDfmpyhh(long accNew, long accInit, long a, long b)
			throws Exception {
		doTestEquiv(HEXAGON,
			Map.ofEntries(
				Map.entry("R1R0", Long.toHexString(accInit)),
				Map.entry("R3R2", Long.toHexString(a)),
				Map.entry("R9R8", Long.toHexString(b))),
			buf -> buf.assemble("dfmpyhh+= R1R0,R3R2,R9R8"), 1,
			Map.ofEntries(
				Map.entry("R1R0_", Long.toHexString(accNew)),
				Map.entry("PC", "400004"),
				Map.entry("P0.new", "ff"),
				Map.entry("P1.new", "ff"),
				Map.entry("P2.new", "ff"),
				Map.entry("P3.new", "ff"),
				Map.entry("R1R0", Long.toHexString(accInit)),
				Map.entry("R3R2", Long.toHexString(a)),
				Map.entry("R9R8", Long.toHexString(b))));
	}

	protected void runTestDfmpylh(long accNew, long accInit, long a, long b)
			throws Exception {
		doTestEquiv(HEXAGON,
			Map.ofEntries(
				Map.entry("R1R0", Long.toHexString(accInit)),
				Map.entry("R3R2", Long.toHexString(a)),
				Map.entry("R9R8", Long.toHexString(b))),
			buf -> buf.assemble("dfmpylh+= R1R0,R3R2,R9R8"), 1,
			Map.ofEntries(
				Map.entry("R1R0_", Long.toHexString(accNew)),
				Map.entry("PC", "400004"),
				Map.entry("P0.new", "ff"),
				Map.entry("P1.new", "ff"),
				Map.entry("P2.new", "ff"),
				Map.entry("P3.new", "ff"),
				Map.entry("R1R0", Long.toHexString(accInit)),
				Map.entry("R3R2", Long.toHexString(a)),
				Map.entry("R9R8", Long.toHexString(b))));
	}

	protected void runTestDfmpyll(long accNew, long accInit, long a, long b)
			throws Exception {
		doTestEquiv(HEXAGON,
			Map.ofEntries(
				Map.entry("R1R0", Long.toHexString(accInit)),
				Map.entry("R3R2", Long.toHexString(a)),
				Map.entry("R9R8", Long.toHexString(b))),
			buf -> buf.assemble("dfmpyll R1R0,R3R2,R9R8"), 1,
			Map.ofEntries(
				Map.entry("R1R0_", Long.toHexString(accNew)),
				Map.entry("PC", "400004"),
				Map.entry("P0.new", "ff"),
				Map.entry("P1.new", "ff"),
				Map.entry("P2.new", "ff"),
				Map.entry("P3.new", "ff"),
				Map.entry("R1R0", Long.toHexString(accInit)),
				Map.entry("R3R2", Long.toHexString(a)),
				Map.entry("R9R8", Long.toHexString(b))));
	}

	@Test
	public void testDfmpyhhOnes() throws Exception {
		runTestDfmpyhh(DF_ONE_HH, DF_ONE, DF_ONE, DF_ONE);
	}

	@Test
	@Ignore
	public void testDfmpyhhZeroAnyQNan() throws Exception {
		runTestDfmpyhh(DF_HEX_NAN, DF_ZERO, DF_ANY, DF_QNAN);
	}

	@Test
	@Ignore
	public void testDfmpyhhZeroAnySNan() throws Exception {
		runTestDfmpyhh(DF_HEX_NAN, DF_ZERO, DF_ANY, DF_SNAN);
	}

	@Test
	@Ignore
	public void testDfmpyhhZeroQNanSNan() throws Exception {
		runTestDfmpyhh(DF_HEX_NAN, DF_ZERO, DF_QNAN, DF_SNAN);
	}

	@Test
	@Ignore
	public void testDfmpyhhZeroSNanQNan() throws Exception {
		runTestDfmpyhh(DF_HEX_NAN, DF_ZERO, DF_SNAN, DF_QNAN);
	}

	@Test
	public void testDfmpyhhMain() throws Exception {
		runTestDfmpyhh(
			0x4023_b81d_7dbf_4880L,
			0x0020_2752_200f_06f7L,
			0x4009_1eb8_51eb_851fL,
			0x4009_1eb8_51eb_851fL);
	}

	@Test
	public void testDfmpylhMins() throws Exception {
		runTestDfmpylh(0x10_0000_0000_0000L, DF_MIN, DF_MIN, DF_MIN);
	}

	@Test
	public void testDfmpylhNegOneMaxMin() throws Exception {
		runTestDfmpylh(0xc00f_ffff_ffe0_0000L, DF_NEG_ONE, DF_MAX, DF_MIN);
	}

	@Test
	public void testDfmpylhMaxZeroNegOne() throws Exception {
		runTestDfmpylh(0x7fef_ffff_ffff_ffffL, DF_MAX, DF_ZERO, DF_NEG_ONE);
	}

	@Test
	public void testDfmpyllMins() throws Exception {
		runTestDfmpyll(0, -1L, DF_MIN, DF_MIN);
	}

	@Test
	public void testDfmpyllNegOneMin() throws Exception {
		runTestDfmpyll(0, -1L, DF_NEG_ONE, DF_MIN);
	}

	@Test
	public void testDfmpyllMaxes() throws Exception {
		runTestDfmpyll(0x1_ffff_fffdL, -1L, DF_MAX, DF_MAX);
	}
}
