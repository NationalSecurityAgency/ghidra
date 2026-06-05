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
import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.*;
import ghidra.program.emulation.TricorePcodeUseropLibraryFactory.TricorePcodeUseropLibrary;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;

public class TricorePcodeUseropLibraryTest extends AbstractEmulationEquivalenceTest {
	static final LanguageID LANGI_ID_TRICORE = new LanguageID("tricore:LE:32:default");

	static SleighLanguage TRICORE;

	@Before
	public void setupTricore() throws Exception {
		if (TRICORE == null) {
			TRICORE = (SleighLanguage) DefaultLanguageService.getLanguageService()
					.getLanguage(LANGI_ID_TRICORE);
		}
	}

	@Test
	public void testFoundById() {
		PcodeUseropLibrary<byte[]> lib = PcodeUseropLibraryFactory
				.createUseropLibraryFromId("tricore", TRICORE,
					BytesPcodeArithmetic.forLanguage(TRICORE));
		assertThat(lib, Matchers.instanceOf(TricorePcodeUseropLibrary.class));
	}

	@Test
	public void testFoundByLang() {
		PcodeUseropLibrary<byte[]> lib = PcodeUseropLibraryFactory
				.createUseropLibraryForLanguage(TRICORE, BytesPcodeArithmetic.forLanguage(TRICORE));
		assertNotNull(lib.getUserops().get("saveCallerState"));
		assertNotNull(lib.getUserops().get("restoreCallerState"));
	}

	@Test
	public void testCall() throws Exception {
		doTestEquiv(TRICORE,
			Map.ofEntries(
				Map.entry("FCX", "00020000"),
				Map.entry("PCXI", "00000000"),
				Map.entry("PSW", "00000000")),
			buf -> buf.assemble("call 0x00401234"), 1,
			Map.ofEntries(
				Map.entry("PCXI", "20000"),
				Map.entry("FCX", "20001"),
				Map.entry("a11", "400004"),
				Map.entry("PC", "401234")));
	}

	@Test
	public void testCallRet() throws Exception {
		doTestEquiv(TRICORE,
			Map.ofEntries(
				Map.entry("FCX", "00020001"),
				Map.entry("PCXI", "00020000"),
				Map.entry("a10", "1110"),
				Map.entry("a11", "1111"),
				Map.entry("a12", "1112"),
				Map.entry("a13", "1113"),
				Map.entry("a14", "1114"),
				Map.entry("a15", "1115"),
				Map.entry("d8", "1208"),
				Map.entry("d9", "1209"),
				Map.entry("d10", "1210"),
				Map.entry("d11", "1211"),
				Map.entry("d12", "1212"),
				Map.entry("d13", "1213"),
				Map.entry("d14", "1214"),
				Map.entry("d15", "1215")),
			buf -> {
				buf.assemble("call 0x00400002"); // length is 2
				buf.assemble("ret");
			}, 2,
			Map.ofEntries(
				Map.entry("PCXI", "20000"),
				Map.entry("PSW", "0"),
				Map.entry("FCX", "20001"),
				Map.entry("PC", "400002"),
				Map.entry("a10", "1110"),
				Map.entry("a11", "1111"),
				Map.entry("a12", "1112"),
				Map.entry("a13", "1113"),
				Map.entry("a14", "1114"),
				Map.entry("a15", "1115"),
				Map.entry("d8", "1208"),
				Map.entry("d9", "1209"),
				Map.entry("d10", "1210"),
				Map.entry("d11", "1211"),
				Map.entry("d12", "1212"),
				Map.entry("d13", "1213"),
				Map.entry("d14", "1214"),
				Map.entry("d15", "1215")));
	}
}
