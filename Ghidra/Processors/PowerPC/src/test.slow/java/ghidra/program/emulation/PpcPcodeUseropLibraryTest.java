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
import ghidra.program.emulation.PpcPcodeUseropLibraryFactory.PpcPcodeUseropLibrary;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;

public class PpcPcodeUseropLibraryTest extends AbstractEmulationEquivalenceTest {
	static final LanguageID LANGI_ID_PCC64 = new LanguageID("PowerPC:BE:64:A2ALT-32addr");

	static SleighLanguage PPC64;

	@Before
	public void setupPpc() throws Exception {
		if (PPC64 == null) {
			PPC64 = (SleighLanguage) DefaultLanguageService.getLanguageService()
					.getLanguage(LANGI_ID_PCC64);
		}
	}

	@Test
	public void testFoundById() {
		PcodeUseropLibrary<byte[]> lib = PcodeUseropLibraryFactory
				.createUseropLibraryFromId("ppc", PPC64, BytesPcodeArithmetic.forLanguage(PPC64));
		assertThat(lib, Matchers.instanceOf(PpcPcodeUseropLibrary.class));
	}

	@Test
	public void testFoundByLang() {
		PcodeUseropLibrary<byte[]> lib = PcodeUseropLibraryFactory
				.createUseropLibraryForLanguage(PPC64, BytesPcodeArithmetic.forLanguage(PPC64));
		assertNotNull(lib.getUserops().get("vectorPermute"));
	}

	@Test
	public void testVperm1() throws Exception {
		doTestEquiv(PPC64,
			Map.ofEntries(
				Map.entry("vs44", "ffffffffffffffff"),
				Map.entry("vs45", "0123456789abcdef"),
				Map.entry("vs33", "fedcba9876543210"),
				Map.entry("vs43", "0004080c1014181c")),
			buf -> buf.assemble("vperm v12,v13,v1,v11"), 1,
			Map.ofEntries(
				Map.entry("vs44", "1890000fe76"),
				Map.entry("vs45", "123456789abcdef"),
				Map.entry("vs33", "fedcba9876543210"),
				Map.entry("vs43", "4080c1014181c")));
	}

	@Test
	public void testVperm2() throws Exception {
		doTestEquiv(PPC64,
			Map.ofEntries(
				Map.entry("vs44", "ffffffffffffffffffffffffffffffff"),
				Map.entry("vs45", "ffffffe0000000000000000100000002"),
				Map.entry("vs33", "00000003000000040000000500000006"),
				Map.entry("vs43", "08090a0b0c0d0e0f1011121314151617")),
			buf -> buf.assemble("vperm v12,v13,v1,v11"), 1,
			Map.ofEntries(
				Map.entry("vs44", "1000000020000000300000004"),
				Map.entry("vs45", "ffffffe0000000000000000100000002"),
				Map.entry("vs33", "3000000040000000500000006"),
				Map.entry("vs43", "8090a0b0c0d0e0f1011121314151617")));
	}

	@Test
	public void testVperm3() throws Exception {
		doTestEquiv(PPC64,
			Map.ofEntries(
				Map.entry("vs44", "ffffffffffffffffffffffffffffffff"),
				Map.entry("vs45", "00000001000000020000000300000004"),
				Map.entry("vs33", "00000001000000020000000300000004"),
				Map.entry("vs43", "101112131415161718191a1b1c1d1e1f")),
			buf -> buf.assemble("vperm v12,v13,v1,v11"), 1,
			Map.ofEntries(
				Map.entry("vs44", "1000000020000000300000004"),
				Map.entry("vs45", "1000000020000000300000004"),
				Map.entry("vs33", "1000000020000000300000004"),
				Map.entry("vs43", "101112131415161718191a1b1c1d1e1f")));
	}
}
