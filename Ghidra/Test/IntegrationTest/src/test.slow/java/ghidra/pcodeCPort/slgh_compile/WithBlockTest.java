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
package ghidra.pcodeCPort.slgh_compile;

import static org.junit.Assert.assertEquals;

import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.languages.sleigh.ConstructorEntryVisitor;
import ghidra.app.plugin.languages.sleigh.SleighLanguages;
import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern;
import ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol;
import ghidra.program.model.lang.LanguageID;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class WithBlockTest extends AbstractGhidraHeadlessIntegrationTest {

	protected static boolean setupDone;
	protected static LanguageID langID;
	protected static SleighLanguageProvider provider;
	protected static SleighLanguage lang;

	@Before
	public void setUp() throws Exception {
		if (!setupDone) {
			langID = new LanguageID("TestWith:BE:32:default");
			provider = new SleighLanguageProvider();
			lang = (SleighLanguage) provider.getLanguage(langID);
			setupDone = true;
		}
	}

	protected String opnd(int n) {
		return "\n" + (char) ('A' + n);
	}

	protected Pair<DisjointPattern, Constructor> findConstructor(String table, String firstPrint) {
		AtomicReference<DisjointPattern> fpat = new AtomicReference<>(null);
		AtomicReference<Constructor> fcon = new AtomicReference<>(null);
		SleighLanguages.traverseConstructors(lang, new ConstructorEntryVisitor() {
			@Override
			public int visit(SubtableSymbol subtable, DisjointPattern pattern, Constructor cons) {
				if (table.equals(subtable.getName()) &&
					firstPrint.equals(cons.getPrintPieces().get(0))) {
					if (null != fpat.get()) {
						throw new AssertionError("Multiple constructors found. " +
							"Write the test slaspec such that no two constructors in the same " +
							"table share the same first printpiece.");
					}
					fpat.set(pattern);
					fcon.set(cons);
				}
				return CONTINUE;
			}
		});
		if (null == fpat.get()) {
			throw new AssertionError(
				"No such constructor found: " + table + ":" + firstPrint + "...");
		}
		return new ImmutablePair<>(fpat.get(), fcon.get());
	}

	@Test
	public void testNOP1_NoWith() {
		Pair<DisjointPattern, Constructor> NOP1 = findConstructor("instruction", "NOP1");
		assertEquals("ins:SS:XF:XX:XX:XX", NOP1.getLeft().toString());
		assertEquals(0, NOP1.getRight().getContextChanges().size());
	}

	@Test
	public void testRel8addr_WithTabRel8_WithChgPhase3() {
		Pair<DisjointPattern, Constructor> Rel8addr = findConstructor("Rel8", opnd(1));
		assertEquals("always", Rel8addr.getLeft().toString());
		assertEquals(1, Rel8addr.getRight().getContextChanges().size());
		assertEquals("ctx&F0:00:00:00 := 0x3( << 28)",
			Rel8addr.getRight().getContextChanges().get(0).toString());
	}

	@Test
	public void testOP1r0_WithTabOp1() {
		Pair<DisjointPattern, Constructor> OP1r0 = findConstructor("OP1", "r0");
		assertEquals("cmb:(ctx:1X:XX:XX:XX,ins:X0:XX:XX:XX)", OP1r0.getLeft().toString());
		assertEquals(1, OP1r0.getRight().getContextChanges().size());
		assertEquals("ctx&F0:00:00:00 := 0x2( << 28)",
			OP1r0.getRight().getContextChanges().get(0).toString());
	}

	@Test
	public void testOP1r1_WithPatPhase1() {
		Pair<DisjointPattern, Constructor> OP1r1 = findConstructor("OP1", "r1");
		assertEquals("cmb:(ctx:1X:XX:XX:XX,ins:X1:XX:XX:XX)", OP1r1.getLeft().toString());
		assertEquals(1, OP1r1.getRight().getContextChanges().size());
		assertEquals("ctx&F0:00:00:00 := 0x2( << 28)",
			OP1r1.getRight().getContextChanges().get(0).toString());
	}

	@Test
	public void testOP1r2_WithChgPhase2() {
		Pair<DisjointPattern, Constructor> OP1r2 = findConstructor("OP1", "r2");
		assertEquals("ins:X2:XX:XX:XX", OP1r2.getLeft().toString());
		assertEquals(2, OP1r2.getRight().getContextChanges().size());
		assertEquals("ctx&F0:00:00:00 := 0x2( << 28)",
			OP1r2.getRight().getContextChanges().get(0).toString());
		assertEquals("ctx&F0:00:00:00 := 0x1( << 28)",
			OP1r2.getRight().getContextChanges().get(1).toString());
	}

	@Test
	public void testDSTr0_WithPatPhase1_WithTabDST() {
		Pair<DisjointPattern, Constructor> DSTr0 = findConstructor("DST", "r0");
		assertEquals("cmb:(ctx:1X:XX:XX:XX,ins:SS:0X:XX:XX:XX)", DSTr0.getLeft().toString());
		assertEquals(0, DSTr0.getRight().getContextChanges().size());
	}

	@Test
	public void testOP1r3_WithPatPhase1_WithTabOP1() {
		Pair<DisjointPattern, Constructor> OP1r3 = findConstructor("OP1", "r3");
		assertEquals("cmb:(ctx:1X:XX:XX:XX,ins:X3:XX:XX:XX)", OP1r3.getLeft().toString());
		assertEquals(0, OP1r3.getRight().getContextChanges().size());
	}

	@Test
	public void testOP2r1_WithPatPhase1_WithTabOP1() {
		Pair<DisjointPattern, Constructor> OP2r1 = findConstructor("OP2", "r1");
		assertEquals("cmb:(ctx:1X:XX:XX:XX,ins:1X:XX:XX:XX)", OP2r1.getLeft().toString());
		assertEquals(0, OP2r1.getRight().getContextChanges().size());
	}

	@Test
	public void testOP2r0_WithPatPhase1_WithTabOP2() {
		Pair<DisjointPattern, Constructor> OP2r0 = findConstructor("OP2", "r0");
		assertEquals("cmb:(ctx:1X:XX:XX:XX,ins:0X:XX:XX:XX)", OP2r0.getLeft().toString());
		assertEquals(0, OP2r0.getRight().getContextChanges().size());
	}

	@Test
	public void testNOP2_NoWith() {
		Pair<DisjointPattern, Constructor> NOP2 = findConstructor("instruction", "NOP2");
		assertEquals("ins:SS:XE:XX:XX:XX", NOP2.getLeft().toString());
		assertEquals(0, NOP2.getRight().getContextChanges().size());
	}

	@Test
	public void testADD_NoWith() {
		Pair<DisjointPattern, Constructor> ADD = findConstructor("instruction", "ADD");
		assertEquals("cmb:(ctx:1X:XX:XX:XX,ins:SS:X0:XX:XX:XX)", ADD.getLeft().toString());
		assertEquals(0, ADD.getRight().getContextChanges().size());
	}

	@Test
	public void testLD_NoWith() {
		Pair<DisjointPattern, Constructor> LD = findConstructor("instruction", "LD");
		assertEquals("cmb:(ctx:1X:XX:XX:XX,ins:SS:X8:XX:XX:XX)", LD.getLeft().toString());
		assertEquals(0, LD.getRight().getContextChanges().size());
	}

	// TODO: Explicit override of subtable in with
}
