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

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;
import org.xml.sax.SAXException;

import ghidra.GhidraApplicationLayout;
import ghidra.app.plugin.assembler.sleigh.expr.*;
import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.languages.sleigh.ConstructorEntryVisitor;
import ghidra.app.plugin.languages.sleigh.SleighLanguages;
import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern;
import ghidra.app.plugin.processors.sleigh.symbol.*;
import ghidra.app.plugin.processors.sleigh.template.ConstructTpl;
import ghidra.app.plugin.processors.sleigh.template.HandleTpl;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.Msg;
import ghidra.xml.XmlPullParser;
import ghidra.xml.XmlPullParserFactory;

public class SolverTest {

	private static final MaskedLong nil = MaskedLong.ZERO;
	private static final MaskedLong unk = MaskedLong.UNKS;
	private static final MaskedLong one = MaskedLong.ONES;

	@Test
	public void testAnd() {
		assertEquals(nil, nil.and(nil));
		assertEquals(nil, nil.and(unk));
		assertEquals(nil, nil.and(one));

		assertEquals(nil, unk.and(nil));
		assertEquals(unk, unk.and(unk));
		assertEquals(unk, unk.and(one));

		assertEquals(nil, one.and(nil));
		assertEquals(unk, one.and(unk));
		assertEquals(one, one.and(one));
	}

	@Test
	public void testInvAnd() throws SolverException {
		assertEquals(unk, nil.invAnd(nil));
		assertEquals(unk, nil.invAnd(unk));
		assertEquals(nil, nil.invAnd(one));

		assertEquals(unk, unk.invAnd(nil));
		assertEquals(unk, unk.invAnd(unk));
		assertEquals(unk, unk.invAnd(one));

		try {
			@SuppressWarnings("unused")
			MaskedLong res = one.invAnd(nil);
			fail();
		}
		catch (SolverException e) {
			// pass
		}
		assertEquals(one, one.invAnd(unk));
		assertEquals(one, one.invAnd(one));
	}

	@Test
	public void testOr() {
		assertEquals(nil, nil.or(nil));
		assertEquals(unk, nil.or(unk));
		assertEquals(one, nil.or(one));

		assertEquals(unk, unk.or(nil));
		assertEquals(unk, unk.or(unk));
		assertEquals(one, unk.or(one));

		assertEquals(one, one.or(nil));
		assertEquals(one, one.or(unk));
		assertEquals(one, one.or(one));
	}

	@Test
	public void testInvOr() throws SolverException {
		assertEquals(nil, nil.invOr(nil));
		assertEquals(nil, nil.invOr(unk));
		try {
			@SuppressWarnings("unused")
			MaskedLong res = nil.invOr(one);
			fail();
		}
		catch (SolverException e) {
			// pass
		}

		assertEquals(unk, unk.invOr(nil));
		assertEquals(unk, unk.invOr(unk));
		assertEquals(unk, unk.invOr(one));

		assertEquals(one, one.invOr(nil));
		assertEquals(unk, one.invOr(unk));
		assertEquals(unk, one.invOr(one));
	}

	@Test
	public void testXor() {
		assertEquals(nil, nil.xor(nil));
		assertEquals(unk, nil.xor(unk));
		assertEquals(one, nil.xor(one));

		assertEquals(unk, unk.xor(nil));
		assertEquals(unk, unk.xor(unk));
		assertEquals(unk, unk.xor(one));

		assertEquals(one, one.xor(nil));
		assertEquals(unk, one.xor(unk));
		assertEquals(nil, one.xor(one));
	}

	@Test
	public void testWriteUnks() {
		String str = "XX:[x10x]5:AA";
		AssemblyPatternBlock a = AssemblyPatternBlock.fromString(str);
		assertEquals(str, a.toString());
		MaskedLong toWrite = MaskedLong.fromMaskAndValue(0x3, 0x2);
		ContextOp chg = new ContextOp() {
			@Override
			public int getMask() {
				return 0x780;
			}

			@Override
			public int getShift() {
				return 7;
			}

			@Override
			public int getWordIndex() {
				return 0;
			}
		};
		AssemblyPatternBlock b = a.writeContextOp(chg, toWrite);
		assertEquals("XX:[x10x]5:A[1xx1]:[0xxx]X", b.toString());
	}

	@Test
	public void testCatOrSolver() throws SAXException, NeedsBackfillException {
		XmlPullParser parser = XmlPullParserFactory.create("" + //
			//
			"<or_exp>\n" + //
			"  <lshift_exp>\n" + //
			"    <tokenfield bigendian='false' signbit='false' bitstart='0' bitend='3' bytestart='0' byteend='0' shift='0'/>\n" + //
			"    <intb val='4'/>\n" + //
			"  </lshift_exp>\n" + //
			"  <tokenfield bigendian='false' signbit='false' bitstart='8' bitend='11' bytestart='1' byteend='1' shift='0'/>\n" + //
			"</or_exp>\n" + //
			"", "Test", null, true);
		PatternExpression exp = PatternExpression.restoreExpression(parser, null);
		RecursiveDescentSolver solver = RecursiveDescentSolver.getSolver();
		AssemblyResolution res =
			solver.solve(exp, MaskedLong.fromLong(0x78), Collections.emptyMap(),
				Collections.emptyMap(), AssemblyResolution.nop("NOP", null), "Test");
		AssemblyResolution e = AssemblyResolvedConstructor.fromString("ins:X7:X8", "Test", null);
		assertEquals(e, res);
	}

	public static Constructor findConstructor(String langId, String subtableName, String patternStr)
			throws Exception {
		if (!Application.isInitialized()) {
			Application.initializeApplication(new GhidraApplicationLayout(),
				new ApplicationConfiguration());
		}
		SleighLanguageProvider provider = new SleighLanguageProvider();
		SleighLanguage lang = (SleighLanguage) provider.getLanguage(new LanguageID(langId));
		AtomicReference<Constructor> consref = new AtomicReference<>();
		SleighLanguages.traverseConstructors(lang, new ConstructorEntryVisitor() {
			@Override
			public int visit(SubtableSymbol subtable, DisjointPattern pattern, Constructor cons) {
				if (subtableName.equals(subtable.getName())) {
					if (patternStr.equals(pattern.toString())) {
						consref.set(cons);
						return FINISHED;
					}
				}
				return CONTINUE;
			}
		});
		Msg.info(SolverTest.class, "Found constructor: " + consref.get());
		return consref.get();
	}

	public static Constructor findConstructor(String langId, int lineno) throws Exception {
		if (!Application.isInitialized()) {
			Application.initializeApplication(new GhidraApplicationLayout(),
				new ApplicationConfiguration());
		}
		SleighLanguageProvider provider = new SleighLanguageProvider();
		SleighLanguage lang = (SleighLanguage) provider.getLanguage(new LanguageID(langId));
		AtomicReference<Constructor> consref = new AtomicReference<>();
		SleighLanguages.traverseConstructors(lang, new ConstructorEntryVisitor() {
			@Override
			public int visit(SubtableSymbol subtable, DisjointPattern pattern, Constructor cons) {
				if (cons.getLineno() == lineno) {
					consref.set(cons);
					Msg.info(SolverTest.class, "Constructor " + cons + " has pattern " + pattern);
					Msg.info(SolverTest.class,
						"You should prefer to find it by pattern rather than line number");
					return FINISHED;
				}
				return CONTINUE;
			}
		});
		return consref.get();
	}

	@Test
	public void testGetOperandExportSize32() throws Exception {
		Constructor ct = findConstructor("AARCH64:BE:64:v8A", "Imm_uimm_exact32", "always");
		ConstructTpl ctpl = ct.getTempl();
		HandleTpl htpl = ctpl.getResult();
		assertEquals(32, htpl.getSize());
	}

	@Test
	public void testGetOperandExportSize64() throws Exception {
		Constructor ct = findConstructor("AARCH64:BE:64:v8A", "addrRegShift64",
			"ins:SS:SS:SS:[01xx][x0xx]:XX:XX:XX");
		ConstructTpl ctpl = ct.getTempl();
		HandleTpl htpl = ctpl.getResult();
		assertEquals(64, htpl.getSize());
	}

	@Test
	public void testGetOperandExportSize16() throws Exception {
		Constructor ct = findConstructor("avr8:LE:16:extended", "next16memPtrVal1", "always");
		ConstructTpl ctpl = ct.getTempl();
		HandleTpl htpl = ctpl.getResult();
		assertEquals(16, htpl.getSize());
	}

	public void testExperimentGetOperandExportSize1() throws Exception {
		if (!Application.isInitialized()) {
			Application.initializeApplication(new GhidraApplicationLayout(),
				new ApplicationConfiguration());
		}
		SleighLanguageProvider provider = new SleighLanguageProvider();
		SleighLanguage lang =
			(SleighLanguage) provider.getLanguage(new LanguageID("AARCH64:BE:64:v8A"));
		AtomicReference<Constructor> consref = new AtomicReference<>();
		SleighLanguages.traverseConstructors(lang, new ConstructorEntryVisitor() {
			@Override
			public int visit(SubtableSymbol subtable, DisjointPattern pattern, Constructor cons) {
				if ("Imm_logical_imm32_operand".equals(subtable.getName())) {
					if ("ins:SS:C[00xx]:[x0xx]X:XX:XX".equals(pattern.toString())) {
						consref.set(cons);
						return FINISHED;
					}
				}
				return CONTINUE;
			}
		});
		Constructor ct = consref.get();
		ConstructState st = new ConstructState(null) {
			@Override
			public Constructor getConstructor() {
				return ct;
			}
		};
		int num = ct.getNumOperands();
		for (int i = 0; i < num; i++) {
			ConstructState sub = new ConstructState(st);
			st.addSubState(sub);
		}
		SleighParserContext ctx = new SleighParserContext(null, null, null, null);

		ParserWalker walker = new ParserWalker(ctx);

		walker.subTreeState(st);
		while (walker.isState()) {
			assert ct == walker.getConstructor();
			int oper = walker.getOperand();
			int numoper = ct.getNumOperands();
			while (oper < numoper) {
				OperandSymbol sym = ct.getOperand(oper);
				walker.pushOperand(oper);
				TripleSymbol triple = sym.getDefiningSymbol();
				if (triple != null) {
					if (triple instanceof SubtableSymbol) {
						break;
					}
					FixedHandle handle = walker.getParentHandle();
					triple.getFixedHandle(handle, walker);
				}
				else { // Must be an expression
						//PatternExpression patexp = sym.getDefiningExpression();
						//long res = patexp.getValue(walker);
					FixedHandle hand = walker.getParentHandle();
					hand.space = lang.getAddressFactory().getConstantSpace();
					hand.offset_space = null;
					hand.offset_offset = 0x1010101010101010L;
					hand.size = 0;
				}
				walker.popOperand();
				oper++;
			}
			if (oper >= numoper) {
				ConstructTpl templ = ct.getTempl();
				if (templ != null) {
					HandleTpl res = templ.getResult();
					if (res != null) {
						res.fix(walker.getParentHandle(), walker);
					}
					else {
						walker.getParentHandle().setInvalid();
					}
				}
				walker.popOperand();
			}
		}

		walker.subTreeState(st);

		walker.subTreeState(st);
		ArrayList<Object> list = new ArrayList<>();
		ct.printList(walker, list);
		for (Object obj : list) {
			if (obj instanceof Character) {
				System.out.print(obj);
			}
			else if (obj instanceof FixedHandle) {
				FixedHandle handle = (FixedHandle) obj;
				System.out.println(
					new Scalar(8 * handle.size, handle.offset_offset) + "(" + handle.size + ")");
			}
		}
	}

	@Test
	public void testInRange() {
		// Simple case of zero, signed and unsigned
		assertTrue(MaskedLong.fromLong(0).isInRange(0xfL, true));
		assertTrue(MaskedLong.fromLong(0).isInRange(0xfL, false));

		assertTrue(MaskedLong.fromLong(0).isInRange(0xffL, true));
		assertTrue(MaskedLong.fromLong(0).isInRange(0xffL, false));

		assertTrue(MaskedLong.fromLong(0).isInRange(0xffffL, true));
		assertTrue(MaskedLong.fromLong(0).isInRange(0xffffL, false));

		assertTrue(MaskedLong.fromLong(0).isInRange(0xffffffffL, true));
		assertTrue(MaskedLong.fromLong(0).isInRange(0xffffffffL, false));

		assertTrue(MaskedLong.fromLong(0).isInRange(0xffffffffffffffffL, true));
		assertTrue(MaskedLong.fromLong(0).isInRange(0xffffffffffffffffL, false));

		// Positive edges, unsigned
		assertTrue(MaskedLong.fromLong(0xfL).isInRange(0xfL, false));
		assertFalse(MaskedLong.fromLong(0x10L).isInRange(0xfL, false));

		assertTrue(MaskedLong.fromLong(0xffL).isInRange(0xffL, false));
		assertFalse(MaskedLong.fromLong(0x100L).isInRange(0xffL, false));

		assertTrue(MaskedLong.fromLong(0xffffL).isInRange(0xffffL, false));
		assertFalse(MaskedLong.fromLong(0x10000L).isInRange(0xffffL, false));

		assertTrue(MaskedLong.fromLong(0xffffffffL).isInRange(0xffffffffL, false));
		assertFalse(MaskedLong.fromLong(0x100000000L).isInRange(0xffffffffL, false));

		assertTrue(MaskedLong.fromLong(0xffffffffffffffffL).isInRange(0xffffffffffffffffL, false));
		// NOTE: Cannot express 2**64 as a long

		// Positive edges signed
		assertTrue(MaskedLong.fromLong(0x7L).isInRange(0xfL, true));
		assertFalse(MaskedLong.fromLong(0x8L).isInRange(0xfL, true));

		assertTrue(MaskedLong.fromLong(0x7fL).isInRange(0xffL, true));
		assertFalse(MaskedLong.fromLong(0x80L).isInRange(0xffL, true));

		assertTrue(MaskedLong.fromLong(0x7fffL).isInRange(0xffffL, true));
		assertFalse(MaskedLong.fromLong(0x8000L).isInRange(0xffffL, true));

		assertTrue(MaskedLong.fromLong(0x7fffffffL).isInRange(0xffffffffL, true));
		assertFalse(MaskedLong.fromLong(0x80000000L).isInRange(0xffffffffL, true));

		assertTrue(MaskedLong.fromLong(0x7fffffffffffffffL).isInRange(0xffffffffffffffffL, true));
		// NOTE: 0x8000000000000000L will appear negative to Java

		// Negative edges signed
		assertTrue(MaskedLong.fromLong(-0x8L).isInRange(0xfL, true));
		assertFalse(MaskedLong.fromLong(-0x9L).isInRange(0xfL, true));

		assertTrue(MaskedLong.fromLong(-0x80L).isInRange(0xffL, true));
		assertFalse(MaskedLong.fromLong(-0x81L).isInRange(0xffL, true));

		assertTrue(MaskedLong.fromLong(-0x8000L).isInRange(0xffffL, true));
		assertFalse(MaskedLong.fromLong(-0x8001L).isInRange(0xffffL, true));

		assertTrue(MaskedLong.fromLong(-0x80000000L).isInRange(0xffffffffL, true));
		assertFalse(MaskedLong.fromLong(-0x80000001L).isInRange(0xffffffffL, true));

		assertTrue(MaskedLong.fromLong(-0x800000000000000L).isInRange(0xffffffffffffffffL, true));
		// NOTE: -0x8000000000000001L will wrap around and appear positive
	}
}
