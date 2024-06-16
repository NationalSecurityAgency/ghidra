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

import static ghidra.pcode.utils.SlaFormat.*;
import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;

import ghidra.GhidraApplicationLayout;
import ghidra.app.plugin.assembler.sleigh.expr.*;
import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.languages.sleigh.ConstructorEntryVisitor;
import ghidra.app.plugin.languages.sleigh.SleighLanguages;
import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern;
import ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol;
import ghidra.app.plugin.processors.sleigh.template.ConstructTpl;
import ghidra.app.plugin.processors.sleigh.template.HandleTpl;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.pcode.*;
import ghidra.util.Msg;

public class SolverTest {
	static final DefaultAssemblyResolutionFactory FACTORY = new DefaultAssemblyResolutionFactory();

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
	public void testCatOrSolver() throws NeedsBackfillException, DecoderException, IOException {
		PatchPackedEncode encode = new PatchPackedEncode();
		encode.clear();
		encode.openElement(ELEM_OR_EXP);
		encode.openElement(ELEM_LSHIFT_EXP);
		encode.openElement(ELEM_TOKENFIELD);
		encode.writeBool(ATTRIB_BIGENDIAN, false);
		encode.writeBool(ATTRIB_SIGNBIT, false);
		encode.writeSignedInteger(ATTRIB_STARTBIT, 0);
		encode.writeSignedInteger(ATTRIB_ENDBIT, 3);
		encode.writeSignedInteger(ATTRIB_STARTBYTE, 0);
		encode.writeSignedInteger(ATTRIB_ENDBYTE, 0);
		encode.writeSignedInteger(ATTRIB_SHIFT, 0);
		encode.closeElement(ELEM_TOKENFIELD);
		encode.openElement(ELEM_INTB);
		encode.writeSignedInteger(ATTRIB_VAL, 4);
		encode.closeElement(ELEM_INTB);
		encode.closeElement(ELEM_LSHIFT_EXP);
		encode.openElement(ELEM_TOKENFIELD);
		encode.writeBool(ATTRIB_BIGENDIAN, false);
		encode.writeBool(ATTRIB_SIGNBIT, false);
		encode.writeSignedInteger(ATTRIB_STARTBIT, 0);
		encode.writeSignedInteger(ATTRIB_ENDBIT, 11);
		encode.writeSignedInteger(ATTRIB_STARTBYTE, 1);
		encode.writeSignedInteger(ATTRIB_ENDBYTE, 1);
		encode.writeSignedInteger(ATTRIB_SHIFT, 0);
		encode.closeElement(ELEM_TOKENFIELD);
		encode.closeElement(ELEM_OR_EXP);
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		encode.writeTo(outStream);
		byte[] bytes = outStream.toByteArray();
		PackedDecode decoder = new PackedDecode();
		decoder.open(1024, "Test");
		decoder.ingestBytes(bytes, 0, bytes.length);
		decoder.endIngest();
//				<or_exp>
//				  <lshift_exp>
//				    <tokenfield bigendian='false' signbit='false' bitstart='0' bitend='3'
//				                bytestart='0' byteend='0' shift='0'/>
//				    <intb val='4'/>
//				  </lshift_exp>
//				  <tokenfield bigendian='false' signbit='false' bitstart='8' bitend='11'
//				              bytestart='1' byteend='1' shift='0'/>
//				</or_exp>
		PatternExpression exp = PatternExpression.decodeExpression(decoder, null);
		RecursiveDescentSolver solver = RecursiveDescentSolver.getSolver();
		AssemblyResolution res = solver.solve(FACTORY, exp, MaskedLong.fromLong(0x78),
			Collections.emptyMap(), FACTORY.nop("NOP"), "Test");
		AssemblyResolution e = FACTORY.fromString("ins:X7:X8", "Test", null);
		assertEquals(e, res);
	}

	public static Constructor findConstructor(String langId, String subtableName, String patternStr)
			throws Exception {
		if (!Application.isInitialized()) {
			Application.initializeApplication(new GhidraApplicationLayout(),
				new ApplicationConfiguration());
		}
		SleighLanguageProvider provider = SleighLanguageProvider.getSleighLanguageProvider();
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
		SleighLanguageProvider provider = SleighLanguageProvider.getSleighLanguageProvider();
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

	@Test
	public void testAssemblyPatternBlockMaskOut() {
		AssemblyPatternBlock base = AssemblyPatternBlock.fromString("8C:45:00:00");
		AssemblyPatternBlock extraMask = AssemblyPatternBlock.fromString("XX:X5:XX:XX");
		AssemblyPatternBlock expectedAnswer = AssemblyPatternBlock.fromString("8C:4X:00:00");
		AssemblyPatternBlock computed = base.maskOut(extraMask);
		assertEquals(expectedAnswer, computed);

		base = AssemblyPatternBlock.fromString("8C:45:00:00");
		extraMask = AssemblyPatternBlock.fromString("XX:X5:XX:XX");
		expectedAnswer = AssemblyPatternBlock.fromString("8C:4X:00:00");
		computed = base.maskOut(extraMask);
		assertEquals(expectedAnswer, computed);

		base = AssemblyPatternBlock.fromString("8C:45:67:89");
		byte[] z = new byte[2];
		z[0] = 0x44;
		z[1] = 0x77;
		extraMask = AssemblyPatternBlock.fromBytes(2, z);
		expectedAnswer = AssemblyPatternBlock.fromString("8C:45:XX:XX");
		computed = base.maskOut(extraMask);
		assertEquals(expectedAnswer, computed);

		extraMask = AssemblyPatternBlock.fromBytes(1, z);
		expectedAnswer = AssemblyPatternBlock.fromString("8C:XX:XX:89");
		computed = base.maskOut(extraMask);
		assertEquals(expectedAnswer, computed);

		base = AssemblyPatternBlock.fromString("01:02:03:04:05:06:07:08");
		extraMask = AssemblyPatternBlock.fromBytes(1, z);
		expectedAnswer = AssemblyPatternBlock.fromString("01:XX:XX:04:05:06:07:08");
		computed = base.maskOut(extraMask);
		assertEquals(expectedAnswer, computed);

		byte[] z3 = new byte[3];
		z3[0] = 0x44;
		z3[1] = 0x77;
		z3[2] = 0x78;
		base = AssemblyPatternBlock.fromBytes(4, z3);
		extraMask = AssemblyPatternBlock.fromBytes(1, z);
		expectedAnswer = AssemblyPatternBlock.fromBytes(4, z3);
		computed = base.maskOut(extraMask);
		assertEquals(expectedAnswer, computed);

		extraMask = AssemblyPatternBlock.fromBytes(4, z);
		byte[] z4 = new byte[1];
		z4[0] = 0x78;
		expectedAnswer = AssemblyPatternBlock.fromBytes(6, z4);
		computed = base.maskOut(extraMask);
		assertEquals(expectedAnswer, computed);
	}

	@Test
	public void testAssemblyPatternBlockTrim() {
		AssemblyPatternBlock base = AssemblyPatternBlock.fromString("XC:45:00:0X");
		AssemblyPatternBlock expectedAnswer = AssemblyPatternBlock.fromString("c4:50:00");
		var computed = base.trim();
		assertEquals(expectedAnswer, computed);

		base = base.shift(5);
		computed = base.trim();
		assertEquals(expectedAnswer, computed);

		base = AssemblyPatternBlock.fromString("XX:XX:00:XX:10:XX");
		expectedAnswer = AssemblyPatternBlock.fromString("00:XX:10");
		computed = base.trim();
		assertEquals(expectedAnswer, computed);

		base = base.shift(2);
		expectedAnswer = AssemblyPatternBlock.fromString("00:XX:10");
		computed = base.trim();
		assertEquals(expectedAnswer, computed);

		base = AssemblyPatternBlock.fromString("[x1xx]X");
		expectedAnswer = AssemblyPatternBlock.fromString("X[xxx1]");
		computed = base.trim();
		assertEquals(expectedAnswer, computed);

		// The "f" here has the "sign bit" set... we wan't to make sure it's treated as
		// unsigned
		base = AssemblyPatternBlock.fromString("F[x1xx]").shift(3);
		expectedAnswer = AssemblyPatternBlock.fromString("[xx11][11x1]");
		computed = base.trim();
		assertEquals(expectedAnswer, computed);
	}
}
