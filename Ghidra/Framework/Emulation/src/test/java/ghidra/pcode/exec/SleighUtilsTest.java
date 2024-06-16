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
package ghidra.pcode.exec;

import static org.junit.Assert.*;

import org.antlr.runtime.RecognitionException;
import org.antlr.runtime.tree.Tree;
import org.junit.Test;

import ghidra.pcode.exec.SleighUtils.AddressOf;
import ghidra.pcode.exec.SleighUtils.SleighParseError;

public class SleighUtilsTest {
	@Test
	public void testParseSleighSemantic() throws RecognitionException {
		String mySleigh = """
				if !(RAX == 0) goto <L1>;
				  emu_swi();
				<L1>
				emu_exec_decoded();
				""";
		Tree tree = SleighUtils.parseSleighSemantic(mySleigh);
		assertEquals(
			"(OP_SEMANTIC (if (! ((...) (== (IDENTIFIER RAX) (DEC_INT 0)))) (goto " +
				"(OP_JUMPDEST_LABEL (< (IDENTIFIER L1))))) (OP_APPLY (IDENTIFIER emu_swi)) " +
				"(< (IDENTIFIER L1)) (OP_APPLY (IDENTIFIER emu_exec_decoded)))",
			tree.toStringTree());
	}

	@Test
	public void testParseSleighSemanticErr() throws RecognitionException {
		String mySleigh = """
				if (!(RAX == 0)) goto <L1>;
				  emu_swi();
				<L1>
				emu_exec_decoded
				""";
		try {
			SleighUtils.parseSleighSemantic(mySleigh);
			fail();
		}
		catch (SleighParseError e) {
			assertEquals("""
					sleigh line 4: no viable alternative on EOF (missing semi-colon after this?):

					emu_exec_decoded
					----------------^
					""", e.getMessage());
		}
	}

	@Test
	public void testRecoverAddressOfMismatchErr() {
		AddressOf addrOf = SleighUtils.recoverAddressOf(null, "ptr + 8");
		assertNull(addrOf);
	}

	@Test
	public void testRecoverAddressOfForm1() {
		AddressOf addrOf = SleighUtils.recoverAddressOf(null, "*ptr");
		assertEquals(null, addrOf.space());
		assertEquals("ptr", SleighUtils.generateSleighExpression(addrOf.offset()));
	}

	@Test
	public void testRecoverAddressOfForm2a() {
		AddressOf addrOf = SleighUtils.recoverAddressOf(null, "*:8 ptr");
		assertEquals(null, addrOf.space());
		assertEquals("ptr", SleighUtils.generateSleighExpression(addrOf.offset()));
	}

	@Test
	public void testRecoverAddressOfForm2b() {
		AddressOf addrOf = SleighUtils.recoverAddressOf(null, "*[ram] ptr");
		assertEquals("ram", addrOf.space());
		assertEquals("ptr", SleighUtils.generateSleighExpression(addrOf.offset()));
	}

	@Test
	public void testRecoverAddressOfForm3() {
		AddressOf addrOf = SleighUtils.recoverAddressOf(null, "*[ram]:8 ptr");
		assertEquals("ram", addrOf.space());
		assertEquals("ptr", SleighUtils.generateSleighExpression(addrOf.offset()));
	}

	@Test
	public void testRecoverConditionEqDec() {
		assertEquals("RAX == 0",
			SleighUtils.recoverConditionFromBreakpoint("""
					if !(RAX == 0) goto <L1>;
					  emu_swi();
					<L1>
					emu_exec_decoded();
					"""));
	}

	@Test
	public void testRecoverConditionNeqHex() {
		assertEquals("RAX != 0x3",
			SleighUtils.recoverConditionFromBreakpoint("""
					if RAX == 0x3 goto <L1>;
					  emu_swi();
					<L1>
					emu_exec_decoded();
					"""));
	}

	@Test
	public void testRecoverConditionUserop() {
		assertEquals("userop(a, b, c)",
			SleighUtils.recoverConditionFromBreakpoint("""
					if !(userop(a,b,c)) goto <L1>;
					  emu_swi();
					<L1>
					emu_exec_decoded();
					"""));
	}

	@Test
	public void testRecoverConditionAddition() {
		assertEquals("RAX + RBX + RCX == 0",
			SleighUtils.recoverConditionFromBreakpoint("""
					if RAX + RBX + RCX != 0 goto <L1>;
					  emu_swi();
					<L1>
					emu_exec_decoded();
					"""));
	}

	@Test
	public void testRecoverConditionDeref() {
		assertEquals("*RAX == 0",
			SleighUtils.recoverConditionFromBreakpoint("""
					if *RAX != 0 goto <L1>;
					  emu_swi();
					<L1>
					emu_exec_decoded();
					"""));
	}

	@Test
	public void testRecoverConditionSizedDeref() {
		assertEquals("*:4 RAX == 0",
			SleighUtils.recoverConditionFromBreakpoint("""
					if *:4 RAX != 0 goto <L1>;
					  emu_swi();
					<L1>
					emu_exec_decoded();
					"""));
	}

	@Test
	public void testRecoverConditionSpacedSizedDeref() {
		assertEquals("*[ram]:4 RAX == 0",
			SleighUtils.recoverConditionFromBreakpoint("""
					if *[ram]:4 RAX != 0 goto <L1>;
					  emu_swi();
					<L1>
					emu_exec_decoded();
					"""));
	}

	@Test
	public void testRecoverConditionSpacedDeref() {
		assertEquals("*[ram] RAX == 0",
			SleighUtils.recoverConditionFromBreakpoint("""
					if *[ram] RAX != 0 goto <L1>;
					  emu_swi();
					<L1>
					emu_exec_decoded();
					"""));
	}

	@Test
	public void testRecoverConditionSizedAddressOf() {
		assertEquals("&:8 RAX == 0",
			SleighUtils.recoverConditionFromBreakpoint("""
					if &:8 RAX != 0 goto <L1>;
					  emu_swi();
					<L1>
					emu_exec_decoded();
					"""));
	}

	@Test
	public void testRecoverConditionAddressOf() {
		assertEquals("&RAX == 0",
			SleighUtils.recoverConditionFromBreakpoint("""
					if &RAX != 0 goto <L1>;
					  emu_swi();
					<L1>
					emu_exec_decoded();
					"""));
	}

	@Test
	public void testRecoverConditionSizedConst() {
		assertEquals("!(1:1)",
			SleighUtils.recoverConditionFromBreakpoint("""
					if 1:1 goto <L1>;
					  emu_swi();
					<L1>
					emu_exec_decoded();
					"""));
	}

	@Test
	public void testRecoverConditionNotSizedConst() {
		assertEquals("1:1",
			SleighUtils.recoverConditionFromBreakpoint("""
					if !(1:1) goto <L1>;
					  emu_swi();
					<L1>
					emu_exec_decoded();
					"""));
	}

	@Test
	public void testRecoverConditionBitRange() {
		assertEquals("RAX[0,1]",
			SleighUtils.recoverConditionFromBreakpoint("""
					if !(RAX[0,1]) goto <L1>;
					  emu_swi();
					<L1>
					emu_exec_decoded();
					"""));
	}

	@Test
	public void testRecoverConditionBitRange2() {
		assertEquals("RAX:4",
			SleighUtils.recoverConditionFromBreakpoint("""
					if !(RAX:4) goto <L1>;
					  emu_swi();
					<L1>
					emu_exec_decoded();
					"""));
	}

	@Test
	public void testRecoverConditionAlways() {
		assertEquals("1:1",
			SleighUtils.recoverConditionFromBreakpoint("""
					emu_swi();
					emu_exec_decoded();
					"""));
	}

	@Test
	public void testParseSleighExpression() throws RecognitionException {
		assertEquals("(|| (== (IDENTIFIER RAX) (DEC_INT 0)) (== (IDENTIFIER RBX) (DEC_INT 7)))",
			SleighUtils.parseSleighExpression("RAX == 0 || RBX == 7").toStringTree());
	}

	@Test
	public void testParseSleighExpressionErr() throws RecognitionException {
		try {
			SleighUtils.parseSleighExpression("RAX RBX RCX");
			fail();
		}
		catch (SleighParseError e) {
			assertEquals("""
					sleigh line 1: no viable alternative on IDENTIFIER: 'RBX':

					RAX RBX RCX
					----^
					""", e.getMessage());
		}
	}

	@Test
	public void testParseSleighExpressionTooMuch() throws RecognitionException {
		try {
			SleighUtils.parseSleighExpression("RAX == 0;");
			fail();
		}
		catch (SleighParseError e) {
			assertEquals("""
					sleigh line 1: extraneous input ';' expecting EOF:

					RAX == 0;
					--------^
					""", e.getMessage());
		}
	}

	@Test
	public void testParseSleighExpressionTooLittle() throws RecognitionException {
		try {
			SleighUtils.parseSleighExpression("RAX ==");
			fail();
		}
		catch (SleighParseError e) {
			assertEquals("""
					sleigh line 1: no viable alternative on SEMI: ';':

					RAX ==
					------^
					""", e.getMessage());
		}
	}

	@Test
	public void testSleighForConditionalBreakpointAlways() throws RecognitionException {
		assertEquals("""
				emu_swi();
				emu_exec_decoded();
				""", SleighUtils.sleighForConditionalBreak("1:1"));
	}

	@Test
	public void testSleighForConditionalBreakpoint() throws RecognitionException {
		assertEquals("""
				if RAX != 0 goto <L1>;
				  emu_swi();
				<L1>
				emu_exec_decoded();
				""", SleighUtils.sleighForConditionalBreak("RAX == 0"));
	}
}
