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
package ghidra.app.util.bin.format.dwarf.expression;

import static ghidra.app.util.bin.format.dwarf.expression.DWARFExpressionOpCode.*;
import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.util.bin.format.dwarf.DWARFTestBase;
import ghidra.program.model.scalar.Scalar;

public class DWARFExpressionEvaluatorTest extends DWARFTestBase {

	DWARFExpressionEvaluator evaluator;

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		ensureCompUnit();
		evaluator = new DWARFExpressionEvaluator(cu);
	}

	@Test
	public void fibTest() throws IOException, DWARFExpressionException {
		// Test by executing a expr that calculates the fibonacci series.
		// Calculates the Nth fibonacci number, with N being pushed on stack as 'arg' to the
		// expression, result left on stack.
		// @formatter:off
		DWARFExpression expr = expr(
				instr(DW_OP_lit0),
				instr(DW_OP_lit1),
				instr(DW_OP_rot),
				instr(DW_OP_rot),
				instr(DW_OP_lit1),
				instr(DW_OP_minus),
				instr(DW_OP_dup),
				instr(DW_OP_lit0),
				instr(DW_OP_eq),
				instr(DW_OP_bra, 0xc, 0),
				instr(DW_OP_rot),
				instr(DW_OP_dup),
				instr(DW_OP_rot),
				instr(DW_OP_plus),
				instr(DW_OP_rot),
				instr(DW_OP_rot),
				instr(DW_OP_skip, 0xf2, 0xff),
				instr(DW_OP_drop),
				instr(DW_OP_swap),
				instr(DW_OP_drop)
		);
		// @formatter:on

		evaluator.evaluate(expr, 19);
		long result = evaluator.popLong();
		assertEquals("Fibonacci[19] should be 4181", 4181, result);
	}

	@Test
	public void test_DW_OP_pick() throws DWARFExpressionException {

		int count = 200;
		for (int i = 0; i < count; i++) {
			evaluator.push(i * 3);
		}
		for (int i = 0; i < count; i++) {
			long expected = (count - i - 1) * 3;
			evaluator.evaluate(instr(DW_OP_pick, i));
			long result = evaluator.popLong();
			assertEquals(expected, result);
		}

	}

	@Test
	public void test_DW_OP_pick_OOB() {
		int count = 200;
		for (int i = 0; i < count; i++) {
			evaluator.push(i * 3);
		}

		try {
			evaluator.evaluate(instr(DW_OP_pick, (byte) (count + 1)));
			fail("Should not get here");
		}
		catch (DWARFExpressionException e) {
			// good
		}
	}

	@Test
	public void test_DW_OP_over() throws DWARFExpressionException {
		evaluator.push(10);
		evaluator.push(20);
		evaluator.evaluate(instr(DW_OP_over));
		assertEquals(10, evaluator.popLong());
	}

	@Test
	public void test_DW_OP_over_OOB() throws DWARFExpressionException {
		DWARFExpression expr = expr(instr(DW_OP_over));

		try {
			evaluator.evaluate(expr);
			fail("Should not get here");
		}
		catch (DWARFExpressionException e) {
			// good
		}

		try {
			evaluator.push(1);
			evaluator.evaluate(expr);
			fail("Should not get here");
		}
		catch (DWARFExpressionException e) {
			// good
		}
	}

	@Test
	public void test_DW_OP_deref() throws DWARFExpressionException {

		try {
			evaluator.setFrameBaseStackLocation(0);
			evaluator.evaluate(expr(instr(DW_OP_fbreg, 0x48), instr(DW_OP_deref)));
			fail();
		}
		catch (DWARFExpressionUnsupportedOpException e) {
			assertEquals(DW_OP_deref, e.getInstruction().getOpCode());
		}
	}

	@Test
	public void test_DW_OP_deref_nonterm() throws DWARFExpressionException {
		// Test to ensure that non-terminal DW_OP_deref opcodes trigger an exception.
		try {
			evaluator.setFrameBaseStackLocation(0);
			evaluator
					.evaluate(expr(instr(DW_OP_fbreg, 0x48), instr(DW_OP_deref), instr(DW_OP_dup)));
			fail("Should not get here");
		}
		catch (DWARFExpressionUnsupportedOpException e) {
			assertEquals(DW_OP_deref, e.getInstruction().getOpCode());
		}
	}

	@Test
	public void test_DW_OP_regx_nonterm() {
		// Test to ensure that non-terminal DW_OP_reg[?] opcodes trigger an exception
		// when evaluating.
		try {
			evaluator.evaluate(expr(instr(DW_OP_reg0), instr(DW_OP_neg)));
			fail("Should not get here");
		}
		catch (DWARFExpressionException dee) {
			// good
		}

		try {
			evaluator.evaluate(expr(instr(DW_OP_regx, 0x01), instr(DW_OP_neg)));
			fail("Should not get here");
		}
		catch (DWARFExpressionException dee) {
			// good
		}
	}

	@Test
	public void test_DW_OP_regx_callback() throws DWARFExpressionException {
		evaluator.setValReader(vn -> new Scalar(64, 0x10000));
		evaluator.evaluate(expr(instr(DW_OP_reg0), instr(DW_OP_neg)));
		long result = evaluator.popLong();
		assertEquals(-0x10000, result);
	}

	@Test
	public void test_DW_OP_breg_callback() throws DWARFExpressionException {
		evaluator.setValReader(vn -> new Scalar(64, 0x10000));
		evaluator.evaluate(expr(instr(DW_OP_breg0, sleb128(-100)), instr(DW_OP_neg)));
		long result = evaluator.popLong();
		assertEquals(-(0x10000 - 100), result);
	}

	@Test(timeout = 10000)
	public void testExcessiveExprLength() {
		// Test to ensure that endless loops or excessive runtime are prevented by
		// DWARFExpressionEvaluator.setMaxStepCount(int) maxStepCount
		try {
			// Endless loop: nop, skip -1.
			evaluator.evaluate(expr(instr(DW_OP_nop), instr(DW_OP_skip, 0xff, 0xff)));
			fail(
				"DWARFExpressionEvaluator should have thrown an exception because of the length of the expression, " +
					"but you are probably not reading this message because junit can't get here because of the endless loop in the expr.");
		}
		catch (DWARFExpressionException dee) {
			// good
		}
	}

	@Test(timeout = 10000)
	public void testThreadIntr() {
		// Test to ensure that endless loops are ended when the thread is interrupted.
		Thread junitThread = Thread.currentThread();
		Thread intrThread = new Thread(() -> {
			try {
				Thread.sleep(500);
			}
			catch (Exception e) {
				return;
			}
			junitThread.interrupt();
		});
		intrThread.start();

		try {
			evaluator.setMaxStepCount(Integer.MAX_VALUE);

			// Endless loop: nop, skip -1.
			evaluator.evaluate(expr(instr(DW_OP_nop), instr(DW_OP_skip, 0xff, 0xff)));

			fail(
				"DWARFExpressionEvaluator should have thrown an exception because it recieved an interrupt, " +
					"but you are probably not reading this message because junit can't get here because of the endless loop in the expr.");
		}
		catch (DWARFExpressionException dee) {
			// good
		}
	}

	@Test
	public void testAddrx() {
		// test that OP_addrx fails with invalid index.  Needs real test
		try {
			evaluator.evaluate(expr(instr(DW_OP_addrx, 0)));
			fail();
		}
		catch (DWARFExpressionException dee) {
			// good
		}
	}

	@Test
	public void testConstx() {
		// test that OP_constx fails with invalid index.  Needs real test
		try {
			evaluator.evaluate(expr(instr(DW_OP_constx, 0)));
			fail();
		}
		catch (DWARFExpressionException dee) {
			// good
		}

	}
}
