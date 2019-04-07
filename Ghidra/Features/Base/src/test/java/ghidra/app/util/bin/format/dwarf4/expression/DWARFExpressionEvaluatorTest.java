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
package ghidra.app.util.bin.format.dwarf4.expression;

import static ghidra.app.util.bin.format.dwarf4.expression.DWARFExpressionOpCodes.*;
import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.*;

import ghidra.app.util.bin.format.dwarf4.DWARFCompilationUnit;
import ghidra.app.util.bin.format.dwarf4.next.DWARFRegisterMappings;

public class DWARFExpressionEvaluatorTest {

	DWARFExpressionEvaluator evaluator;

	@Before
	public void setup() {
		evaluator = new DWARFExpressionEvaluator((byte) 8, true, DWARFCompilationUnit.DWARF_32,
			DWARFRegisterMappings.DUMMY);
	}

	/**
	 * Test {@link DWARFExpressionEvaluator} by executing a expr that calculates
	 * the fibonacci series.
	 *
	 * @throws IOException
	 * @throws DWARFExpressionException
	 */
	@Test
	public void fibTest() throws IOException, DWARFExpressionException {
		// calculates the Nth fibonacci number
		// @formatter:off
		DWARFExpression expr = evaluator.readExpr(
			new byte[] {
				DW_OP_lit0,
				DW_OP_lit1,
				DW_OP_rot,
				DW_OP_rot,
				DW_OP_lit1,
				DW_OP_minus,
				DW_OP_dup,
				DW_OP_lit0,
				DW_OP_eq,
				DW_OP_bra, 0xc, 0,
				DW_OP_rot,
				DW_OP_dup,
				DW_OP_rot,
				DW_OP_plus,
				DW_OP_rot,
				DW_OP_rot,
				DW_OP_skip, (byte)0xf2, (byte) 0xff,
				DW_OP_drop,
				DW_OP_swap,
				DW_OP_drop
			});
		// @formatter:on

		long result = evaluator.evaluate(expr, 19).pop();
		assertEquals("Fibonacci[19] should be 4181", 4181, result);
	}

	/**
	 * Test reading (but not executing) an expression that has every opcode
	 * that takes operands.  Operands that are signed vs unsigned are present in
	 * byte patterns that exercise high-bit set vs. not set.
	 * @throws IOException
	 */
	@Test
	public void testReadingAllOpCodesWithArgs() throws DWARFExpressionException {
		// @formatter:off
		DWARFExpression expr =
			evaluator.readExpr(new byte[] {
			/* 0 */ DW_OP_addr, 1, 2, 3, 4, 5, 6, 7, 8,

			/* 1 */ DW_OP_const1u, (byte)0x55,
			/* 2 */ DW_OP_const1u, (byte)0xfe,

			/* 3 */ DW_OP_const1s, (byte)0x55,
			/* 4 */ DW_OP_const1s, (byte) 0xfe, // -2

			/* 5 */ DW_OP_const2u, (byte)0x55, (byte)0x55,
			/* 6 */ DW_OP_const2u, (byte)0xf0, (byte)0xf0,

			/* 7 */ DW_OP_const2s, (byte)0x55, (byte)0x55,
			/* 8 */ DW_OP_const2s, (byte)0xf0, (byte)0xf0, // -3856

			/* 9 */ DW_OP_const4u, (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55,
			/* 10 */ DW_OP_const4u, (byte)0xf0, (byte)0xf0, (byte)0xf0, (byte)0xf0,

			/* 11 */ DW_OP_const4s, (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55,
			/* 12 */ DW_OP_const4s, (byte) 0xf0, (byte) 0xf0, (byte) 0xf0, (byte) 0xf0, // -252645136

			/* 13 */ DW_OP_const8u, (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55,
			/* 14 */ DW_OP_const8u, (byte)0xf0, (byte)0xf0, (byte)0xf0, (byte)0xf0, (byte)0xf0, (byte)0xf0, (byte)0xf0, (byte)0xf0,

			/* 15 */ DW_OP_const8s, (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55,
			/* 16 */ DW_OP_const8s, (byte)0xf0, (byte)0xf0, (byte)0xf0, (byte)0xf0, (byte)0xf0, (byte)0xf0, (byte)0xf0, (byte)0xf0,

			/* 17 */ DW_OP_constu, (byte)0x55,
			/* 18 */ DW_OP_constu, (byte)0x80, (byte)0x01,	// == 128
			/* 19 */ DW_OP_constu, (byte)0x80, (byte)0x7f,	// == 16256

			/* 20 */ DW_OP_consts, (byte)0x33,
			/* 21 */ DW_OP_consts, (byte)0x80, (byte)0x01, // == 128
			/* 22 */ DW_OP_consts, (byte)0x80, (byte)0x7f, // == -128

			/* 23 */ DW_OP_pick, (byte)0x04,
			/* 24 */ DW_OP_pick, (byte)0xf0,

			/* 25 */ DW_OP_plus_uconst, (byte)0x80, (byte)0x01,
			/* 26 */ DW_OP_plus_uconst, (byte)0xbf, (byte)0x01,	// == 191

			/* 27 */ DW_OP_skip, (byte)0x05, (byte)0x05,
			/* 28 */ DW_OP_skip, (byte)0xf0, (byte)0xf0,

			/* 29 */ DW_OP_bra, (byte)0x05, (byte)0x05,
			/* 30 */ DW_OP_bra, (byte)0xf0, (byte)0xf0,

			/* 31 */ DW_OP_breg0, (byte) 0x0a,
			/* 32 */ DW_OP_breg0, (byte)0x80, (byte)0x01,	// == ????

			/* 33 */ (byte)DW_OP_breg31, (byte)0x55,
			/* 34 */ (byte)DW_OP_breg31, (byte)0x80, (byte)0x01,	// == ????

			/* 35 */ (byte)DW_OP_regx, (byte)0x55,
			/* 36 */ (byte)DW_OP_regx, (byte)0x80, (byte)0x01,	// == ????

			/* 37 */ (byte)DW_OP_fbreg, (byte)0x55,
			/* 38 */ (byte)DW_OP_fbreg, (byte)0x80, (byte)0x01,	// == ????

			/* 39 */ (byte)DW_OP_bregx, (byte)0x55, (byte)0x44,
			/* 40 */ (byte)DW_OP_bregx, (byte)0x55, (byte)0x80, (byte)0x01,

			/* 41 */ (byte)DW_OP_piece, (byte)0x55,
			/* 42 */ (byte)DW_OP_piece, (byte)0x80, (byte)0x01,	// == 191

			/* 43 */ (byte)DW_OP_deref_size, (byte)0x55,
			/* 44 */ (byte)DW_OP_deref_size, (byte)0xf0,

			/* 45 */ (byte)DW_OP_xderef_size, (byte)0x55,
			/* 46 */ (byte)DW_OP_xderef_size, (byte)0xf0,

			/* 47 */ (byte)DW_OP_call2, (byte)0x55, (byte)0x55,
			/* 48 */ (byte)DW_OP_call2, (byte)0xf0, (byte)0xf0,

			/* 49 */ (byte)DW_OP_call4, (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55,
			/* 50 */ (byte)DW_OP_call4, (byte)0xf0, (byte)0xf0, (byte)0xf0, (byte)0xf0,

			/* 51 */ (byte)DW_OP_bit_piece, (byte)0x55, (byte)0x55,
			/* 52 */ (byte)DW_OP_bit_piece, (byte)0x80, (byte)0x01, (byte)0x81, (byte)0x01,

			/* 53 */ (byte) DW_OP_call_ref, 4, 3, 2, 1,

			/* 54 */ (byte) DW_OP_implicit_value, (byte) 0x05, 1, 2, 3, 4, 5//
		});
		// @formatter:on

		assertNotNull("Did not successfully instantiate DWARFExpression", expr);
		assertEquals("Did not read all opcodes", 55, expr.getOpCount());

		assertEquals(0x55, expr.getOp(1).getOperandValue(0));
		assertEquals(0xfe, expr.getOp(2).getOperandValue(0));

		assertEquals(0x55, expr.getOp(3).getOperandValue(0));
		assertEquals(-2, expr.getOp(4).getOperandValue(0));

		assertEquals(0x5555, expr.getOp(5).getOperandValue(0));
		assertEquals(0xf0f0, expr.getOp(6).getOperandValue(0));

		assertEquals(0x5555, expr.getOp(7).getOperandValue(0));
		assertEquals(-3856, expr.getOp(8).getOperandValue(0));

		assertEquals(0x55555555, expr.getOp(9).getOperandValue(0));
		assertEquals(0xf0f0f0f0L, expr.getOp(10).getOperandValue(0));

		assertEquals(0x55555555, expr.getOp(11).getOperandValue(0));
		assertEquals(-252645136, expr.getOp(12).getOperandValue(0));

		assertEquals(0x5555555555555555L, expr.getOp(13).getOperandValue(0));
		assertEquals(0xf0f0f0f0f0f0f0f0L, expr.getOp(14).getOperandValue(0));

		assertEquals(0x5555555555555555L, expr.getOp(15).getOperandValue(0));
		assertEquals(0xf0f0f0f0f0f0f0f0L, expr.getOp(16).getOperandValue(0));

		assertEquals(0x55, expr.getOp(17).getOperandValue(0));
		assertEquals(128, expr.getOp(18).getOperandValue(0));
		assertEquals(16256, expr.getOp(19).getOperandValue(0));

		assertEquals(0x33, expr.getOp(20).getOperandValue(0));
		assertEquals(128, expr.getOp(21).getOperandValue(0));
		assertEquals(-128, expr.getOp(22).getOperandValue(0));
	}

	@Test
	public void test_DW_OP_pick() throws DWARFExpressionException {

		int count = 200;
		for (int i = 0; i < count; i++) {
			evaluator.push(i * 3);
		}
		for (int i = 0; i < count; i++) {
			long expected = (count - i - 1) * 3;
			evaluator.evaluate(new byte[] { DW_OP_pick, (byte) i });
			long result = evaluator.pop();
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
			evaluator.evaluate(new byte[] { DW_OP_pick, (byte) (count + 1) });
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
		evaluator.evaluate(new byte[] { DW_OP_over });
		assertEquals(10, evaluator.pop());
	}

	@Test
	public void test_DW_OP_over_OOB() throws DWARFExpressionException {
		DWARFExpression expr = evaluator.readExpr(new byte[] { DW_OP_over });

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
		DWARFExpression expr =
			evaluator.readExpr(new byte[] { (byte) DW_OP_fbreg, 0x48, DW_OP_deref });

		evaluator.setFrameBase(0);
		evaluator.evaluate(expr);
		assertTrue(evaluator.isDeref());
	}

	/**
	 * Test to ensure that non-terminal DW_OP_deref opcodes trigger an exception.
	 * @throws IOException
	 */
	@Test
	public void test_DW_OP_deref_nonterm() throws DWARFExpressionException {
		DWARFExpression expr =
			evaluator.readExpr(new byte[] { (byte) DW_OP_fbreg, 0x48, DW_OP_deref, DW_OP_dup });

		try {
			evaluator.setFrameBase(0);
			evaluator.evaluate(expr);
			fail("Should not get here");
		}
		catch (DWARFExpressionException dee) {
			// good
		}
	}

	/**
	 * Test to ensure that non-terminal DW_OP_reg[?] opcodes trigger an exception
	 * when evaluating.
	 *
	 * @throws IOException
	 * @throws DWARFExpressionException
	 */
	@Test
	public void test_DW_OP_regx_nonterm() throws IOException, DWARFExpressionException {

		DWARFExpression expr1 = evaluator.readExpr(new byte[] { (byte) DW_OP_reg0, DW_OP_dup });
		DWARFExpression expr2 =
			evaluator.readExpr(new byte[] { (byte) DW_OP_regx, (byte) 0x01, DW_OP_dup });

		try {
			evaluator.evaluate(expr1);
			fail("Should not get here");
		}
		catch (DWARFExpressionException dee) {
			// good
		}

		try {
			evaluator.evaluate(expr2);
			fail("Should not get here");
		}
		catch (DWARFExpressionException dee) {
			// good
		}
	}

	/**
	 * Test to ensure that endless loops or excessive runtime are prevented by
	 * {@link DWARFExpressionEvaluator#setMaxStepCount(int) maxStepCount}
	 * <p>
	 * @throws IOException
	 */
	@Test(timeout = 10000)
	public void testExcessiveExprLength() throws DWARFExpressionException {
		// Endless loop: nop, skip -1.
		DWARFExpression expr = evaluator.readExpr(
			new byte[] { (byte) DW_OP_nop, (byte) DW_OP_skip, (byte) 0xff, (byte) 0xff, });
		try {
			evaluator.evaluate(expr);
			fail(
				"DWARFExpressionEvaluator should have thrown an exception because of the length of the expression, " +
					"but you are probably not reading this message because junit can't get here because of the endless loop in the expr.");
		}
		catch (DWARFExpressionException dee) {
			// good
		}

	}

	/**
	 * Test to ensure that endless loops are ended when the thread is interrupted.
	 * <p>
	 * @throws IOException
	 */
	@Test(timeout = 10000)
	public void testThreadIntr() throws DWARFExpressionException {
		// Endless loop: nop, skip -1.
		DWARFExpression expr = evaluator.readExpr(
			new byte[] { (byte) DW_OP_nop, (byte) DW_OP_skip, (byte) 0xff, (byte) 0xff, });

		final Thread junitThread = Thread.currentThread();
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
			evaluator.evaluate(expr);
			fail(
				"DWARFExpressionEvaluator should have thrown an exception because it recieved an interrupt, " +
					"but you are probably not reading this message because junit can't get here because of the endless loop in the expr.");
		}
		catch (DWARFExpressionException dee) {
			// good
		}
	}

	@Test
	public void testBadExpr() {
		try {
			DWARFExpression expr =
				evaluator.readExpr(new byte[] { DW_OP_addr, 1, 2, 3, 4, 5, 6, 7, 8, DW_OP_const1u,
					(byte) 0x55, DW_OP_const1u, (byte) 0xfe, DW_OP_addr, 1, 2 /* truncated */ });
			fail(
				"readExpr should have thrown an exception because the expr's final op was truncated: " +
					expr.toString());
		}
		catch (DWARFExpressionException dee) {
			// Should have been able to read 3 of the operations before failing
			Assert.assertEquals(dee.getExpression().getOpCount(), 3);
		}
	}
}
