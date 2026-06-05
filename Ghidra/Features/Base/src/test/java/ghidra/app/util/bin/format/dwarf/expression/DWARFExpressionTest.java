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

import org.junit.*;

import ghidra.app.util.bin.format.dwarf.DWARFTestBase;

public class DWARFExpressionTest extends DWARFTestBase {

	DWARFExpressionEvaluator evaluator;

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		ensureCompUnit();
		evaluator = new DWARFExpressionEvaluator(cu);
	}

	/**
	 * Test reading (but not executing) an expression that has every opcode
	 * that takes operands.  Operands that are signed vs unsigned are present in
	 * byte patterns that exercise high-bit set vs. not set.
	 * @throws DWARFExpressionException if error
	 */
	@Test
	public void testReadingAllOpCodesWithArgs() throws DWARFExpressionException {
		// @formatter:off
		DWARFExpression expr = expr(
			/* 0 */ instr(DW_OP_addr, 1, 2, 3, 4, 5, 6, 7, 8),

			/* 1 */ instr(DW_OP_const1u, 0x55),
			/* 2 */ instr(DW_OP_const1u, 0xfe),

			/* 3 */ instr(DW_OP_const1s, 0x55),
			/* 4 */ instr(DW_OP_const1s, 0xfe), // -2

			/* 5 */ instr(DW_OP_const2u, 0x55, 0x55),
			/* 6 */ instr(DW_OP_const2u, 0xf0, 0xf0),

			/* 7 */ instr(DW_OP_const2s, 0x55, 0x55),
			/* 8 */ instr(DW_OP_const2s, 0xf0, 0xf0), // -3856

			/* 9 */ instr(DW_OP_const4u, 0x55, 0x55, 0x55, 0x55),
			/* 10 */ instr(DW_OP_const4u, 0xf0, 0xf0, 0xf0, 0xf0),

			/* 11 */ instr(DW_OP_const4s, 0x55, 0x55, 0x55, 0x55),
			/* 12 */ instr(DW_OP_const4s,  0xf0,  0xf0,  0xf0,  0xf0), // -252645136

			/* 13 */ instr(DW_OP_const8u, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55),
			/* 14 */ instr(DW_OP_const8u, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0),

			/* 15 */ instr(DW_OP_const8s, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55),
			/* 16 */ instr(DW_OP_const8s, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0),

			/* 17 */ instr(DW_OP_constu, 0x55),
			/* 18 */ instr(DW_OP_constu, uleb128(128)),
			/* 19 */ instr(DW_OP_constu, uleb128(16256)),

			/* 20 */ instr(DW_OP_consts, sleb128(0x33)),
			/* 21 */ instr(DW_OP_consts, sleb128(128)),
			/* 22 */ instr(DW_OP_consts, sleb128(-128)),

			/* 23 */ instr(DW_OP_pick, 0x04),
			/* 24 */ instr(DW_OP_pick, 0xf0),

			/* 25 */ instr(DW_OP_plus_uconst, uleb128(128)),
			/* 26 */ instr(DW_OP_plus_uconst, uleb128(191)),

			/* 27 */ instr(DW_OP_skip, 0x05, 0x05),
			/* 28 */ instr(DW_OP_skip, 0xf0, 0xf0),

			/* 29 */ instr(DW_OP_bra, 0x05, 0x05),
			/* 30 */ instr(DW_OP_bra, 0xf0, 0xf0),

			/* 31 */ instr(DW_OP_breg0, sleb128(10)),
			/* 32 */ instr(DW_OP_breg0, sleb128(128)),

			/* 33 */ instr(DW_OP_breg31, sleb128(12)),
			/* 34 */ instr(DW_OP_breg31, sleb128(128)),

			/* 35 */ instr(DW_OP_regx, sleb128(12)),
			/* 36 */ instr(DW_OP_regx, sleb128(128)),

			/* 37 */ instr(DW_OP_fbreg, sleb128(8)),
			/* 38 */ instr(DW_OP_fbreg, sleb128(85)),

			/* 39 */ instr(DW_OP_bregx, 0x55, 0x44),
			/* 40 */ instr(DW_OP_bregx, 0x55, 0x80, 0x01),

			/* 41 */ instr(DW_OP_piece, uleb128(128)),
			/* 42 */ instr(DW_OP_piece, uleb128(191)),

			/* 43 */ instr(DW_OP_deref_size, 0x55),
			/* 44 */ instr(DW_OP_deref_size, 0xf0),

			/* 45 */ instr(DW_OP_xderef_size, 0x55),
			/* 46 */ instr(DW_OP_xderef_size, 0xf0),

			/* 47 */ instr(DW_OP_call2, 0x55, 0x55),
			/* 48 */ instr(DW_OP_call2, 0xf0, 0xf0),

			/* 49 */ instr(DW_OP_call4, 0x55, 0x55, 0x55, 0x55),
			/* 50 */ instr(DW_OP_call4, 0xf0, 0xf0, 0xf0, 0xf0),

			/* 51 */ instr(DW_OP_bit_piece, 0x55, 0x55),
			/* 52 */ instr(DW_OP_bit_piece, 0x80, 0x01, 0x81, 0x01),

			/* 53 */ instr(DW_OP_call_ref, 4, 3, 2, 1),

			/* 54 */ instr( DW_OP_implicit_value,  0x05, 1, 2, 3, 4, 5),
			
			/* 55 */ instr( DW_OP_implicit_pointer, 1, 0, 0, 0, 2),
			
			/* 56 */ instr( DW_OP_addrx, 0)
		);
		// @formatter:on

		assertEquals(4, evaluator.getDWARFCompilationUnit().getIntSize());
		assertNotNull("Did not successfully instantiate DWARFExpression", expr);
		assertEquals("Did not read all instructions", 57, expr.getInstructionCount());

		assertEquals(0x55, expr.getInstruction(1).getOperandValue(0));
		assertEquals(0xfe, expr.getInstruction(2).getOperandValue(0));

		assertEquals(0x55, expr.getInstruction(3).getOperandValue(0));
		assertEquals(-2, expr.getInstruction(4).getOperandValue(0));

		assertEquals(0x5555, expr.getInstruction(5).getOperandValue(0));
		assertEquals(0xf0f0, expr.getInstruction(6).getOperandValue(0));

		assertEquals(0x5555, expr.getInstruction(7).getOperandValue(0));
		assertEquals(-3856, expr.getInstruction(8).getOperandValue(0));

		assertEquals(0x55555555, expr.getInstruction(9).getOperandValue(0));
		assertEquals(0xf0f0f0f0L, expr.getInstruction(10).getOperandValue(0));

		assertEquals(0x55555555, expr.getInstruction(11).getOperandValue(0));
		assertEquals(-252645136, expr.getInstruction(12).getOperandValue(0));

		assertEquals(0x5555555555555555L, expr.getInstruction(13).getOperandValue(0));
		assertEquals(0xf0f0f0f0f0f0f0f0L, expr.getInstruction(14).getOperandValue(0));

		assertEquals(0x5555555555555555L, expr.getInstruction(15).getOperandValue(0));
		assertEquals(0xf0f0f0f0f0f0f0f0L, expr.getInstruction(16).getOperandValue(0));

		assertEquals(0x55, expr.getInstruction(17).getOperandValue(0));
		assertEquals(128, expr.getInstruction(18).getOperandValue(0));
		assertEquals(16256, expr.getInstruction(19).getOperandValue(0));

		assertEquals(0x33, expr.getInstruction(20).getOperandValue(0));
		assertEquals(128, expr.getInstruction(21).getOperandValue(0));
		assertEquals(-128, expr.getInstruction(22).getOperandValue(0));

		assertEquals(5, expr.getInstruction(54).getOperandValue(0));

		assertEquals(1, expr.getInstruction(55).getOperandValue(0));
		assertEquals(2, expr.getInstruction(55).getOperandValue(1));
	}

	@Test
	public void testBadExpr() {
		try {
			DWARFExpression expr = expr(
				instr(DW_OP_addr, 1, 2, 3, 4, 5, 6, 7, 8), // instr 0 
				instr(DW_OP_const1u, 0x55), // instr 1
				instr(DW_OP_const1u, 0xfe), // instr 2
				instr(DW_OP_addr, 1, 2) // instr 3, truncated
			);
			fail(
				"readExpr should have thrown an exception because the expr's final op was truncated: " +
					expr.toString());
		}
		catch (DWARFExpressionException dee) {
			// Should have been able to read 3 of the operations before failing
			Assert.assertEquals(dee.getExpression().getInstructionCount(), 3);
		}
	}

	@Test
	public void testUnknownOpCode() {
		try {
			DWARFExpression expr = expr(new byte[] { (byte) 0xf0, 1, 2, 3 });
			fail(
				"readExpr should have thrown an exception because the expr's final op was truncated: " +
					expr.toString());
		}
		catch (DWARFExpressionException dee) {
			DWARFExpression expr = dee.getExpression();
			assertEquals(1, expr.getInstructionCount());
			assertEquals(DW_OP_unknown_opcode, expr.getInstruction(0).getOpCode());
		}
	}

	@Test
	public void test_DW_OP_addr_ExprRep() throws DWARFExpressionException {
		assertEquals("DW_OP_addr: 807060504030201",
			expr(instr(DW_OP_addr, 1, 2, 3, 4, 5, 6, 7, 8)).toString());
		assertEquals("DW_OP_addr: d0c0b0a",
			expr(instr(DW_OP_addr, 0xa, 0xb, 0xc, 0xd, 0, 0, 0, 0)).toString());
	}

	@Test
	public void test_DW_OP_fbreg_ExprRep() throws DWARFExpressionException {
		// instructions with operands that are signed should show a "+" for positive values 
		assertEquals("DW_OP_fbreg: -48", expr(instr(DW_OP_fbreg, sleb128(-48))).toString());
		assertEquals("DW_OP_fbreg: -120", expr(instr(DW_OP_fbreg, sleb128(-120))).toString());
		assertEquals("DW_OP_fbreg: +120", expr(instr(DW_OP_fbreg, sleb128(120))).toString());
		assertEquals("DW_OP_fbreg: 0", expr(instr(DW_OP_fbreg, sleb128(0))).toString());
	}

	@Test
	public void test_DW_OP_const_ExprRep() throws DWARFExpressionException {
		assertEquals("DW_OP_const1s: -1", expr(instr(DW_OP_const1s, 0xff)).toString());
		assertEquals("DW_OP_const1s: +5", expr(instr(DW_OP_const1s, 0x5)).toString());
		assertEquals("DW_OP_const1s: 0", expr(instr(DW_OP_const1s, 0)).toString());

		assertEquals("DW_OP_const1u: 255", expr(instr(DW_OP_const1u, 0xff)).toString());
	}
}
