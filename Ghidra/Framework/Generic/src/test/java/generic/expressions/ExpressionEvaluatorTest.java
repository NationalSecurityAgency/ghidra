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
package generic.expressions;

import static org.junit.Assert.*;

import org.junit.Test;

public class ExpressionEvaluatorTest {

	@Test
	public void testUnaryPlus() {
		assertEval(100, "+100");
	}

	@Test
	public void testUnaryMinus() {
		assertEval(-100, "-100");
	}

	@Test
	public void testAdd() {
		assertEval(100, "20+10 +   70");
	}

	@Test
	public void testSubtract() {
		assertEval(5, "20-10-5");
		assertEval(5, "20-5-10");
	}

	@Test
	public void testMultiply() {
		assertEval(42, "2*3*7");
	}

	@Test
	public void testDivide() {
		assertEval(1, "8/4/2");
		assertEval(1, "5/4");
	}

	@Test
	public void testShiftLeft() {
		assertEval(4, "16>>2");
	}

	@Test
	public void testShiftRight() {
		assertEval(8, "1<<3");
	}

	@Test
	public void testBitWiseNot() {
		assertEval(-1, "~0");
	}

	@Test
	public void testLogicalNot() {
		assertEval(0, "!1");
		assertEval(1, "!0");
		assertEval(0, "!124");
	}

	@Test
	public void testGreaterThan() {
		assertEval(1, "8>5");
		assertEval(0, "5>8");
		assertEval(0, "8>8");
	}

	@Test
	public void testLessThan() {
		assertEval(0, "8<5");
		assertEval(1, "5<8");
		assertEval(0, "8<8");
	}

	@Test
	public void testGreaterThanOrEqual() {
		assertEval(1, "8>=5");
		assertEval(0, "5>=8");
		assertEval(1, "8>=8");
	}

	@Test
	public void testLessThanOrEqual() {
		assertEval(0, "8<=5");
		assertEval(1, "5<=8");
		assertEval(1, "8<=8");
	}

	@Test
	public void testAddSubtractAssociatesLeftToRight() {
		assertEval(110, "100+30-10-10");
		assertEval(110, "100-10-10+30");
	}

	@Test
	public void testMultiplyDivide() {
		assertEval(100, "10*30/3");
		assertEval(90, "10/3*30");
	}

	@Test
	public void testBitwiseAnd() {
		assertEval(0x4, "0xffff & 0x4");
		assertEval(0x0, "0x4 & 0x2");
	}

	@Test
	public void testBitwiseOr() {
		assertEval(0x6, "0x2 | 0x4");
	}

	@Test
	public void testBitwiseXor() {
		assertEval(0x2, "0x3 ^ 0x1");
	}

	@Test
	public void testLogicalAnd() {
		assertEval(1, "0xffff && 0x4");
		assertEval(0, "0x4 && 0");
	}

	@Test
	public void testLogicalOr() {
		assertEval(1, "0x2 || 0x4");
		assertEval(0, "0 || 0");
	}

	@Test
	public void testMixedPrecedence() {
		assertEval(23, "10+3*5-8/4");
	}

	@Test
	public void testGrouping() {
		assertEval(42, "6*(3+4)");
		assertEval(16, "1 << (8/2)");
		assertEval(-1, "~(-1+1)");
		assertEval(13, "1+(3 * (7+1)/2)");
	}

	@Test
	public void testStackedUnaryOperators() {
		assertEval(-1, "~~~0");
	}

	@Test
	public void testInvalidSyntax() {
		assertEvalNull("5 5");
		assertEvalNull("+");
		assertEvalNull("<< 5");
		assertEvalNull("5 +");
		assertEvalNull("(3+2");
	}

	@Test
	public void testMixedValues() {
		assertEval(26, "10+0x10");
	}

	@Test
	public void testHexOnly() {
		assertEvalHexOnly(22, "10+6");
	}

	private void assertEval(long expected, String expression) {
		long result = ExpressionEvaluator.evaluateToLong(expression);
		assertEquals(expected, result);

	}

	private void assertEvalHexOnly(long expected, String expression) {
		ExpressionEvaluator evaluator = new ExpressionEvaluator(true);
		long result;
		try {
			result = evaluator.parseAsLong(expression);
			assertEquals(expected, result);
		}
		catch (ExpressionException e) {
			// ignore
		}

	}

	private void assertEvalNull(String expression) {
		assertNull(ExpressionEvaluator.evaluateToLong(expression));

	}
}
