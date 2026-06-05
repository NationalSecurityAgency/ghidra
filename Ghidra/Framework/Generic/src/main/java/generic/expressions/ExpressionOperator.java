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

import java.util.*;

import org.apache.commons.collections4.map.LazyMap;

/**
 * Enum of support operators for the {@link ExpressionEvaluator}
 */
public enum ExpressionOperator implements ExpressionElement {
	// unary
	BITWISE_NOT("~", OpType.UNARY, 1),
	LOGICAL_NOT("!", OpType.UNARY, 1),
	UNARY_PLUS("+", OpType.UNARY, 1),
	UNARY_MINUS("-", OpType.UNARY, 1),

	// multiplicative
	MULTIPLY("*", OpType.BINARY, 2),
	DIVIDE("/", OpType.BINARY, 2),

	// additive
	ADD("+", OpType.BINARY, 3),
	SUBTRACT("-", OpType.BINARY, 3),

	// shift
	SHIFT_LEFT("<<", OpType.BINARY, 4),
	SHIFT_RIGHT(">>", OpType.BINARY, 4),

	// relational
	LESS_THAN("<", OpType.BINARY, 5),
	GREATER_THAN(">", OpType.BINARY, 5),
	LESS_THAN_OR_EQUAL("<=", OpType.BINARY, 5),
	GREATER_THAN_OR_EQUAL(">=", OpType.BINARY, 5),

	// equality
	EQUALS("==", OpType.BINARY, 6),
	NOT_EQUALS("!=", OpType.BINARY, 6),

	// bitwise
	BITWISE_AND("&", OpType.BINARY, 7),
	BITWISE_XOR("^", OpType.BINARY, 8),
	BITWISE_OR("|", OpType.BINARY, 9),

	// logical
	LOGICAL_AND("&&", OpType.BINARY, 10),
	LOGICAL_OR("||", OpType.BINARY, 11);

	public static List<Set<ExpressionOperator>> binaryOperatorsByPrecedence;

	private String name;
	private OpType type;
	private int precedence;

	private ExpressionOperator(String name, OpType type, int precedence) {
		this.name = name;
		this.type = type;
		this.precedence = precedence;
	}

	@Override
	public String toString() {
		return name;
	}

	/**
	 * Returns a list of all the binary operators in precedence order, organized into sets where
	 * each set contains all the operators of the same precedence.
	 * @return a list of all the binary operators in precedence order, organized into sets where
	 * each set contains all the operators of the same precedence.
	 */
	public static List<Set<ExpressionOperator>> getBinaryOperatorsByPrecedence() {
		if (binaryOperatorsByPrecedence == null) {
			binaryOperatorsByPrecedence = buildOperatorsByPrecedenceList();
		}
		return binaryOperatorsByPrecedence;
	}

	private static List<Set<ExpressionOperator>> buildOperatorsByPrecedenceList() {
		ExpressionOperator[] values = values();
		LazyMap<Integer, HashSet<ExpressionOperator>> map =
			LazyMap.lazyMap(new TreeMap<>(), k -> new HashSet<>());

		for (ExpressionOperator op : values) {
			if (op.isBinary()) {
				map.get(op.precedence).add(op);
			}
		}
		return new ArrayList<>(map.values());

	}

	/**
	 * Returns the operator for the given token and look ahead token and if we are expecting to find
	 * a binary operator. This method first tries merging the tokens looking for a double char
	 * operator first.
	 * @param token the first token
	 * @param lookahead1 the next token that may or may not be part of this operand
	 * @param preferBinary if we are expecting a binary operator (the previous expression element
	 * was an operand value). We need this to know if the token '-' is the unary operator or the
	 * binary operator. If the token before was an operator, then we expect a unary operator. If
	 * the previous was a value, then we expect a binary operator.
	 * @return the operator that matches the given tokens and expected type
	 */
	public static ExpressionOperator getOperator(String token, String lookahead1,
			boolean preferBinary) {

		if (lookahead1 != null) {
			String doubleToken = token + lookahead1;
			ExpressionOperator operator = findOperator(doubleToken, preferBinary);
			if (operator != null) {
				return operator;
			}
		}

		return findOperator(token, preferBinary);
	}

	private static ExpressionOperator findOperator(String tokens, boolean expectBinary) {
		for (ExpressionOperator operator : values()) {
			if (operator.name.equals(tokens)) {
				if (operator.isBinary() == expectBinary) {
					return operator;
				}
			}
		}
		return null;
	}

	/**
	 * Returns the number of chars in the operator
	 * @return the number of chars in the operator
	 */
	public int size() {
		return name.length();
	}

	/**
	 * Returns if the operator is a unary operator.
	 * @return if the operator is a unary operator.
	 */
	public boolean isUnary() {
		return type == OpType.UNARY;
	}

	/**
	 * Returns if the operator is a binary operator.
	 * @return if the operator is a binary operator.
	 */
	public boolean isBinary() {
		return type == OpType.BINARY;
	}

	private enum OpType {
		UNARY, BINARY
	}

}
