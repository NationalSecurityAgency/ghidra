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

import static generic.expressions.ExpressionGrouper.*;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import ghidra.util.NumericUtilities;

/**
 * Class for evaluating numeric expressions. See 
 * {@link ExpressionOperator} for the full list of supported operators. All values are interpreted
 * as longs. Optionally, an ExpressionEvalualuator can be constructed with a symbol evaluator that
 * will be called on any string that can't be evaluated as an operator or number.
 * <P>
 * ExpressionEvaluators can operate in either decimal or hex mode. If in hex mode, all numbers are
 * assumed to be hexadecimal values. In decimal mode, numbers are assumed to be decimal values, but
 * hexadecimal values can still be specified by prefixing them with "0x".
 * <P>
 * There are also two convenience static methods that can be called to evaluate expressions. These
 * methods will either return a Long value as the result or null if there was an error evaluating
 * the expression. To get error messages related to parsing the expression, instantiate an
 * ExpressionEvaluator and call {@link #parse(String)} which will throw a 
 * {@link ExpressionException} when the expression can't be evaluated.
 */
public class ExpressionEvaluator {
	private static final String TOKEN_CHARS = "+-*/()<>|^&~ =!";

	private boolean assumeHex = false;

	private Function<String, ExpressionValue> evaluator;

	/**
	 * Evaluates the given input as a Long value. This call assumes all numbers are decimal unless
	 * prefixed with a "0x". 
	 * @param input the expression to be parsed into a Long value
	 * @return the resulting Long value or null if the expression could not be evaluated.
	 */
	public static Long evaluateToLong(String input) {
		return evaluateToLong(input, false);
	}

	/**
	 * Evaluates the given input as a long value. 
	 * @param input the expression to be parsed into a Long value
	 * @param assumeHex if true, numbers will be assumed to be hexadecimal values.
	 * @return the resulting Long value or null if the expression could not be evaluated.
	 */
	public static Long evaluateToLong(String input, boolean assumeHex) {
		ExpressionEvaluator evaluator = new ExpressionEvaluator(assumeHex);
		try {
			return evaluator.parseAsLong(input);
		}
		catch (ExpressionException e) {
			return null;
		}
	}

	/**
	 * Constructs an ExpressionEvaluator in decimal mode.
	 */
	public ExpressionEvaluator() {
		this(false);
	}

	/**
	 * Constructs an ExpressionEvaluator in either decimal or hex mode.
	 * @param assumeHex if true, the evaluator will assume all values are hexadecimal.
	 */
	public ExpressionEvaluator(boolean assumeHex) {
		this(assumeHex, s -> null);
	}

	/**
	 * Constructs an ExpressionEvaluator in decimal mode with a given symbol evaluator.
	 * @param evaluator A function that can convert a string token into a value (Must be Long
	 * ExpressionValues, unless this is being called by a subclass that can handle other types
	 * of operand values)
	 */
	public ExpressionEvaluator(Function<String, ExpressionValue> evaluator) {
		this(false, evaluator);
	}

	/**
	 * Constructs an ExpressionEvaluator in either decimal or hex mode with a given symbol
	 * evaluator.
	 * @param assumeHex if true, the evaluator will assume all values are hexadecimal.
	 * @param evaluator A function that can convert a string token into a value (Must be Long
	 * ExpressionValues, unless this is being called by a subclass that can handle other types
	 * of operand values)
	 */
	public ExpressionEvaluator(boolean assumeHex, Function<String, ExpressionValue> evaluator) {
		this.assumeHex = assumeHex;
		this.evaluator = Objects.requireNonNull(evaluator);
	}

	/**
	 * Parses the given expression input, expecting the result to be long value.
	 * @param input the expression string
	 * @return the long value result.
	 * @throws ExpressionException if the expression could not be evaluated to a long value.
	 */
	public long parseAsLong(String input) throws ExpressionException {
		ExpressionValue expressionValue = parse(input);
		if (expressionValue instanceof LongExpressionValue longValue) {
			return longValue.getLongValue();
		}
		throw new ExpressionException("Expression did not evalute to a long! Got a " +
			expressionValue.getClass() + " instead.");
	}

	/**
	 * Changes the hex/decimal mode.
	 * @param b if true, all numbers will be assumed to be hexadecimal
	 */
	public void setAssumeHex(boolean b) {
		this.assumeHex = b;
	}

	protected ExpressionValue parse(String input) throws ExpressionException {
		return this.parse(input, null);
	}

	protected ExpressionValue parse(String input, ExpressionValue initial)
			throws ExpressionException {
		List<ExpressionElement> list = new ArrayList<>();

		// if there is a given initial value (used for relative expressions), add it to the 
		// sequential list of valid expression elements.
		if (initial != null) {
			list.add(initial);
		}

		// convert the text input into a list of valid expression elements
		parseToList(input, list);

		// evaluate the list of expression elements in operator precedence order.
		return eval(list);
	}

	/**
	 * Parses the input string into a list of valid elements. When this method completes, the list
	 * will contain only valid operators, valid operand values, or group operators. 
	 * @param input the input string to be parsed.
	 * @param list the list to populate with valid elements.
	 * @throws ExpressionException if any part of the input string can't be parsed into a valid 
	 * expression element.
	 */
	private void parseToList(String input, List<ExpressionElement> list)
			throws ExpressionException {

		LookAheadTokenizer parser = new LookAheadTokenizer(input);
		while (parser.hasMoreTokens()) {
			String token = parser.getCurrentToken();

			if (token.isBlank()) {
				parser.advance(1);
			}
			else if (processGroupToken(list, token)) {
				parser.advance(1);
			}
			else if (processOperator(list, token, parser.getNextToken())) {
				ExpressionOperator op = getLastOperator(list);
				parser.advance(op.size());
			}
			else if (processNumber(list, token)) {
				parser.advance(1);
			}
			else if (processSymbol(list, token)) {
				parser.advance(1);
			}
			else {
				throw new ExpressionException("Could not evaluate token \"" + token + "\"");
			}
		}
		if (list.isEmpty()) {
			throw new ExpressionException("Expression is empty. Nothing to parse!");
		}
	}

	/**
	 * Evaluates a list of valid expression elements into a single final value.
	 * @param list the list of valid expression elements.
	 * @return the final value the expression evaluates to
	 * @throws ExpressionException if sequence of expression elements is not in a valid order such
	 * that it evaluates to a single value. (such as two values not being separated by an operator)
	 */
	private ExpressionValue eval(List<ExpressionElement> list) throws ExpressionException {
		// first evaluate any sub-lists grouped by parenthesis
		processGroups(list);

		// next process any unary operators
		processUnaryOperators(list);

		// final process binary operators in operator precedence order.
		processBinaryOperators(list);

		// if everything evaluated properly, there should only be one item left in the list
		if (list.size() != 1) {
			String result = list.stream().map(Object::toString).collect(Collectors.joining(" "));
			throw new ExpressionException("Parse failed! Stopped at \"" + result + "\"");
		}

		ExpressionElement element = list.get(0);
		if (element instanceof ExpressionValue ev) {
			return ev;
		}
		throw new ExpressionException("Parse failed to evaluate to a value! Stopped at " + element);
	}

	private void processBinaryOperators(List<ExpressionElement> list) throws ExpressionException {
		List<Set<ExpressionOperator>> ops = ExpressionOperator.getBinaryOperatorsByPrecedence();

		// Each set in the list contains operators at the same precedence, so they all need
		// to be processed at the same time so that they are processed left to right (which 
		// corresponds to the list order)
		for (Set<ExpressionOperator> set : ops) {
			processBinaryOperators(list, set);
		}
	}

	private void processBinaryOperators(List<ExpressionElement> list,
			Set<ExpressionOperator> operators) throws ExpressionException {
		// can't have a valid binary operator at index 0, so start looking at index 1
		int operatorIndex = findValidBinaryOperator(list, operators, 1);
		while (operatorIndex >= 0) {
			// we can safely cast here because we checked in the findValidBinaryOperator method
			ExpressionOperator operator = (ExpressionOperator) list.get(operatorIndex);
			ExpressionValue value1 = (ExpressionValue) list.get(operatorIndex - 1);
			ExpressionValue value2 = (ExpressionValue) list.get(operatorIndex + 1);
			ExpressionValue newValue = value1.applyBinaryOperator(operator, value2);
			list.set(operatorIndex - 1, newValue);
			list.subList(operatorIndex, operatorIndex + 2).clear();

			// After the operator completed, the list has been changed and the sequence
			// "value operator value" has been replace with the resulting value of the operation.

			// Now look for the next operator in the current set of operators we are evaluating
			operatorIndex = findValidBinaryOperator(list, operators, operatorIndex);
		}

	}

	private int findValidBinaryOperator(List<ExpressionElement> list,
			Set<ExpressionOperator> operators, int startIndex) {

		// can't have a valid binary operator at the last index, so stop 1 before last
		for (int i = startIndex; i < list.size() - 1; i++) {
			if (operators.contains(list.get(i))) {
				// make sure the elements before and after the operator are value types so
				// that the caller can just cast them as values. If they are not, then
				// this operator won't be evaluated and at the end the evaluate process, the list
				// won't be reduced to just one element.
				if (list.get(i - 1) instanceof ExpressionValue &
					list.get(i + 1) instanceof ExpressionValue) {
					return i;
				}
			}
		}
		return -1;
	}

	private void processUnaryOperators(List<ExpressionElement> list) throws ExpressionException {

		int unaryOperatorIndex = findValidUnaryOperator(list);
		while (unaryOperatorIndex >= 0) {
			ExpressionOperator operator = (ExpressionOperator) list.get(unaryOperatorIndex);
			ExpressionValue value = (ExpressionValue) list.get(unaryOperatorIndex + 1);
			ExpressionValue newValue = value.applyUnaryOperator(operator);
			list.remove(unaryOperatorIndex);
			list.set(unaryOperatorIndex, newValue);

			unaryOperatorIndex = findValidUnaryOperator(list);
		}

	}

	private int findValidUnaryOperator(List<ExpressionElement> list) {
		// stop 1 before end since you can't end in a valid unary operator

		for (int i = 0; i < list.size() - 1; i++) {
			// check any element in the list if it is a unary operator
			if (list.get(i) instanceof ExpressionOperator op) {
				if (!op.isUnary()) {
					continue;
				}

				// make sure the next element is a value so the the caller can cast without fear
				if (list.get(i + 1) instanceof ExpressionValue) {
					return i;
				}
			}
		}
		return -1;
	}

	/**
	 * Recursively for groups (sublists surrounded by parenthesis) and process the sub list of 
	 * elements in the group before processing the outer list. As each group is evaluated, the start
	 * paren operator, the end paren operator and all the tokens in between are replaced by the
	 * single value the group evaluated to.
	 * @param list the list to look for grouped sub-lists.
	 * @throws ExpressionException if a exception occurs processing a sub list
	 */
	private void processGroups(List<ExpressionElement> list) throws ExpressionException {
		int groupStart = findGroupStart(list);
		while (groupStart >= 0) {
			int groupEndIndex = findGroupEnd(list, groupStart);
			if (groupEndIndex < 0) {
				throw new ExpressionException("Missing end parenthesis!");
			}
			ExpressionValue value = eval(list.subList(groupStart + 1, groupEndIndex));

			// After evaluating, everything between the parens will be replaced by the result. So
			// replace the left paren with the results and clear the next 2 entries.
			list.set(groupStart, value);
			list.subList(groupStart + 1, groupStart + 3).clear();

			groupStart = findGroupStart(list);
		}
	}

	private int findGroupStart(List<ExpressionElement> list) {
		for (int i = 0; i < list.size(); i++) {
			if (list.get(i) == LEFT_PAREN) {
				return i;
			}
		}
		return -1;
	}

	private int findGroupEnd(List<ExpressionElement> list, int groupStart) {
		int depth = 1;
		for (int i = groupStart + 1; i < list.size(); i++) {
			Object obj = list.get(i);
			if (obj == LEFT_PAREN) {
				depth++;
			}
			else if (obj == RIGHT_PAREN) {
				if (--depth == 0) {
					return i;
				}
			}
		}
		return -1;
	}

	// A tokenizer that keeps track of one future token. This is so the parser can handle operator 
	// chars that can ether be an operator by itself or part of a 2 char operator(i.e. "<", "=",
	// "<=", "<<", "==")
	private class LookAheadTokenizer {
		private StringTokenizer tokenizer;
		private String currentToken;
		private String nextToken;

		LookAheadTokenizer(String input) {
			tokenizer = new StringTokenizer(input, TOKEN_CHARS, true);
			currentToken = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
			nextToken = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
		}

		public boolean hasMoreTokens() {
			return currentToken != null;
		}

		public String getCurrentToken() {
			return currentToken;
		}

		public String getNextToken() {
			return nextToken;
		}

		public void advance(int count) {
			for (int i = 0; i < count; i++) {
				currentToken = nextToken;
				nextToken = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
			}
		}
	}

	private ExpressionOperator getLastOperator(List<ExpressionElement> list) {
		ExpressionElement lastElement = list.get(list.size() - 1);
		return (ExpressionOperator) lastElement;
	}

	private boolean processSymbol(List<ExpressionElement> list, String token) {
		ExpressionValue value = evaluateSymbol(token);
		if (value != null) {
			list.add(value);
			return true;
		}
		return false;
	}

	protected ExpressionValue evaluateSymbol(String token) {
		return evaluator.apply(token);
	}

	private boolean processOperator(List<ExpressionElement> list, String token, String nextToken) {
		boolean preferBinary = shouldPreferBinaryOp(list);
		ExpressionOperator op = ExpressionOperator.getOperator(token, nextToken, preferBinary);
		if (op != null) {
			list.add(op);
			return true;
		}
		return false;
	}

	private boolean processGroupToken(List<ExpressionElement> list, String token) {
		if (token.equals("(")) {
			list.add(LEFT_PAREN);
			return true;
		}

		if (token.equals(")")) {
			list.add(RIGHT_PAREN);
			return true;
		}
		return false;
	}

	private boolean shouldPreferBinaryOp(List<ExpressionElement> list) {
		if (list.isEmpty()) {
			return false;
		}
		ExpressionElement lastElement = list.get(list.size() - 1);
		if (lastElement instanceof ExpressionValue) {
			return true;
		}
		if (lastElement instanceof ExpressionOperator) {
			return false;
		}
		if (lastElement == ExpressionGrouper.LEFT_PAREN) {
			return false;
		}
		if (lastElement == ExpressionGrouper.RIGHT_PAREN) {
			return true;
		}
		return false;
	}

	private boolean processNumber(List<ExpressionElement> list, String token) {
		int radix = 10;

		if (assumeHex && processAsHexNumber(list, token)) {
			return true;
		}
		token = toLowerAndRemoveEndNumberDecorators(token);
		if (token.startsWith("0x")) {
			radix = 16;
			token = token.substring(2);
		}

		try {
			long value = (radix == 10) ? NumericUtilities.parseLong(token)
					: NumericUtilities.parseHexLong(token);

			list.add(new LongExpressionValue(value));
			return true;
		}
		catch (Exception e) {
			return false;
		}
	}

	private String toLowerAndRemoveEndNumberDecorators(String token) {
		token = token.toLowerCase();
		if (token.endsWith("ull") || token.endsWith("llu")) {
			token = token.substring(0, token.length() - 3);
		}
		else if (token.endsWith("ul") || token.endsWith("lu") || token.endsWith("ll")) {
			token = token.substring(0, token.length() - 2);
		}
		else if (token.endsWith("l") || token.endsWith("u")) {
			token = token.substring(0, token.length() - 1);
		}
		return token;
	}

	// parses values as a hex value (e.g. parsing "10" returns 16 instead of 10)
	private boolean processAsHexNumber(List<ExpressionElement> list, String token) {
		try {
			long value = NumericUtilities.parseHexLong(token);
			list.add(new LongExpressionValue(value));
			return true;
		}
		catch (NumberFormatException e) {
			// ignore
		}
		return false;
	}
}
