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
package ghidra.program.util;

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.NumericUtilities;

/**
 * The <CODE>AddressEvaluator</CODE> class provides a way to evaluate a string
 * that represents an address and resolve it to an address for a particular program.
 */
public class AddressEvaluator {

	private static final String TOKEN_CHARS = "+-*/()<>|^&~ =";

	/**
	 * Gets a legitimate address for the specified program as indicated by the string.
	 * @param p the program to use for determining the address.
	 * @param baseAddr the base address to use for relative addressing.
	 * @param s string representation of the address desired.
	 * @return the address. Otherwise, return null if the string fails to evaluate
	 * to a unique legitimate address.
	 */
	public static Address evaluate(Program p, Address baseAddr, String s) {

		AddressFactory af = p.getAddressFactory();
		SymbolTable st = p.getSymbolTable();
		List<Object> list = new ArrayList<Object>();
		if (baseAddr != null) {
			list.add(baseAddr);
		}
		if (!parseToList(s, af, st, list)) {
			return null;
		}
		Object obj = eval(list);
		if (obj instanceof Address) {
			return (Address) obj;
		}
		else if (obj instanceof Long) {
			try {
				return af.getDefaultAddressSpace().getAddress(((Long) obj).longValue());
			}
			catch (Exception e) {
				// ignore
			}
		}
		return null;
	}

	public static Long evaluateToLong(String s) {
		List<Object> list = new ArrayList<Object>();

		if (!parseToList(s, null, null, list)) {
			return null;
		}
		Object obj = eval(list);
		if (obj instanceof Address) {
			return ((Address) obj).getOffset();
		}
		else if (obj instanceof Long) {
			return (Long) obj;
		}
		return null;
	}

	protected static boolean parseToList(String s, AddressFactory af, SymbolTable st,
			List<Object> list) {
		StringTokenizer parser = new StringTokenizer(s, TOKEN_CHARS, true);
		String lookahead = null;
		while (lookahead != null || parser.hasMoreTokens()) {
			String tok = null;
			if (lookahead != null) {
				tok = lookahead;
				lookahead = null;
			}
			else {
				tok = parser.nextToken();
			}

			if (tok.equals(" ")) {
				continue;
			}

			// = must be followed by =, others can be followed
			if (tok.equals("=") || tok.equals("!") || tok.equals("<") || tok.equals(">")) {
				lookahead = parser.nextToken();
				tok = checkDoubleToken(tok, lookahead);
				// if tok is now longer, consumed lookahead
				if (tok.length() > 1) {
					lookahead = null;
				}
			}
			Object obj = Operator.getOperator(tok);
			if (obj == null) {
				obj = getValueObject(st, af, tok);
			}
			if (obj == null) {
				return false;
			}
			list.add(obj);
		}
		return true;
	}

	private static String checkDoubleToken(String tok, String lookahead) {
		switch (tok) {
			case "=":
				if (lookahead.equals("=")) {
					return "==";
				}
				break;

			case "<":
				if (lookahead.equals("=")) {
					return "<=";
				}
				if (lookahead.equals("<")) {
					return "<<";
				}
				break;

			case ">":
				if (lookahead.equals("=")) {
					return ">=";
				}
				if (lookahead.equals(">")) {
					return ">>";
				}
				break;

			case "!":
				if (lookahead.equals("=")) {
					return "!=";
				}
				break;
		}

		return tok;
	}

	/**
	 * Gets a legitimate address for the specified program as indicated by the string.
	 * @param p the program to use for determining the address.
	 * @param s string representation of the address desired.
	 * @return the address. Otherwise, return null if the string fails to evaluate
	 * to a legitimate address.
	 */
	public static Address evaluate(Program p, String s) {
		return evaluate(p, null, s);
	}

	/**
	 * Utility method for creating an Address object from a byte array. The Address object may or may not
	 * be a legitimate Address in the program's address space. This method is meant to provide a way of
	 * creating an Address object from a sequence of bytes that can be used for additional tests and
	 * comparisons.
	 *
	 * @param p - program being analyzed.
	 * @param addrBytes - byte array to use containing the values the address will be constructed from.
	 * @return - Address object constructed from the addrBytes array. Returns null if the program is null,
	 * addrBytes is null, or the length of addrBytes does not match the default Pointer size or does not contain
	 * a valid offset.
	 *
	 */
	public static Address evaluate(Program p, byte[] addrBytes) {

		boolean isBigEndian = p.getMemory().isBigEndian();

		int ptrSize = p.getDefaultPointerSize();
		int index = 0;
		long offset = 0;

		// Make sure correct # of bytes were passed
		if (addrBytes == null || addrBytes.length != ptrSize) {
			return null;
		}

		/*
		 * Make sure we account for endianess of the program.
		 * Computing the number of bits to shift the current byte value
		 * is different for Little vs. Big Endian. Need to multiply by
		 * 8 to shift in 1-byte increments.
		 */
		if (isBigEndian) {
			index = 0;
			while (index < addrBytes.length) {
				offset += (addrBytes[index] & 0xff) << ((addrBytes.length - index - 1) * 8);
				index++;
			}
		}
		else {
			// Program is LittleEndian
			index = addrBytes.length - 1;
			while (index >= 0) {
				offset += ((addrBytes[index] & 0xff) << (index * 8));
				index--;
			}
		}

		AddressSpace space = p.getAddressFactory().getDefaultAddressSpace();
		try {
			return space.getAddress(offset, true);
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

	private static Object getValueObject(SymbolTable st, AddressFactory af, String tok) {

		if (st == null || af == null) {
			return getValueObject(tok);
		}

		try {
			return NumericUtilities.parseHexLong(tok);
		}
		catch (NumberFormatException e) {
			// ignore
		}
		Address address = af.getAddress(tok);
		if (address != null) {
			return address;
		}

		List<Symbol> globalSymbols = st.getLabelOrFunctionSymbols(tok, null);
		if (globalSymbols.size() == 1) {
			return globalSymbols.get(0).getAddress();
		}
		return null;
	}

	private static Object getValueObject(String strValue) {
		try {
			int start = 0;
			int radix = 10;
			if (strValue.indexOf("0x") == 0) {
				start = 2;
				radix = 16;
			}
			if (strValue.endsWith("UL")) {
				strValue = strValue.substring(start, strValue.length() - 2);
			}
			else if (strValue.endsWith("L") || strValue.endsWith("l") || strValue.endsWith("U")) {
				strValue = strValue.substring(start, strValue.length() - 1);
			}
			else {
				strValue = strValue.substring(start);
			}

			return (radix == 10) ? NumericUtilities.parseLong(strValue)
					: NumericUtilities.parseHexLong(strValue);
		}
		catch (RuntimeException e) {
			// ignore
		}
		return null;
	}

	private static Object eval(List<Object> list) {

		// first evaluate any grouped expressions
		boolean done = false;
		while (!done) {
			done = true;
			for (int i = 0; i < list.size(); i++) {
				if (list.get(i) == Operator.LEFT_PAREN) {
					done = false;
					int end = findMatchingParen(list, i);
					if (end < 0) {
						return null;
					}
					Object obj = eval(list.subList(i + 1, end));
					if (obj == null) {
						return null;
					}
					list.subList(i, i + 2).clear();
					list.set(i, obj);
				}
			}
		}

		//check for leading Minus
		if (list.size() > 1 && list.get(0) == Operator.MINUS) {
			Object obj = list.get(1);
			if (obj instanceof Long) {
				obj = -((Long) obj).longValue();
				list.remove(0);
				list.set(0, obj);
			}
		}

		//check for leading ~
		if (list.size() > 1 && list.get(0) == Operator.NOT) {
			Object obj = list.get(1);
			if (obj instanceof Long) {
				obj = ~((Long) obj).longValue();
				list.remove(0);
				list.set(0, obj);
			}
		}

		//check for trailing leading ~
		if (list.size() > 3 && list.get(2) == Operator.NOT) {
			Object obj = list.get(3);
			if (obj instanceof Long) {
				obj = ~((Long) obj).longValue();
				list.remove(2);
				list.set(2, obj);
			}
		}

		// evaluate all SHIFT because they have precedence
		if (!evaluateOperator(list, Operator.RIGHTSHIFT, Operator.LEFTSHIFT)) {
			return null;
		}

		// evaluate all TIMES because they have precedence
		if (!evaluateOperator(list, Operator.TIMES, Operator.DIVIDE)) {
			return null;
		}

		// evaluate Plus and Minus, same precedence, but do plus then minus
		if (!evaluateOperator(list, Operator.PLUS, Operator.MINUS)) {
			return null;
		}

		// evaluate & ^ |
		if (!evaluateOperator(list, Operator.AND, null)) {
			return null;
		}
		if (!evaluateOperator(list, Operator.XOR, null)) {
			return null;
		}
		if (!evaluateOperator(list, Operator.OR, null)) {
			return null;
		}

		if (!evaluateOperator(list, Operator.EQUALS, Operator.NOTEQUALS)) {
			return null;
		}

		if (!evaluateOperator(list, Operator.LESS, Operator.GREATER)) {
			return null;
		}

		if (!evaluateOperator(list, Operator.LESSEQUALS, Operator.GREATEREQUALS)) {
			return null;
		}

		if (list.size() != 1) {
			return null;
		}
		return list.get(0);
	}

	private static boolean evaluateOperator(List<Object> list, Operator op1, Operator op2) {
		boolean done;
		done = false;
		while (!done) {
			done = true;
			for (int i = 0; i < list.size(); i++) {
				Object obj = list.get(i);
				if (obj == op1 || obj == op2) {
					done = false;
					if (i == 0 || i == list.size() - 1) {
						return false;
					}
					Object value = computeValue(list.get(i - 1), (Operator) obj, list.get(i + 1));
					if (value == null) {
						return false;
					}
					list.subList(i, i + 2).clear();
					list.set(i - 1, value);
				}
			}
		}
		return true;
	}

	private static Object computeValue(Object v1, Operator op, Object v2) {
		if (op == Operator.TIMES) {
			if ((v1 instanceof Long) && (v2 instanceof Long)) {
				return ((Long) v1).longValue() * ((Long) v2).longValue();
			}
		}
		if (op == Operator.DIVIDE) {
			if ((v1 instanceof Long) && (v2 instanceof Long)) {
				return ((Long) v1).longValue() / ((Long) v2).longValue();
			}
		}
		else if (op == Operator.AND) {
			if ((v1 instanceof Long) && (v2 instanceof Long)) {
				return ((Long) v1).longValue() & ((Long) v2).longValue();
			}
		}
		else if (op == Operator.XOR) {
			if ((v1 instanceof Long) && (v2 instanceof Long)) {
				return ((Long) v1).longValue() ^ ((Long) v2).longValue();
			}
		}
		else if (op == Operator.OR) {
			if ((v1 instanceof Long) && (v2 instanceof Long)) {
				return ((Long) v1).longValue() | ((Long) v2).longValue();
			}
		}
		else if (op == Operator.LEFTSHIFT) {
			if ((v1 instanceof Long) && (v2 instanceof Long)) {
				return ((Long) v1).longValue() << ((Long) v2).longValue();
			}
		}
		else if (op == Operator.RIGHTSHIFT) {
			if ((v1 instanceof Long) && (v2 instanceof Long)) {
				return ((Long) v1).longValue() >> ((Long) v2).longValue();
			}
		}
		else if (op == Operator.PLUS) {
			if ((v1 instanceof Long) && (v2 instanceof Long)) {
				return ((Long) v1).longValue() + ((Long) v2).longValue();
			}
			else if ((v1 instanceof Address) && (v2 instanceof Long)) {
				return ((Address) v1).addWrap(((Long) v2).longValue());
			}
			else if ((v1 instanceof Long) && (v2 instanceof Address)) {
				return ((Address) v2).addWrap(((Long) v1).longValue());
			}
		}
		else if (op == Operator.NOT) {
			if (v2 instanceof Long) {
				return ~(((Long) v2).longValue());
			}
			else if (v2 instanceof Address) {
				return ((Address) v2).getNewAddress(~(((Long) v2).longValue()));
			}
		}
		else if (op == Operator.MINUS) {
			if ((v1 instanceof Long) && (v2 instanceof Long)) {
				return ((Long) v1).longValue() - ((Long) v2).longValue();
			}
			else if ((v1 instanceof Address) && (v2 instanceof Long)) {
				return ((Address) v1).subtractWrap(((Long) v2).longValue());
			}
			else if ((v1 instanceof Address) && (v2 instanceof Address)) {
				return ((Address) v1).subtract((Address) v2);
			}
		}
		else if (op == Operator.EQUALS) {
			Long diff = getDifference(v1, v2);
			if (diff != null) {
				return diff == 0L ? 1L : 0L;
			}
		}
		else if (op == Operator.NOTEQUALS) {
			Long diff = getDifference(v1, v2);
			if (diff != null) {
				return diff != 0L ? 1L : 0L;
			}
		}
		else if (op == Operator.LESSEQUALS) {
			Long diff = getDifference(v1, v2);
			if (diff != null) {
				return diff <= 0L ? 1L : 0L;
			}
		}
		else if (op == Operator.GREATEREQUALS) {
			Long diff = getDifference(v1, v2);
			if (diff != null) {
				return diff >= 0L ? 1L : 0L;
			}
		}
		else if (op == Operator.LESS) {
			Long diff = getDifference(v1, v2);
			if (diff != null) {
				return diff < 0L ? 1L : 0L;
			}
		}
		else if (op == Operator.GREATER) {
			Long diff = getDifference(v1, v2);
			if (diff != null) {
				return diff > 0L ? 1L : 0L;
			}
		}
		return null;
	}

	private static Long getDifference(Object v1, Object v2) {
		if ((v1 instanceof Address) && (v2 instanceof Long)) {
			return ((Address) v1).subtractWrap(((Long) v2).longValue()).getOffset();
		}
		else if ((v1 instanceof Address) && (v2 instanceof Address)) {
			return ((Address) v1).subtract((Address) v2);
		}
		else if ((v1 instanceof Long) && (v2 instanceof Long)) {
			return ((Long) v1).longValue() - ((Long) v2).longValue();
		}
		return null;
	}

	private static int findMatchingParen(List<Object> list, int index) {
		int depth = 1;
		for (int j = index + 1; j < list.size(); j++) {
			Object obj = list.get(j);
			if (obj == Operator.LEFT_PAREN) {
				depth++;
			}
			else if (obj == Operator.RIGHT_PAREN) {
				if (--depth == 0) {
					return j;
				}
			}
		}
		return -1;
	}
}

class Operator {
	static Operator PLUS = new Operator("+");
	static Operator MINUS = new Operator("-");
	static Operator TIMES = new Operator("*");
	static Operator DIVIDE = new Operator("/");
	static Operator AND = new Operator("&");
	static Operator OR = new Operator("|");
	static Operator NOT = new Operator("~");
	static Operator XOR = new Operator("^");
	static Operator LEFTSHIFT = new Operator("<<");
	static Operator RIGHTSHIFT = new Operator(">>");
	static Operator LEFT_PAREN = new Operator("(");
	static Operator RIGHT_PAREN = new Operator(")");
	static Operator EQUALS = new Operator("==");
	static Operator NOTEQUALS = new Operator("!=");
	static Operator LESS = new Operator("<");
	static Operator GREATER = new Operator(">");
	static Operator LESSEQUALS = new Operator("<=");
	static Operator GREATEREQUALS = new Operator(">=");

	final String name;

	private Operator(String name) {
		this.name = name;
	}

	@Override
	public String toString() {
		return name;
	}

	/**
	 * Gets the static object implementation of an operator.
	 * @param tok token string for the operator
	 * @return the static operator object.
	 */
	public static Operator getOperator(String tok) {
		if (tok.equals("+")) {
			return PLUS;
		}
		if (tok.equals("&")) {
			return AND;
		}
		if (tok.equals("|")) {
			return OR;
		}
		if (tok.equals("^")) {
			return XOR;
		}
		else if (tok.equals("-")) {
			return MINUS;
		}
		else if (tok.equals("~")) {
			return NOT;
		}
		else if (tok.equals("*")) {
			return TIMES;
		}
		else if (tok.equals("/")) {
			return DIVIDE;
		}
		else if (tok.equals(")")) {
			return RIGHT_PAREN;
		}
		else if (tok.equals("(")) {
			return LEFT_PAREN;
		}
		else if (tok.equals("<<")) {
			return LEFTSHIFT;
		}
		else if (tok.equals(">>")) {
			return RIGHTSHIFT;
		}
		else if (tok.equals("==")) {
			return EQUALS;
		}
		else if (tok.equals("!=")) {
			return NOTEQUALS;
		}
		else if (tok.equals("<")) {
			return LESS;
		}
		else if (tok.equals(">")) {
			return GREATER;
		}
		else if (tok.equals("<=")) {
			return LESSEQUALS;
		}
		else if (tok.equals(">=")) {
			return GREATEREQUALS;
		}
		return null;
	}
}
