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
package ghidra.sleigh.grammar;

import java.math.BigInteger;

import org.antlr.runtime.*;
import org.antlr.runtime.tree.*;

import ghidra.pcodeCPort.slgh_compile.PcodeCompile;
import ghidra.pcodeCPort.slgh_compile.SleighCompile;
import ghidra.pcodeCPort.slghsymbol.*;

public abstract class AbstractSleighCompiler extends TreeParser {

	protected static final BigInteger MAX_ULONG = new BigInteger("ffffffffffffffff", 16);
	protected static final BigInteger MIN_SLONG = new BigInteger("-8000000000000000", 16);
	protected static final BigInteger MAX_UINT = new BigInteger("ffffffff", 16);

	public AbstractSleighCompiler(TreeNodeStream input) {
		super(input);
	}

	public AbstractSleighCompiler(TreeNodeStream input, RecognizerSharedState state) {
		super(input, state);
	}

	protected ParsingEnvironment env = null;
	protected SleighCompile sc = null;
	protected PcodeCompile pcode = null;

	public void reportError(Location loc, String msg) {
		if (pcode != null) {
			pcode.reportError(loc, msg);
		}
		else {
			sc.reportError(loc, msg);
		}
	}

	public void reportWarning(Location loc, String msg) {
		if (pcode != null) {
			pcode.reportWarning(loc, msg);
		}
		else {
			sc.reportWarning(loc, msg);
		}
	}

	public boolean passesCheck(RadixBigInteger rbi) {
		return rbi.bitLength() <= 64;
	}

	public void check(RadixBigInteger rbi) {
		if (!passesCheck(rbi)) {
			reportError(rbi.location, "Integer representation exceeds Java long (" + rbi + ")");
		}
	}

	protected long toSLong(RadixBigInteger bi) {
		try {
			return bi.longValueExact();
		}
		catch (ArithmeticException e) {
			reportError(bi.location, "Integer cannot be represented as signed long: " + bi);
			return bi.longValue();
		}
	}

	protected long toULong(RadixBigInteger bi) {
		if (bi.compareTo(MAX_ULONG) > 0 || bi.signum() < 0) {
			reportError(bi.location, "Integer cannot be represented as unsigned long: " + bi);
		}
		return bi.longValue();
	}

	protected long toLong(RadixBigInteger bi) {
		if (bi.compareTo(MAX_ULONG) > 0 || bi.compareTo(MIN_SLONG) < 0) {
			reportError(bi.location, "Integer cannot be represented as long: " + bi);
		}
		return bi.longValue();
	}

	protected int toUInt(RadixBigInteger bi) {
		if (bi.compareTo(MAX_UINT) > 0 || bi.signum() < 0) {
			reportError(bi.location, "Integer cannot be represented as unsigned int: " + bi);
		}
		return bi.intValue();
	}

	protected void redefinedError(SleighSymbol sym, Tree t, String what) {
		String msg =
			"symbol '" + sym.getName() + "' (from " + sym.getLocation() + ") redefined as " + what;
		reportError(find(t), msg);
	}

	protected void wildcardError(Tree t, String what) {
		String msg = "wildcard (_) not allowed in " + what;
		reportError(find(t), msg);
	}

	protected void wrongSymbolTypeError(SleighSymbol sym, Location where, String type,
			String purpose) {
		String msg = sym.getType() + " '" + sym + "' (defined at " + sym.getLocation() +
			") is wrong type (should be " + type + ") in " + purpose;
		reportError(where, msg);
	}

	protected void undeclaredSymbolError(SleighSymbol sym, Location where, String purpose) {
		String msg = "'" + sym + "' (used in " + purpose + ") is not declared in the pattern list";
		reportError(where, msg);
	}

	protected void unknownSymbolError(String text, Location loc, String type, String purpose) {
		String msg = "unknown " + type + " '" + text + "' in " + purpose;
		reportError(loc, msg);
	}

	protected void invalidDynamicTargetError(Location loc, String purpose) {
		String msg = "invalid dynamic target used in " + purpose;
		reportError(loc, msg);
	}

	protected Location find(Tree t) {
		return env.getLocator().getLocation(t.getLine());
	}

	protected SubtableSymbol findOrNewTable(Location loc, String name) {
		SleighSymbol sym = sc.findSymbol(name);
		if (sym == null) {
			SubtableSymbol ss = sc.newTable(loc, name);
			return ss;
		}
		else if (sym.getType() != symbol_type.subtable_symbol) {
			wrongSymbolTypeError(sym, loc, "subtable", "subconstructor");
			return null;
		}
		else {
			return (SubtableSymbol) sym;
		}
	}

	protected RadixBigInteger resolveDefaultConstant(Location loc, String text) {
		throw new AssertionError("Implement me");
	}

	@Override
	public String getErrorMessage(RecognitionException e, String[] tokenNames) {
		return env.getParserErrorMessage(e, tokenNames);
	}

	@Override
	public String getTokenErrorDisplay(Token t) {
		return env.getTokenErrorDisplay(t);
	}

	@Override
	public String getErrorHeader(RecognitionException e) {
		return env.getErrorHeader(e);
	}

	void bail(String msg) {
		throw new BailoutException(msg);
	}
}
