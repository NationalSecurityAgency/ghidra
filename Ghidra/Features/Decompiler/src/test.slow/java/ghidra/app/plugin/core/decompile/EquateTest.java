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
package ghidra.app.plugin.core.decompile;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.component.ClangTextField;
import ghidra.app.plugin.core.decompile.actions.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;

public class EquateTest extends AbstractDecompilerTest {

	private static class EquateNameForce extends SetEquateAction {

		private String nameForce;		// Simulate name chosen by the equate dialog

		public EquateNameForce(DecompilePlugin plugin, String nm) {
			super(plugin);
			nameForce = nm;
		}

		@Override
		public String getEquateName(long value, int size, boolean isSigned, Program program) {
			if (program == null) {
				return null;
			}
			return nameForce;
		}
	}

	@Override
	protected String getProgramName() {
		return "Winmine__XP.exe.gzf";
	}

	private DecompilerActionContext getContext() {
		Function function = getHighFunction().getFunction();
		return new DecompilerActionContext(getDecompilerProvider(), function.getEntryPoint(),
			false);
	}

	/**
	 * Simulate the action of "converting" the current token to the given format
	 * @param convertType is the given format
	 */
	private void convertToken(int convertType) {
		checkInitialToken();
		ConvertConstantAction action;
		switch (convertType) {
			case EquateSymbol.FORMAT_DEC:
				action = new ConvertDecAction(decompiler);
				break;
			case EquateSymbol.FORMAT_BIN:
				action = new ConvertBinaryAction(decompiler);
				break;
			case EquateSymbol.FORMAT_OCT:
				action = new ConvertOctAction(decompiler);
				break;
			case EquateSymbol.FORMAT_CHAR:
				action = new ConvertCharAction(decompiler);
				break;
			case EquateSymbol.FORMAT_HEX:
				action = new ConvertHexAction(decompiler);
				break;
			default:
				action = null;
		}
		modifyProgram(p -> {
			action.actionPerformed(getContext());
		});
		waitForDecompiler();
	}

	/**
	 * Simulate setting an equate on the current token with the given name
	 * @param nm is the given name
	 */
	private void convertToken(String nm) {
		checkInitialToken();
		EquateNameForce action = new EquateNameForce(decompiler, nm);
		modifyProgram(p -> {
			action.actionPerformed(getContext());
		});
		waitForDecompiler();
	}

	private void checkInitialToken() {
		ClangToken token = getToken();
		assertTrue(token instanceof ClangVariableToken);
		HighVariable variable = token.getHighVariable();
		assertTrue(variable instanceof HighConstant);
	}

	private void verifyMatch(String eqName, String text, long address, boolean seeInListing) {
		ClangToken token = getToken();
		assertTrue(token instanceof ClangVariableToken);
		assertEquals(token.getText(), text);
		HighSymbol symbol = token.getHighVariable().getSymbol();
		assertTrue(symbol instanceof EquateSymbol);
		EquateSymbol eqSym = (EquateSymbol) symbol;
		SymbolEntry entry = eqSym.getFirstWholeMap();
		assertTrue(entry instanceof DynamicEntry);
		DynamicEntry dynEntry = (DynamicEntry) entry;
		assertEquals(dynEntry.getPCAdress().getOffset(), address);
		EquateTable equateTable = program.getEquateTable();
		assertNotNull(equateTable);
		Equate equate = equateTable.getEquate(eqName);
		assertNotNull(equate);
		List<EquateReference> references = equate.getReferences(eqSym.getPCAddress());
		assertEquals(references.size(), 1);
		EquateReference ref = references.get(0);
		assertEquals(equate.getValue(), eqSym.getValue());
		boolean foundHash = false;
		if (ref.getDynamicHashValue() == 0) {
			Instruction instr = program.getListing().getInstructionAt(ref.getAddress());
			long values[] = DynamicHash.calcConstantHash(instr, equate.getValue());
			for (long value : values) {
				if (value == dynEntry.getHash()) {
					foundHash = true;
					break;
				}
			}
		}
		else {
			foundHash = (dynEntry.getHash() == ref.getDynamicHashValue());
		}
		assertTrue(foundHash);
		assertEquals(ref.getOpIndex() >= 0, seeInListing);
	}

	@Test
	public void testEquate_basicConversion() {

		decompile("10016fa");

		ClangTextField line = getLineContaining("0x53");
		setDecompilerLocation(line.getLineNumber(), 17);

		convertToken(EquateSymbol.FORMAT_DEC);
		line = getLineContaining("83");
		setDecompilerLocation(line.getLineNumber(), 15);
		verifyMatch("83", "83", 0x1001700, true);
	}

	@Test
	public void testEquate_offByOne() {
		decompile("10016fa");

		ClangTextField line = getLineContaining("< 3)");
		setDecompilerLocation(line.getLineNumber(), line.getText().indexOf('3'));
		convertToken(EquateSymbol.FORMAT_BIN);
		line = getLineContaining("0b00000011");		// Binary format of "3"
		setDecompilerLocation(line.getLineNumber(), line.getText().indexOf("0b"));
		verifyMatch("00000000000000000000000000000010b", "0b00000011", 0x1001732, true);
	}

	@Test
	public void testEquate_decompilerInvented() {
		decompile("10016fa");

		ClangTextField line = getLineContaining("0x111)");
		setDecompilerLocation(line.getLineNumber(), line.getText().indexOf("0x111"));

		convertToken(EquateSymbol.FORMAT_OCT);
		line = getLineContaining("0421");
		setDecompilerLocation(line.getLineNumber(), line.getText().indexOf("0421"));
		verifyMatch("421o", "0421", 0x100171f, false);
	}

	@Test
	public void testEquate_oneOffNearby() {
		decompile("1002bc2");

		ClangTextField line = getLineContaining("9,0,0,1");
		setDecompilerLocation(line.getLineNumber(), line.getText().indexOf("0,0"));

		convertToken("MYZERO");
		line = getLineContaining("9,MYZERO");	// Make sure equate comes right after '9'
		setDecompilerLocation(line.getLineNumber(), line.getText().indexOf("MYZERO"));
		// The operand of the nearby "PUSH 0x1" instruction gets selected as a possible
		// candidate for the equate, but it doesn't propagate to the desired zero.
		verifyMatch("MYZERO", "MYZERO", 0x1002c8a, false);
	}

	@Test
	public void testEquate_namedMinus() {
		decompile("1002825");

		ClangTextField line = getLineContaining("0x38");
		setDecompilerLocation(line.getLineNumber(), line.getText().indexOf("0x38"));

		convertToken("MYMINUS");
		line = getLineContaining("+ MYMINUS");
		setDecompilerLocation(line.getLineNumber(), line.getText().indexOf("MYMINUS"));
		// Make sure the named equate applies to the negative number in the decompiler window
		// NOT the positive variant in the listing
		verifyMatch("MYMINUS", "MYMINUS", 0x1002862, false);
	}

	@Test
	public void testEquate_unnamedMinus() {
		decompile("1002825");

		ClangTextField line = getLineContaining("0x2b");
		setDecompilerLocation(line.getLineNumber(), line.getText().indexOf("0x2b"));

		convertToken(EquateSymbol.FORMAT_DEC);
		line = getLineContaining("43");
		setDecompilerLocation(line.getLineNumber(), line.getText().indexOf("43"));
		// Conversion should be attached to the positive formatting, but should affect both listing and decompiler
		verifyMatch("43", "-43", 0x1002882, true);
	}

	@Test
	public void testEquate_escapechar() {
		decompile("1002785");

		ClangTextField line = getLineContaining("/ 10)");
		setDecompilerLocation(line.getLineNumber(), line.getText().indexOf("10)"));

		convertToken(EquateSymbol.FORMAT_CHAR);
		line = getLineContaining("\\n");
		setDecompilerLocation(line.getLineNumber(), line.getText().indexOf("\\n"));
		verifyMatch("'\\n'", "L'\\n'", 0x10027d3, true);
	}

	@Test
	public void testEquate_convertChar() {
		decompile("1003d76");

		ClangTextField line = getLineContaining("'.'");
		setDecompilerLocation(line.getLineNumber(), line.getText().indexOf("'.'"));

		convertToken(EquateSymbol.FORMAT_HEX);
		line = getLineContaining("x2e");
		setDecompilerLocation(line.getLineNumber(), line.getText().indexOf("x2e"));
		verifyMatch("0x2E", "'\\x2e'", 0x1003db9, true);
	}

	@Test
	public void testEquate_actionNoShow() {
		decompile("1001915");

		ClangTextField line = getLineContaining("GetSystemMetrics(0x4e)");
		setDecompilerLocation(line.getLineNumber(), line.getText().indexOf("4e"));
		ConvertHexAction action = new ConvertHexAction(decompiler);
		assertFalse(action.isEnabledForContext(getContext()));
	}

	@Test
	public void testEquate_charNonAscii() {
		decompile("1002eab");

		ClangTextField line = getLineContaining("0xe0");
		setDecompilerLocation(line.getLineNumber(), line.getText().indexOf("0xe0"));
		convertToken(EquateSymbol.FORMAT_CHAR);
		line = getLineContaining("xe0");
		setDecompilerLocation(line.getLineNumber(), line.getText().indexOf("xe0"));
		verifyMatch("E0h", "'\\xe0'", 0x1002ec3, true);
	}
}
