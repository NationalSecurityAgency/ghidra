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

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.component.ClangTextField;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.core.decompile.actions.RenameGlobalVariableTask;
import ghidra.program.database.symbol.CodeSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.pcode.*;

public class HighSymbolTest extends AbstractDecompilerTest {
	@Override
	protected String getProgramName() {
		return "Winmine__XP.exe.gzf";
	}

	protected ClangTextField getLineStarting(String val) {
		DecompilerPanel panel = provider.getDecompilerPanel();
		List<Field> fields = panel.getFields();
		for (Field field : fields) {
			ClangTextField textField = (ClangTextField) field;
			String text = textField.getText().trim();
			if (text.startsWith(val)) {
				return textField;
			}
		}
		return null;
	}

	private void renameGlobalVariable(HighSymbol highSymbol, HighVariable highVar, Varnode exact,
			String newName) {
		Address addr = highSymbol.getStorage().getMinAddress();
		RenameGlobalVariableTask rename = new RenameGlobalVariableTask(provider.getTool(),
			highSymbol.getName(), addr, highSymbol.getProgram());

		assertTrue(rename.isValid("newGlobal"));
		modifyProgram(p -> {
			rename.commit();
		});
	}

	@Test
	public void testHighSymbol_globalRename() {

		decompile("1001b49");

		ClangTextField line = getLineStarting("DAT_010056a0");
		FieldLocation loc = loc(line.getLineNumber(), 5);
		ClangToken token = line.getToken(loc);
		assertTrue(token instanceof ClangVariableToken);
		HighVariable variable = token.getHighVariable();
		assertTrue(variable instanceof HighGlobal);
		HighSymbol highSymbol = variable.getSymbol();
		assertTrue(highSymbol instanceof HighCodeSymbol);
		HighCodeSymbol highCode = (HighCodeSymbol) highSymbol;
		CodeSymbol codeSymbol = highCode.getCodeSymbol();
		assertNull(codeSymbol);	// A DAT_ should not have a permanent CodeSymbol
		Data data = highCode.getData();
		assertNotNull(data);
		assertEquals(data.getAddress().getOffset(), 0x10056a0L);
		assertEquals(data.getBaseDataType().getLength(), 2);

		renameGlobalVariable(highSymbol, variable, null, "newGlobal");
		waitForDecompiler();
		line = getLineStarting("newGlobal");
		loc = loc(line.getLineNumber(), 5);
		token = line.getToken(loc);
		assertTrue(token instanceof ClangVariableToken);
		variable = token.getHighVariable();
		assertTrue(variable instanceof HighGlobal);
		highSymbol = variable.getSymbol();
		assertTrue(highSymbol instanceof HighCodeSymbol);
		highCode = (HighCodeSymbol) highSymbol;
		assertTrue(highCode.isGlobal());
		assertTrue(highCode.isNameLocked());
		assertTrue(highCode.isTypeLocked());
		codeSymbol = highCode.getCodeSymbol();
		assertNotNull(codeSymbol);
		assertEquals(codeSymbol.getID(), highCode.getId());
	}
}
