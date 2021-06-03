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

import java.awt.Point;
import java.util.List;

import org.junit.After;
import org.junit.Before;

import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.ClangTextField;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.program.model.pcode.HighFunction;
import ghidra.test.AbstractProgramBasedTest;

public abstract class AbstractDecompilerTest extends AbstractProgramBasedTest {

	protected DecompilePlugin decompiler;
	protected DecompilerProvider provider;

	@Before
	public void setUp() throws Exception {

		super.initialize();

		decompiler = getPlugin(tool, DecompilePlugin.class);
		provider = getDecompilerProvider();
		showProvider("Decompiler"); // for debugging
	}

	@Override
	@After
	public void tearDown() throws Exception {
		waitForDecompiler();

		super.tearDown();
	}

	protected void decompile(long addr) {
		goTo(addr);
		waitForDecompiler();
	}

	protected void decompile(String addr) {
		goTo(addr);
		waitForDecompiler();
	}

	protected DecompilerProvider getDecompilerProvider() {
		Object theProvider = getInstanceField("connectedProvider", decompiler);
		return (DecompilerProvider) theProvider;
	}

	protected void waitForDecompiler() {
		waitForSwing();
		waitForCondition(() -> !provider.isBusy());
		waitForSwing();
	}

	protected void setDecompilerLocation(int line, int charPosition) {

		DecompilerPanel panel = provider.getDecompilerPanel();
		FieldPanel fp = panel.getFieldPanel();
		FieldLocation loc = loc(line, charPosition);

		// scroll to the field to make sure it has been built so that we can get its point
		fp.scrollTo(loc);
		Point p = fp.getPointForLocation(loc);

		click(fp, p, 1, true);
		waitForSwing();
	}

	protected void doubleClick() {
		DecompilerPanel panel = provider.getDecompilerPanel();
		FieldPanel fp = panel.getFieldPanel();
		click(fp, 2, true);
		waitForSwing();
	}

	protected FieldLocation loc(int lineNumber, int col) {
		FieldLocation loc = new FieldLocation(lineNumber - 1, 0, 0, col);
		return loc;
	}

	protected ClangTextField getFieldForLine(int lineNumber) {

		DecompilerPanel panel = provider.getDecompilerPanel();
		List<Field> fields = panel.getFields();
		Field line = fields.get(lineNumber - 1); // -1 for 1-based line number
		return (ClangTextField) line;
	}

	protected ClangTextField getFieldForLine(DecompilerProvider theProvider, int lineNumber) {

		DecompilerPanel panel = theProvider.getDecompilerPanel();
		List<Field> fields = panel.getFields();
		Field line = fields.get(lineNumber - 1); // -1 for 1-based line number
		return (ClangTextField) line;
	}

	// note: the index is 0-based; use getFieldForLine() when using 1-based line numbers
	protected ClangTextField getFieldForIndex(int lineIndex) {

		DecompilerPanel panel = provider.getDecompilerPanel();
		List<Field> fields = panel.getFields();
		Field line = fields.get(lineIndex);
		return (ClangTextField) line;
	}

	protected ClangToken getToken(int line, int col) {
		return getToken(loc(line, col));
	}

	protected ClangToken getToken(FieldLocation loc) {
		return getToken(provider, loc);
	}

	protected ClangToken getToken(DecompilerProvider theProvider, FieldLocation loc) {
		int lineNumber = loc.getIndex().intValue() + 1; // 0-based
		ClangTextField field = getFieldForLine(theProvider, lineNumber);
		ClangToken token = field.getToken(loc);
		return token;
	}

	protected DecompilerPanel getDecompilerPanel() {
		return provider.getDecompilerPanel();
	}

	/**
	 * Returns the token under the cursor
	 * @return the token under the cursor
	 */
	protected ClangToken getToken() {
		return getToken(provider);
	}

	protected ClangToken getToken(DecompilerProvider theProvider) {
		DecompilerPanel panel = theProvider.getDecompilerPanel();
		FieldLocation loc = panel.getCursorPosition();
		return getToken(theProvider, loc);
	}

	protected String getTokenText(FieldLocation loc) {
		ClangToken token = getToken(loc);
		return token.getText();
	}

	protected void assertToken(String tokenText, int line, int... cols) {
		for (int col : cols) {
			ClangToken token = getToken(line, col);
			String text = token.getText();
			assertEquals(tokenText, text);
		}
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

	protected ClangTextField getLineContaining(String val) {
		DecompilerPanel panel = provider.getDecompilerPanel();
		List<Field> fields = panel.getFields();
		for (Field field : fields) {
			ClangTextField textField = (ClangTextField) field;
			String text = textField.getText();
			if (text.contains(val)) {
				return textField;
			}
		}
		return null;
	}

	protected HighFunction getHighFunction() {
		return provider.getController().getHighFunction();
	}
}
