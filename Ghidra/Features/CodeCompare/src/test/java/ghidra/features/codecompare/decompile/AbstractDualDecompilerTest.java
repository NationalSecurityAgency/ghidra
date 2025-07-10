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
package ghidra.features.codecompare.decompile;

import java.awt.Point;
import java.util.Set;

import org.junit.After;
import org.junit.Before;

import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.ClangTextField;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.function.FunctionPlugin;
import ghidra.features.base.codecompare.panel.CodeComparisonPanel;
import ghidra.features.codecompare.plugin.FunctionComparisonPlugin;
import ghidra.features.codecompare.plugin.FunctionComparisonProvider;
import ghidra.program.model.listing.Function;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.datastruct.Duo.Side;

public abstract class AbstractDualDecompilerTest extends AbstractGhidraHeadedIntegrationTest {
	protected TestEnv env;
	protected FunctionComparisonPlugin fcPlugin;
	protected FunctionPlugin fPlugin;
	protected CodeBrowserPlugin cbPlugin;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		fcPlugin = env.addPlugin(FunctionComparisonPlugin.class);
		fPlugin = env.addPlugin(FunctionPlugin.class);
		cbPlugin = env.addPlugin(CodeBrowserPlugin.class);
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	protected FunctionComparisonProvider compareFunctions(Set<Function> functions) {
		runSwing(() -> fcPlugin.createComparison(functions));
		waitForSwing();
		return waitForComponentProvider(FunctionComparisonProvider.class);
	}

	protected DecompilerCodeComparisonPanel findDecompilerPanel(
			FunctionComparisonProvider provider) {
		for (CodeComparisonPanel panel : provider.getComponent().getComparisonPanels()) {
			if (panel instanceof DecompilerCodeComparisonPanel decompPanel) {
				return decompPanel;
			}
		}

		return null;
	}

	protected void setActivePanel(FunctionComparisonProvider provider, CodeComparisonPanel panel) {
		runSwing(() -> provider.getComponent().setCurrentTabbedComponent(panel.getName()));
		waitForSwing();
	}

	protected void waitForDecompile(DecompilerCodeComparisonPanel panel) {
		waitForSwing();
		waitForCondition(() -> !panel.isBusy());
		waitForSwing();
	}

	protected DecompilerPanel getDecompSide(DecompilerCodeComparisonPanel panel, Side side) {
		CDisplay sideDisplay = side == Side.LEFT ? panel.getLeftPanel() : panel.getRightPanel();
		return sideDisplay.getDecompilerPanel();
	}

	// 1-indexed lines
	protected ClangToken setDecompLocation(DecompilerCodeComparisonPanel comparePanel, Side side,
			int line, int charPos) {
		DecompilerPanel panel = getDecompSide(comparePanel, side);
		FieldPanel fp = panel.getFieldPanel();
		FieldLocation loc = new FieldLocation(line - 1, 0, 0, charPos); // 0-indexed lines

		fp.scrollTo(loc);

		Point p = fp.getPointForLocation(loc);

		click(fp, p, 1, true);

		waitForSwing();

		return getCurrentToken(comparePanel, side);
	}

	// Get the token under the cursor at the given side
	protected ClangToken getCurrentToken(DecompilerCodeComparisonPanel comparePanel, Side side) {
		DecompilerPanel panel = getDecompSide(comparePanel, side);
		FieldLocation loc = panel.getCursorPosition();
		int lineNumber = loc.getIndex().intValue();
		ClangTextField field = (ClangTextField) panel.getFields().get(lineNumber);
		return field.getToken(loc);
	}
}
