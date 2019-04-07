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

import org.junit.After;
import org.junit.Before;

import docking.widgets.fieldpanel.FieldPanel;
import ghidra.app.decompiler.component.DecompilerPanel;
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
		waitForCondition(() -> !provider.isDecompiling());
		waitForSwing();
	}

	protected void setDecompilerLocation(int line, int charPosition) {
		runSwing(() -> provider.setCursorLocation(line, charPosition));
	}

	protected void doubleClick() {
		DecompilerPanel panel = provider.getDecompilerPanel();
		FieldPanel fp = panel.getFieldPanel();
		click(fp, 2, true);
	}
}
