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
package ghidra.app.decompiler.component;

import org.junit.Before;
import org.junit.Test;

import docking.action.DockingActionIf;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompileOptions.NamespaceStrategy;
import ghidra.app.plugin.core.decompile.AbstractDecompilerTest;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.util.OptionsService;

public class DecompilerClang2Test extends AbstractDecompilerTest {

	@Override
	@Before
	public void setUp() throws Exception {

		super.setUp();
		OptionsService service = provider.getTool().getService(OptionsService.class);
		ToolOptions opt = service.getOptions("Decompiler");
		opt.setEnum("Display.Display Namespaces", NamespaceStrategy.Never);
	}

	@Override
	protected String getProgramName() {
		return "Winmine__XP.exe.gzf";
	}

	@Test
	public void testGoToNextBrace() {

		/*
		 
			void FUN_01002ed5(void)
			
			{
			  int iVar1;
			  int iVar2;
			  int iVar3;
			  undefined *puVar5;
			  undefined *puVar6;
			  int iVar7;
			  int iVar4;
			  
			  iVar4 = 0x360;
			  do {
			    iVar2 = iVar4 + -1;
			    *(undefined *)(iVar4 + 0x100533f) = 0xf;
			    iVar7 = DAT_01005338;
			    iVar1 = DAT_01005334;
			    iVar4 = iVar2;
			  } while (iVar2 != 0);
			  if (DAT_01005334 + 2 != 0) {
			    iVar2 = DAT_01005338 * 0x20;
			    iVar4 = DAT_01005334 + 2;
			    do {
			      iVar3 = iVar4 + -1;
			      *(undefined *)(iVar4 + 0x100533f) = 0x10;
			      (&DAT_01005360)[iVar3 + iVar2] = 0x10;
			      iVar4 = iVar3;
			    } while (iVar3 != 0);
			  }
			  iVar7 = iVar7 + 2;
			  if (iVar7 != 0) {
			    puVar6 = &DAT_01005340 + iVar7 * 0x20;
			    puVar5 = &DAT_01005341 + iVar1 + iVar7 * 0x20;
			    do {
			      puVar6 = puVar6 + -0x20;
			      puVar5 = puVar5 + -0x20;
			      iVar7 = iVar7 + -1;
			      *puVar6 = 0x10;
			      *puVar5 = 0x10;
			    } while (iVar7 != 0);
			  }
			  return;
			}
		
		 */

		//
		// This test will put the cursor on a line that is nested 3 levels deep.
		//

		decompile("01002ed5"); // 'main'

		int line = 26; 	// iVar3 = iVar4 + -1;
		int charPosition = 2;
		setDecompilerLocation(line, charPosition);

		goToNextBrace();
		assertClosingBrace(29);

		goToNextBrace();
		assertClosingBrace(30);

		goToNextBrace();
		assertClosingBrace(44);

		// at the last brace; no change
		goToNextBrace();
		assertClosingBrace(44);
	}

	@Test
	public void testGoToNextBrace_AlreadyOnBrace() {

		//
		// This test will put the cursor on a line that is nested 3 levels deep.
		//

		decompile("01002ed5"); // 'main'

		int line = 24; 	// iVar3 = iVar4 + -1;
		int charPosition = 4;
		setDecompilerLocation(line, charPosition);

		goToNextBrace();
		assertClosingBrace(29);

		goToNextBrace();
		assertClosingBrace(30);

		goToNextBrace();
		assertClosingBrace(44);

		// at the last brace; no change
		goToNextBrace();
		assertClosingBrace(44);
	}

	@Test
	public void testGoToPreviousBrace() {

		/*
		 
			void FUN_01002ed5(void)
			
			{
			  int iVar1;
			  int iVar2;
			  int iVar3;
			  undefined *puVar5;
			  undefined *puVar6;
			  int iVar7;
			  int iVar4;
			  
			  iVar4 = 0x360;
			  do {
			    iVar2 = iVar4 + -1;
			    *(undefined *)(iVar4 + 0x100533f) = 0xf;
			    iVar7 = DAT_01005338;
			    iVar1 = DAT_01005334;
			    iVar4 = iVar2;
			  } while (iVar2 != 0);
			  if (DAT_01005334 + 2 != 0) {
			    iVar2 = DAT_01005338 * 0x20;
			    iVar4 = DAT_01005334 + 2;
			    do {
			      iVar3 = iVar4 + -1;
			      *(undefined *)(iVar4 + 0x100533f) = 0x10;
			      (&DAT_01005360)[iVar3 + iVar2] = 0x10;
			      iVar4 = iVar3;
			    } while (iVar3 != 0);
			  }
			  iVar7 = iVar7 + 2;
			  if (iVar7 != 0) {
			    puVar6 = &DAT_01005340 + iVar7 * 0x20;
			    puVar5 = &DAT_01005341 + iVar1 + iVar7 * 0x20;
			    do {
			      puVar6 = puVar6 + -0x20;
			      puVar5 = puVar5 + -0x20;
			      iVar7 = iVar7 + -1;
			      *puVar6 = 0x10;
			      *puVar5 = 0x10;
			    } while (iVar7 != 0);
			  }
			  return;
			}
		
		 */

		//
		// This test will put the cursor on a line that is nested 3 levels deep.
		//

		decompile("01002ed5"); // 'main'

		int line = 26; 	// iVar3 = iVar4 + -1;
		int charPosition = 2;
		setDecompilerLocation(line, charPosition);

		goToPreviousBrace();
		assertOpeningBrace(24);

		goToPreviousBrace();
		assertOpeningBrace(21);

		goToPreviousBrace();
		assertOpeningBrace(4);

		// at the first brace; no change
		goToPreviousBrace();
		assertOpeningBrace(4);
	}

	@Test
	public void testGoToPreviousBrace_AlreadyOnBrace() {

		decompile("01002ed5"); // 'main'

		int line = 29; 	// iVar3 = iVar4 + -1;
		int charPosition = 0;
		setDecompilerLocation(line, charPosition);

		goToPreviousBrace();
		assertOpeningBrace(24);

		goToPreviousBrace();
		assertOpeningBrace(21);

		goToPreviousBrace();
		assertOpeningBrace(4);

		// at the first brace; no change
		goToPreviousBrace();
		assertOpeningBrace(4);
	}

	private void goToNextBrace() {
		DockingActionIf action = getAction(decompiler, "Go To Next Brace");
		performAction(action, provider.getActionContext(null), true);
		waitForDecompiler();
	}

	private void goToPreviousBrace() {
		DockingActionIf action = getAction(decompiler, "Go To Previous Brace");
		performAction(action, provider.getActionContext(null), true);
		waitForDecompiler();
	}

	private void assertOpeningBrace(int line) {

		waitForCondition(() -> {
			ClangToken token = getToken();
			int actualLine = token.getLineParent().getLineNumber();
			if (line != actualLine) {
				return false;
			}
			String text = token.getText();
			return "{".equals(text);
		}, "Cursor is not on opening brace at line " + line);
	}

	private void assertClosingBrace(int line) {

		waitForCondition(() -> {
			ClangToken token = getToken();
			int actualLine = token.getLineParent().getLineNumber();
			if (line != actualLine) {
				return false;
			}
			String text = token.getText();
			return "}".equals(text);
		}, "Cursor is not on closing brace at line " + line);
	}

}
