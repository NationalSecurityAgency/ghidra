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
package help.screenshot;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.features.base.replace.*;

/**
 * Screenshots for help/topics/Search/Search_Memory.htm
 */
public class SearchAndReplaceScreenShots extends AbstractSearchScreenShots {

	private CodeBrowserPlugin cb;
	private SearchAndReplacePlugin plugin;

	@Override
	@Before
	public void setUp() throws Exception {

		super.setUp();

		plugin = env.getPlugin(SearchAndReplacePlugin.class);
		cb = env.getPlugin(CodeBrowserPlugin.class);

		env.showTool();
	}

	@Test
	public void testSearchAndReplaceDialog() {
		performAction("Search And Replace", "SearchAndReplacePlugin", false);
		waitForSwing();

		SearchAndReplaceDialog dialog =
			(SearchAndReplaceDialog) getDialog(SearchAndReplaceDialog.class);

		runSwing(() -> {
			dialog.setSarchAndReplaceText("value", "amount");
			dialog.selectSearchType("Labels");
			dialog.selectSearchType("Functions");
			dialog.selectSearchType("Comments");
			dialog.selectSearchType("Datatypes");
			dialog.selectSearchType("Datatype Fields");
			dialog.selectSearchType("Datatype Comments");
			dialog.selectSearchType("Parameters");
		});

		captureDialog(dialog);

	}

	@Test
	public void testSearchAndReplaceResults() {
		performAction("Search And Replace", "SearchAndReplacePlugin", false);
		waitForSwing();

		SearchAndReplaceDialog dialog =
			(SearchAndReplaceDialog) getDialog(SearchAndReplaceDialog.class);

		runSwing(() -> {
			dialog.setSarchAndReplaceText("value", "amount");
			dialog.selectSearchType("Labels");
			dialog.selectSearchType("Functions");
			dialog.selectSearchType("Comments");
			dialog.selectSearchType("Datatypes");
			dialog.selectSearchType("Datatype Fields");
			dialog.selectSearchType("Datatype Comments");
			dialog.selectSearchType("Parameters");
		});
		pressOkOnDialog();

		SearchAndReplaceProvider provider =
			waitForComponentProvider(SearchAndReplaceProvider.class);

		captureIsolatedProvider(provider, 700, 500);
	}
}
