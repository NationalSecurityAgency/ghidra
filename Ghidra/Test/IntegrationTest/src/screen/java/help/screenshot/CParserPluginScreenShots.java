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

import org.junit.Test;

import docking.DialogComponentProvider;
import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.cparser.CParserPlugin;
import ghidra.util.Msg;

public class CParserPluginScreenShots extends GhidraScreenShotGenerator {

	@Override
	public void setUp() throws Exception {

		super.setUp();
		loadPlugin(CParserPlugin.class);
	}

	@Test
	public void testParseCSource() {

		performAction("Import C DataTypes", "CParserPlugin", false);
		captureDialog();
		closeAllWindowsAndFrames();
	}

	@Test
	public void testParseError() {
		Msg.showInfo(getClass(), null, "Parse Errors",
			"C Parser: Encountered errors during parse.\n" +
				"        in C:\\tmp\\samp.h near line 12\n " +
				"       near token: \"This function or variable may be unsafe. Consider using \" \n" +
				"        Last Valid Dataype: PCUWSTR");
		captureDialog();
		closeAllWindowsAndFrames();
	}

	@Test
	public void testUseOpenArchives() {

		performAction("Import C DataTypes", "CParserPlugin", false);

		DialogComponentProvider parseDialog = getDialog();
		pressButtonByText(parseDialog, "Parse to Program", false);

		OptionDialog confirmDialog =
			waitForDialogComponent(null, OptionDialog.class, DEFAULT_WINDOW_TIMEOUT);
		pressButtonByText(confirmDialog, "Continue");

		OptionDialog useOpenArchivesDialog = waitForDialogComponent(null, OptionDialog.class, 5000);

		captureDialog(useOpenArchivesDialog);
		closeAllWindowsAndFrames();
	}

}
