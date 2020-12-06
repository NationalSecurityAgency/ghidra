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

import java.awt.Dimension;
import java.awt.Window;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import docking.widgets.dialogs.ObjectChooserDialog;
import ghidra.app.util.pdb.PdbLocator;
import ghidra.util.Msg;
import pdb.URLChoice;

public class PdbScreenShots extends GhidraScreenShotGenerator {

	@Test
	public void testPdbOrXmlDialog() throws Exception {

		performAction("Download_PDB_File", "PdbSymbolServerPlugin", false);

		Window pdbDialog = waitForWindow("pdb or pdb.xml");
		pdbDialog.setSize(new Dimension(750, 200));
		captureWindow(pdbDialog);

		pressButtonByText(pdbDialog, "Cancel");
	}

	@Test
	public void testPeSpecifiedPathDialog() throws Exception {

		performAction("Download_PDB_File", "PdbSymbolServerPlugin", false);

		Window pdbDialog = waitForWindow("pdb or pdb.xml");
		pressButtonByText(pdbDialog, "PDB");

		Window peSpecifiedPathDialog = waitForWindow("PE-specified PDB Path");
		captureWindow(peSpecifiedPathDialog);

		pressButtonByText(peSpecifiedPathDialog, "Cancel");
	}

	@Test
	public void testSymbolServerURLDialog() throws Exception {

		// Set up for local directory
		PdbLocator.setDefaultPdbSymbolsDir(getTestDataDirectory());

		performAction("Download_PDB_File", "PdbSymbolServerPlugin", false);

		Window pdbDialog = waitForWindow("pdb or pdb.xml");
		pressButtonByText(pdbDialog, "PDB");

		Window peSpecifiedPathDialog = waitForWindow("PE-specified PDB Path");
		pressButtonByText(peSpecifiedPathDialog, "Yes");

		Window saveLocationDialog = waitForWindow("Select Location to Save Retrieved File");
		pressButtonByText(saveLocationDialog, "OK");

		Window urlDialog = waitForWindow("Symbol Server URL");
		urlDialog.setSize(new Dimension(850, 135));

		captureWindow(urlDialog);

		pressButtonByText(urlDialog, "Cancel");
	}

	@Test
	public void testKnownSymbolServerURLsDialog() throws Exception {

		List<URLChoice> urlChoices = new ArrayList<>();
		urlChoices.add(new URLChoice("Internet", "https://msdl.microsoft.com/download/symbols"));
		urlChoices.add(new URLChoice("My Network", "https://my_symbol_server.my.org"));

		final ObjectChooserDialog<URLChoice> urlDialog = new ObjectChooserDialog<>("Choose a URL",
			URLChoice.class, urlChoices, "getNetwork", "getUrl");

		runSwing(() -> {
			// Do nothing
		});
		showDialogWithoutBlocking(tool, urlDialog);
		captureDialog();

		pressButtonByText(urlDialog, "Cancel");
	}

	@Test
	public void testSuccessDialog() throws Exception {

		// Can't really get success message without actually downloading a file.
		// So, fake out the message by showing the same sort of dialog the user would see.
		Msg.showInfo(getClass(), null, "File Retrieved",
			"Downloaded and saved file 'example.pdb' to \n" +
				"C:\\Symbols\\example.pdb\\1123A456B7889012C3DDFA4556789B011");

		Window successDialog = waitForWindow("File Retrieved");
		captureWindow(successDialog);

		pressButtonByText(successDialog, "OK");
	}
}
