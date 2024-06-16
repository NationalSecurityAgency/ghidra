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

import java.nio.charset.StandardCharsets;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.core.strings.EncodedStringsDialog;
import ghidra.app.plugin.core.strings.EncodedStringsPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.HelpTopics;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.Swing;

public class EncodedStringsDialogScreenShots extends GhidraScreenShotGenerator {

	private EncodedStringsPlugin plugin;

	public EncodedStringsDialogScreenShots() {
		super();
	}

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		plugin = env.addPlugin(EncodedStringsPlugin.class);
	}

	@Override
	public void loadProgram() throws Exception {

		ToyProgramBuilder builder = new ToyProgramBuilder("String Examples", false);
		builder.createMemory("RAM", "0x0", 0x2000);

		builder.createString("0x100", "Hello World!\n", StandardCharsets.US_ASCII, true, null);

		builder.createString("0x150", bytes(0, 1, 2, 3, 4, 0x80, 0x81, 0x82, 0x83),
			StandardCharsets.US_ASCII, null);

		builder.createString("0x200", "\u6211\u96bb\u6c23\u588a\u8239\u88dd\u6eff\u6652\u9c54",
			StandardCharsets.UTF_16, true, null);

		builder.createString("0x250", "Exception %s\n\tline: %d\n", StandardCharsets.US_ASCII, true,
			null);

		builder.createString("0x330", "A: \u6211\u96bb\u6c23\u588a\u8239\u88dd\u6eff\u6652\u9c54",
			StandardCharsets.UTF_8, true, null);

		builder.createString("0x450",
			"Roses are \u001b[0;31mred\u001b[0m, violets are \u001b[0;34mblue. Hope you enjoy terminal hue",
			StandardCharsets.US_ASCII, true, null);

		program = builder.getProgram();

		runSwing(() -> {
			ProgramManager pm = tool.getService(ProgramManager.class);
			pm.openProgram(program.getDomainFile());
		});

	}

	@Override
	protected String getHelpTopicName() {
		return HelpTopics.SEARCH;
	}

	@Test
	public void testEncodedStringsDialog_initial() {
		positionListingTop(0x50);
		makeSelection(0x50, 0x500);
		performAction(plugin.getSearchForEncodedStringsAction());

		EncodedStringsDialog dialog = waitForDialogComponent(EncodedStringsDialog.class);
		waitForTableModel(dialog.getStringModel());

		captureDialog(600, 300);
	}

	@Test
	public void testEncodedStringsDialog_advancedoptions() {
		positionListingTop(0x50);
		makeSelection(0x50, 0x500);
		performAction(plugin.getSearchForEncodedStringsAction());

		EncodedStringsDialog dialog = waitForDialogComponent(EncodedStringsDialog.class);
		Swing.runNow(() -> {
			dialog.setShowAdvancedOptions(true);
			dialog.setShowScriptOptions(true);
			dialog.setAllowAnyScriptOption(true);
			dialog.setRequireValidStringOption(false);
			dialog.setSelectedCharset("UTF-8");
		});
		waitForTableModel(dialog.getStringModel());

		captureDialog(600, 450);
	}

}
