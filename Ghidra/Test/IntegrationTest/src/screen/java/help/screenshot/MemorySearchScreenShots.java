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

import java.awt.*;

import org.junit.Before;
import org.junit.Test;

import docking.action.DockingActionIf;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.features.base.memsearch.format.SearchFormat;
import ghidra.features.base.memsearch.gui.MemorySearchProvider;
import ghidra.features.base.memsearch.gui.SearchSettings;
import ghidra.features.base.memsearch.mnemonic.MnemonicSearchPlugin;
import ghidra.program.model.address.*;

/**
 * Screenshots for help/topics/Search/Search_Memory.htm
 */
public class MemorySearchScreenShots extends AbstractSearchScreenShots {

	private CodeBrowserPlugin cb;
	private MnemonicSearchPlugin mnemonicSearchPlugin;

	@Override
	@Before
	public void setUp() throws Exception {

		super.setUp();

		mnemonicSearchPlugin = env.getPlugin(MnemonicSearchPlugin.class);
		cb = env.getPlugin(CodeBrowserPlugin.class);

		env.showTool();
	}

	@Test
	public void testMemorySearchProvider() {
		performAction("Memory Search", "MemorySearchPlugin", false);
		waitForSwing();

		MemorySearchProvider provider = getComponentProvider(MemorySearchProvider.class);

		runSwing(() -> provider.setSearchInput("12 34"));

		captureIsolatedProvider(provider, 700, 400);

	}

	@Test
	public void testMemorySearchProviderWithOptionsOn() {
		performAction("Memory Search", "MemorySearchPlugin", false);
		waitForSwing();

		MemorySearchProvider provider = getComponentProvider(MemorySearchProvider.class);

		runSwing(() -> {
			provider.setSearchInput("12 34");
			provider.showOptions(true);
		});

		captureIsolatedProvider(provider, 700, 650);
	}

	@Test
	public void testMemorySearchProviderWithScanPanelOn() {
		performAction("Memory Search", "MemorySearchPlugin", false);
		waitForSwing();

		MemorySearchProvider provider = getComponentProvider(MemorySearchProvider.class);

		runSwing(() -> {
			provider.setSearchInput("12 34");
			provider.showScanPanel(true);
		});

		captureIsolatedProvider(provider, 700, 500);
	}

	@Test
	public void testSearchInstructions() {
		Font font = new Font("Monospaced", Font.PLAIN, 14);
		Color selectionColor = Palette.getColor("palegreen");
		TextFormatter tf = new TextFormatter(font, 8, 500, 4, 5, 2);
		TextFormatterContext blue = new TextFormatterContext(Palette.BLUE);
		TextFormatterContext navyBlue = new TextFormatterContext(NAVY);
		TextFormatterContext darkGreen = new TextFormatterContext(DARK_GREEN);
		TextFormatterContext orange = new TextFormatterContext(YELLOW_ORANGE);
		tf.colorLines(selectionColor, 3, 4);

		// @formatter:off
		tf.writeln("                         LAB_00401e8c");
		tf.writeln("    00401e8c |a1 20 0d|     |MOV|      |EAX|,DAT_00410d20]", blue, navyBlue, orange);
		tf.writeln("             |41 00|                                   ", blue);
		tf.writeln("    00401e91 |85 c0|        |TEST|     |EAX|,|EAX|", blue, navyBlue, orange, orange);
		tf.writeln("    00401e93 |56|           |PUSH|     |ESI|", blue, navyBlue, orange);
		tf.writeln("    00401e94 |6a 14|        |PUSH|     |0x14|", blue, navyBlue, darkGreen);
		tf.writeln("    00401e96 |5e|           |POP|      |ESI|", blue, navyBlue, orange);
		tf.writeln("    00401e97 |75 07|        |JNZ|      LAB_00401ea0", blue, navyBlue);
		// @formatter:on

		image = tf.getImage();
	}

	@Test
	public void testSearchInstructionsIncludeOperands() {
		Font font = new Font("Monospaced", Font.PLAIN, 14);
		TextFormatter tf = new TextFormatter(font, 4, 300, 4, 5, 2);
		TextFormatterContext blue = new TextFormatterContext(Palette.BLUE);
		TextFormatterContext navy = new TextFormatterContext(NAVY);
		TextFormatterContext darkGreen = new TextFormatterContext(DARK_GREEN);
		TextFormatterContext orange = new TextFormatterContext(YELLOW_ORANGE);

		tf.writeln(" |85 c0|      |TEST|     |EAX|,|EAX|", blue, navy, orange, orange);
		tf.writeln(" |56|         |PUSH|     |ESI|      ", blue, navy, orange);
		tf.writeln(" |6a 14|      |PUSH|     |0x14|     ", blue, navy, darkGreen);
		tf.writeln(" |5e|         |POP|      |ESI|      ", blue, navy, orange);

		image = tf.getImage();
	}

	@Test
	public void testSearchMemoryRegex() {
		performAction("Memory Search", "MemorySearchPlugin", false);
		waitForSwing();

		MemorySearchProvider provider = getComponentProvider(MemorySearchProvider.class);

		runSwing(() -> {
			provider.setSettings(new SearchSettings().withSearchFormat(SearchFormat.REG_EX));
			provider.setSearchInput("\\x50.{0,10}\\x55");
		});

		captureIsolatedProvider(provider, 700, 300);
	}

	@Test
	public void testSearchInstructionsExcludeOperands() {
		Font font = new Font("Monospaced", Font.PLAIN, 14);
		TextFormatter tf = new TextFormatter(font, 4, 80, 4, 5, 2);
		TextFormatterContext navy = new TextFormatterContext(NAVY);

		tf.writeln(" |TEST|", navy);
		tf.writeln(" |PUSH|", navy);
		tf.writeln(" |PUSH|", navy);
		tf.writeln(" |POP| ", navy);
		image = tf.getImage();
	}

	@Test
	public void testSearchInstructionsIncludeOperandsNoConsts() {
		Font font = new Font("Monospaced", Font.PLAIN, 14);
		TextFormatter tf = new TextFormatter(font, 4, 200, 4, 5, 2);
		TextFormatterContext navy = new TextFormatterContext(NAVY);
		TextFormatterContext darkGreen = new TextFormatterContext(DARK_GREEN);
		TextFormatterContext orange = new TextFormatterContext(YELLOW_ORANGE);

		tf.writeln(" |TEST|     |EAX|,|EAX|", navy, orange, orange);
		tf.writeln(" |PUSH|     |ESI|      ", navy, orange);
		tf.writeln(" |PUSH|     N          ", navy, darkGreen);
		tf.writeln(" |POP|      |ESI|      ", navy, orange);

		image = tf.getImage();
	}

	/**
	 * Captures the error dialog displayed when trying to search with multiple selections.
	 */
	@Test
	public void testMultipleSelectionError() {

		// First set up two selection ranges.
		AddressRange range1 = new AddressRangeImpl(addr(0x00407267), addr(0x00407268));
		AddressRange range2 = new AddressRangeImpl(addr(0x0040726c), addr(0x0040726e));
		AddressSet addrSet = new AddressSet();
		addrSet.add(range1);
		addrSet.add(range2);

		// Create an event that we can fire to all subscribers, and send it.
		makeSelection(tool, program, addrSet);

		// Now invoke the menu option we want to test.
		CodeViewerProvider provider = cb.getProvider();
		DockingActionIf action = getAction(mnemonicSearchPlugin, "Include Operands");
		performAction(action, provider, false);

		// And capture the error dialog.
		Window errorDialog = waitForWindow("Mnemonic Search Error");
		captureWindow(errorDialog);
	}
}
