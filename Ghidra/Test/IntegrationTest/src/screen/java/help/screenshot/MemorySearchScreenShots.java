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

import javax.swing.*;

import org.junit.Before;
import org.junit.Test;

import docking.DialogComponentProvider;
import docking.action.DockingActionIf;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.searchmem.mask.MnemonicSearchPlugin;
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
	public void testSearchMemoryHex() {

		moveTool(500, 500);

		performAction("Search Memory", "MemSearchPlugin", false);
		waitForSwing();

		DialogComponentProvider dialog = getDialog();
		JTextField textField = (JTextField) getInstanceField("valueField", dialog);
		setText(textField, "12 34");

		JToggleButton button = (JToggleButton) getInstanceField("advancedButton", dialog);
		pressButton(button);

		waitForSwing();

		captureDialog(DialogComponentProvider.class);
	}

	@Test
	public void testSearchMemoryRegex() {

		moveTool(500, 500);

		performAction("Search Memory", "MemSearchPlugin", false);
		waitForSwing();

		DialogComponentProvider dialog = getDialog();
		JRadioButton regexRadioButton =
			(JRadioButton) findAbstractButtonByText(dialog.getComponent(), "Regular Expression");
		pressButton(regexRadioButton);

		JTextField textField = (JTextField) getInstanceField("valueField", dialog);
		setText(textField, "\\x50.{0,10}\\x55");

		JToggleButton button = (JToggleButton) getInstanceField("advancedButton", dialog);
		pressButton(button);

		waitForSwing();

		captureDialog(DialogComponentProvider.class);
	}

	@Test
	public void testSearchMemoryBinary() {

		moveTool(500, 500);

		performAction("Search Memory", "MemSearchPlugin", false);
		waitForSwing();

		DialogComponentProvider dialog = getDialog();
		JRadioButton binaryRadioButton =
			(JRadioButton) findAbstractButtonByText(dialog.getComponent(), "Binary");
		pressButton(binaryRadioButton);

		JTextField textField = (JTextField) getInstanceField("valueField", dialog);
		setText(textField, "10xx0011");

		JToggleButton button = (JToggleButton) getInstanceField("advancedButton", dialog);
		pressButton(button);

		waitForSwing();

		captureDialog(DialogComponentProvider.class);
	}

	@Test
	public void testSearchMemoryDecimal() {

		moveTool(500, 500);

		performAction("Search Memory", "MemSearchPlugin", false);
		waitForSwing();

		DialogComponentProvider dialog = getDialog();
		JRadioButton decimalRadioButton =
			(JRadioButton) findAbstractButtonByText(dialog.getComponent(), "Decimal");
		pressButton(decimalRadioButton);

		JTextField textField = (JTextField) getInstanceField("valueField", dialog);
		setText(textField, "1234");

		JToggleButton button = (JToggleButton) getInstanceField("advancedButton", dialog);
		pressButton(button);

		waitForSwing();

		captureDialog(DialogComponentProvider.class);
	}

	@Test
	public void testSearchMemoryString() {

		moveTool(500, 500);

		performAction("Search Memory", "MemSearchPlugin", false);
		waitForSwing();

		DialogComponentProvider dialog = getDialog();
		JRadioButton stringRadioButton =
			(JRadioButton) findAbstractButtonByText(dialog.getComponent(), "String");
		pressButton(stringRadioButton);

		JTextField textField = (JTextField) getInstanceField("valueField", dialog);
		setText(textField, "Hello");

		JToggleButton button = (JToggleButton) getInstanceField("advancedButton", dialog);
		pressButton(button);

		waitForSwing();

		captureDialog(DialogComponentProvider.class);
	}

	@Test
	public void testSearchInstructions() {
		Font font = new Font("Monospaced", Font.PLAIN, 14);
		Color selectionColor = new Color(180, 255, 180);
		TextFormatter tf = new TextFormatter(font, 8, 500, 4, 5, 2);
		TextFormatterContext blue = new TextFormatterContext(Color.BLUE);
		TextFormatterContext darkBlue = new TextFormatterContext(DARK_BLUE);
		TextFormatterContext darkGreen = new TextFormatterContext(DARK_GREEN);
		TextFormatterContext orange = new TextFormatterContext(YELLOW_ORANGE);
		tf.colorLines(selectionColor, 3, 4);

		// @formatter:off
		tf.writeln("                         LAB_00401e8c");
		tf.writeln("    00401e8c |a1 20 0d|     |MOV|      |EAX|,DAT_00410d20]", blue, darkBlue, orange);
		tf.writeln("             |41 00|                                   ", blue);
		tf.writeln("    00401e91 |85 c0|        |TEST|     |EAX|,|EAX|", blue, darkBlue, orange, orange);
		tf.writeln("    00401e93 |56|           |PUSH|     |ESI|", blue, darkBlue, orange);
		tf.writeln("    00401e94 |6a 14|        |PUSH|     |0x14|", blue, darkBlue, darkGreen);
		tf.writeln("    00401e96 |5e|           |POP|      |ESI|", blue, darkBlue, orange);
		tf.writeln("    00401e97 |75 07|        |JNZ|      LAB_00401ea0", blue, darkBlue);
		// @formatter:on

		image = tf.getImage();
	}

	@Test
	public void testSearchInstructionsIncludeOperands() {
		Font font = new Font("Monospaced", Font.PLAIN, 14);
		TextFormatter tf = new TextFormatter(font, 4, 300, 4, 5, 2);
		TextFormatterContext blue = new TextFormatterContext(Color.BLUE);
		TextFormatterContext darkBlue = new TextFormatterContext(DARK_BLUE);
		TextFormatterContext darkGreen = new TextFormatterContext(DARK_GREEN);
		TextFormatterContext orange = new TextFormatterContext(YELLOW_ORANGE);

		tf.writeln(" |85 c0|      |TEST|     |EAX|,|EAX|", blue, darkBlue, orange, orange);
		tf.writeln(" |56|         |PUSH|     |ESI|      ", blue, darkBlue, orange);
		tf.writeln(" |6a 14|      |PUSH|     |0x14|     ", blue, darkBlue, darkGreen);
		tf.writeln(" |5e|         |POP|      |ESI|      ", blue, darkBlue, orange);

		image = tf.getImage();
	}

	@Test
	public void testSearchInstructionsExcludeOperands() {
		Font font = new Font("Monospaced", Font.PLAIN, 14);
		TextFormatter tf = new TextFormatter(font, 4, 80, 4, 5, 2);
		TextFormatterContext darkBlue = new TextFormatterContext(DARK_BLUE);

		tf.writeln(" |TEST|", darkBlue);
		tf.writeln(" |PUSH|", darkBlue);
		tf.writeln(" |PUSH|", darkBlue);
		tf.writeln(" |POP| ", darkBlue);
		image = tf.getImage();
	}

	@Test
	public void testSearchInstructionsIncludeOperandsNoConsts() {
		Font font = new Font("Monospaced", Font.PLAIN, 14);
		TextFormatter tf = new TextFormatter(font, 4, 200, 4, 5, 2);
		TextFormatterContext darkBlue = new TextFormatterContext(DARK_BLUE);
		TextFormatterContext darkGreen = new TextFormatterContext(DARK_GREEN);
		TextFormatterContext orange = new TextFormatterContext(YELLOW_ORANGE);

		tf.writeln(" |TEST|     |EAX|,|EAX|", darkBlue, orange, orange);
		tf.writeln(" |PUSH|     |ESI|      ", darkBlue, orange);
		tf.writeln(" |PUSH|     N          ", darkBlue, darkGreen);
		tf.writeln(" |POP|      |ESI|      ", darkBlue, orange);

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
		Window errorDialog = waitForWindow("Mnemonic Search Error", 2000);
		captureWindow(errorDialog);
	}
}
