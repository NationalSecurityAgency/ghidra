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
package ghidra.framework.main;

import static org.junit.Assert.assertEquals;

import java.util.function.Supplier;

import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.text.Document;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.framework.plugintool.DummyPluginTool;

public class ConsoleTextPaneTest {

	private int runNumber = 1;

	@Test
	public void testScrollLock_Unlocked() throws Exception {

		DummyPluginTool tool = swing(() -> new DummyPluginTool());
		ConsoleTextPane text = new ConsoleTextPane(tool);
		text.setMaximumCharacterLimit(100);
		text.setScrollLock(false);

		JFrame frame = new JFrame();
		frame.setSize(600, 400);

		JScrollPane scroller = new JScrollPane(text);
		frame.getContentPane().add(scroller);
		frame.setVisible(true);

		printEnoughLinesToOverflowTheMaxCharCount(text);

		assertCaretAtBottom(text);
	}

	@Test
	public void testScrollLock_Locked() throws Exception {

		DummyPluginTool tool = swing(() -> new DummyPluginTool());
		ConsoleTextPane text = new ConsoleTextPane(tool);
		text.setMaximumCharacterLimit(100);
		text.setScrollLock(true);

		JFrame frame = new JFrame();
		frame.setSize(600, 400);

		JScrollPane scroller = new JScrollPane(text);
		frame.getContentPane().add(scroller);
		frame.setVisible(true);

		swing(() -> text.addMessage("Initial text..."));
		int arbitraryPosition = 5;
		setCaret(text, arbitraryPosition);

		printEnoughLinesToOverflowTheMaxCharCount(text);

		assertCaretPosition(text, arbitraryPosition);
	}

	@Test
	public void testScrollLock_Unlocked_Locked_Unlocked() throws Exception {

		DummyPluginTool tool = swing(() -> new DummyPluginTool());
		ConsoleTextPane text = new ConsoleTextPane(tool);
		text.setMaximumCharacterLimit(100);
		text.setScrollLock(false);

		JFrame frame = new JFrame();
		frame.setSize(600, 400);

		JScrollPane scroller = new JScrollPane(text);
		frame.getContentPane().add(scroller);
		frame.setVisible(true);

		printEnoughLinesToOverflowTheMaxCharCount(text);
		assertCaretAtBottom(text);

		text.setScrollLock(true);
		setCaret(text, 0);
		printEnoughLinesToOverflowTheMaxCharCount(text);
		assertCaretAtTop(text);

		text.setScrollLock(false);
		printEnoughLinesToOverflowTheMaxCharCount(text);
		assertCaretAtBottom(text);
	}

	private void setCaret(ConsoleTextPane text, int position) {
		swing(() -> text.setCaretPosition(position));
	}

	private void assertCaretAtTop(ConsoleTextPane text) {

		AbstractGenericTest.waitForSwing();
		int expectedPosition = 0;
		assertCaretPosition(text, expectedPosition);
	}

	private void assertCaretAtBottom(ConsoleTextPane text) {

		AbstractGenericTest.waitForSwing();
		int expectedPosition = text.getDocument().getLength();
		assertCaretPosition(text, expectedPosition);
	}

	private void assertCaretPosition(ConsoleTextPane text, int expectedPosition) {

		AbstractGenericTest.waitForSwing();
		Document doc = text.getDocument();
		int actualPosition = swing(() -> text.getCaretPosition());
		assertEquals(expectedPosition, actualPosition);
	}

	private void printEnoughLinesToOverflowTheMaxCharCount(ConsoleTextPane text) {
		AbstractGenericTest.runSwing(() -> {

			for (int i = 0; i < 20; i++) {
				text.addMessage("Run " + runNumber + " - line " + (i + 1) + '\n');
			}
		});

		runNumber++;
	}

	private void swing(Runnable r) {
		AbstractGenericTest.runSwing(r);
	}

	private <T> T swing(Supplier<T> s) {
		return AbstractGenericTest.runSwing(s);
	}
}
