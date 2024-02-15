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
package ghidra.app.plugin.core.terminal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.*;

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;

import docking.widgets.OkDialog;
import docking.widgets.fieldpanel.support.*;
import ghidra.app.plugin.core.clipboard.ClipboardPlugin;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.app.services.*;
import ghidra.framework.OperatingSystem;
import ghidra.pty.*;
import ghidra.util.SystemUtilities;

public class TerminalProviderTest extends AbstractGhidraHeadedDebuggerTest {
	protected static byte[] ascii(String str) {
		try {
			return str.getBytes("UTF-8");
		}
		catch (UnsupportedEncodingException e) {
			throw new AssertionError(e);
		}
	}

	protected static final byte[] TEST_CONTENTS = ascii("""
			term Term\r
			noterm\r
			""");
	TerminalService terminalService;
	ClipboardService clipboardService;

	@Test
	@SuppressWarnings("resource")
	public void testBash() throws Exception {
		assumeFalse(SystemUtilities.isInTestingBatchMode());
		assumeFalse(OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS);

		terminalService = addPlugin(tool, TerminalPlugin.class);
		clipboardService = addPlugin(tool, ClipboardPlugin.class);

		PtyFactory factory = PtyFactory.local();
		try (Pty pty = factory.openpty()) {
			Map<String, String> env = new HashMap<>(System.getenv());
			env.put("TERM", "xterm-256color");
			PtySession session = pty.getChild().session(new String[] { "/usr/bin/bash" }, env);

			PtyParent parent = pty.getParent();
			try (Terminal term = terminalService.createWithStreams(Charset.forName("UTF-8"),
				parent.getInputStream(), parent.getOutputStream())) {
				term.addTerminalListener(new TerminalListener() {
					@Override
					public void resized(short cols, short rows) {
						System.err.println("resized: " + cols + "x" + rows);
						parent.setWindowSize(cols, rows);
					}
				});
				session.waitExited();
				pty.close();
			}
		}
	}

	@Test
	@SuppressWarnings("resource")
	public void testCmd() throws Exception {
		assumeFalse(SystemUtilities.isInTestingBatchMode());
		assumeTrue(OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS);

		terminalService = addPlugin(tool, TerminalPlugin.class);
		clipboardService = addPlugin(tool, ClipboardPlugin.class);

		PtyFactory factory = PtyFactory.local();
		try (Pty pty = factory.openpty()) {
			Map<String, String> env = new HashMap<>(System.getenv());
			PtySession session =
				pty.getChild().session(new String[] { "C:\\Windows\\system32\\cmd.exe" }, env);

			PtyParent parent = pty.getParent();
			try (Terminal term = terminalService.createWithStreams(Charset.forName("UTF-8"),
				parent.getInputStream(), parent.getOutputStream())) {
				term.addTerminalListener(new TerminalListener() {
					@Override
					public void resized(short cols, short rows) {
						System.err.println("resized: " + cols + "x" + rows);
						parent.setWindowSize(cols, rows);
					}
				});
				session.waitExited();
				pty.close();
			}
		}
	}

	@Test
	@SuppressWarnings("resource")
	public void testCmd80x25() throws Exception {
		assumeFalse(SystemUtilities.isInTestingBatchMode());
		assumeTrue(OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS);

		terminalService = addPlugin(tool, TerminalPlugin.class);
		clipboardService = addPlugin(tool, ClipboardPlugin.class);

		PtyFactory factory = PtyFactory.local();
		try (Pty pty = factory.openpty(80, 25)) {
			Map<String, String> env = new HashMap<>(System.getenv());
			PtySession session =
				pty.getChild().session(new String[] { "C:\\Windows\\system32\\cmd.exe" }, env);

			PtyParent parent = pty.getParent();
			try (Terminal term = terminalService.createWithStreams(Charset.forName("UTF-8"),
				parent.getInputStream(), parent.getOutputStream())) {
				term.setFixedSize(80, 25);
				session.waitExited();
				pty.close();
			}
		}
	}

	protected void assertSingleSelection(int row, int colStart, int colEnd, FieldSelection sel) {
		assertEquals(1, sel.getNumRanges());
		FieldRange range = sel.getFieldRange(0);
		assertEquals(new FieldLocation(row, 0, 0, colStart), range.getStart());
		assertEquals(new FieldLocation(row, 0, 0, colEnd), range.getEnd());
	}

	@Test
	@SuppressWarnings("resource")
	public void testFindText() throws Exception {
		terminalService = addPlugin(tool, TerminalPlugin.class);

		try (DefaultTerminal term = (DefaultTerminal) terminalService
				.createNullTerminal(Charset.forName("UTF-8"), buf -> {
				})) {
			term.setFixedSize(80, 25);
			term.injectDisplayOutput(TEST_CONTENTS);

			term.provider.findDialog.txtFind.setText("term");

			performAction(term.provider.actionFindNext, false);
			waitForPass(() -> assertSingleSelection(0, 0, 4,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindNext, false);
			waitForPass(() -> assertSingleSelection(0, 5, 9,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindNext, false);
			waitForPass(() -> assertSingleSelection(1, 2, 6,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindNext, false);
			OkDialog dialog = waitForInfoDialog();
			assertEquals("String not found", dialog.getMessage());
			dialog.close();
		}
	}

	@Test
	@SuppressWarnings("resource")
	public void testFindTextCaps() throws Exception {
		terminalService = addPlugin(tool, TerminalPlugin.class);

		try (DefaultTerminal term = (DefaultTerminal) terminalService
				.createNullTerminal(Charset.forName("UTF-8"), buf -> {
				})) {
			term.setFixedSize(80, 25);
			term.injectDisplayOutput(TEST_CONTENTS);

			term.provider.findDialog.txtFind.setText("TERM");

			performAction(term.provider.actionFindNext, false);
			waitForPass(() -> assertSingleSelection(0, 0, 4,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindNext, false);
			waitForPass(() -> assertSingleSelection(0, 5, 9,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindNext, false);
			waitForPass(() -> assertSingleSelection(1, 2, 6,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindNext, false);
			OkDialog dialog = waitForInfoDialog();
			assertEquals("String not found", dialog.getMessage());
			dialog.close();
		}
	}

	@Test
	@SuppressWarnings("resource")
	public void testFindCaseSensitive() throws Exception {
		terminalService = addPlugin(tool, TerminalPlugin.class);

		try (DefaultTerminal term = (DefaultTerminal) terminalService
				.createNullTerminal(Charset.forName("UTF-8"), buf -> {
				})) {
			term.setFixedSize(80, 25);
			term.injectDisplayOutput(TEST_CONTENTS);

			term.provider.findDialog.txtFind.setText("term");
			term.provider.findDialog.cbCaseSensitive.setSelected(true);

			performAction(term.provider.actionFindNext, false);
			waitForPass(() -> assertSingleSelection(0, 0, 4,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindNext, false);
			waitForPass(() -> assertSingleSelection(1, 2, 6,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindNext, false);
			OkDialog dialog = waitForInfoDialog();
			assertEquals("String not found", dialog.getMessage());
			dialog.close();
		}
	}

	@Test
	@SuppressWarnings("resource")
	public void testFindWrap() throws Exception {
		terminalService = addPlugin(tool, TerminalPlugin.class);

		try (DefaultTerminal term = (DefaultTerminal) terminalService
				.createNullTerminal(Charset.forName("UTF-8"), buf -> {
				})) {
			term.setFixedSize(80, 25);
			term.injectDisplayOutput(TEST_CONTENTS);

			term.provider.findDialog.txtFind.setText("term");
			term.provider.findDialog.cbWrapSearch.setSelected(true);

			performAction(term.provider.actionFindNext, false);
			waitForPass(() -> assertSingleSelection(0, 0, 4,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindNext, false);
			waitForPass(() -> assertSingleSelection(0, 5, 9,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindNext, false);
			waitForPass(() -> assertSingleSelection(1, 2, 6,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindNext, false);
			waitForPass(() -> assertSingleSelection(0, 0, 4,
				term.provider.panel.fieldPanel.getSelection()));
		}
	}

	@Test
	@SuppressWarnings("resource")
	public void testFindWholeWord() throws Exception {
		terminalService = addPlugin(tool, TerminalPlugin.class);

		try (DefaultTerminal term = (DefaultTerminal) terminalService
				.createNullTerminal(Charset.forName("UTF-8"), buf -> {
				})) {
			term.setFixedSize(80, 25);
			term.injectDisplayOutput(TEST_CONTENTS);

			term.provider.findDialog.txtFind.setText("term");
			term.provider.findDialog.cbWholeWord.setSelected(true);

			performAction(term.provider.actionFindNext, false);
			waitForPass(() -> assertSingleSelection(0, 0, 4,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindNext, false);
			waitForPass(() -> assertSingleSelection(0, 5, 9,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindNext, false);
			OkDialog dialog = waitForInfoDialog();
			assertEquals("String not found", dialog.getMessage());
			dialog.close();
		}
	}

	@Test
	@SuppressWarnings("resource")
	public void testFindRegex() throws Exception {
		terminalService = addPlugin(tool, TerminalPlugin.class);

		try (DefaultTerminal term = (DefaultTerminal) terminalService
				.createNullTerminal(Charset.forName("UTF-8"), buf -> {
				})) {
			term.setFixedSize(80, 25);
			term.injectDisplayOutput(TEST_CONTENTS);

			term.provider.findDialog.txtFind.setText("o?term");
			term.provider.findDialog.cbRegex.setSelected(true);

			performAction(term.provider.actionFindNext, false);
			waitForPass(() -> assertSingleSelection(0, 0, 4,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindNext, false);
			waitForPass(() -> assertSingleSelection(0, 5, 9,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindNext, false);
			waitForPass(() -> assertSingleSelection(1, 1, 6,
				term.provider.panel.fieldPanel.getSelection()));

			// NB. the o is optional, so it finds a subrange of the previous result
			performAction(term.provider.actionFindNext, false);
			waitForPass(() -> assertSingleSelection(1, 2, 6,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindNext, false);
			OkDialog dialog = waitForInfoDialog();
			assertEquals("String not found", dialog.getMessage());
			dialog.close();
		}
	}

	@Test
	@SuppressWarnings("resource")
	public void testFindRegexCaps() throws Exception {
		terminalService = addPlugin(tool, TerminalPlugin.class);

		try (DefaultTerminal term = (DefaultTerminal) terminalService
				.createNullTerminal(Charset.forName("UTF-8"), buf -> {
				})) {
			term.setFixedSize(80, 25);
			term.injectDisplayOutput(TEST_CONTENTS);

			term.provider.findDialog.txtFind.setText("o?TERM");
			term.provider.findDialog.cbRegex.setSelected(true);

			performAction(term.provider.actionFindNext, false);
			waitForPass(() -> assertSingleSelection(0, 0, 4,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindNext, false);
			waitForPass(() -> assertSingleSelection(0, 5, 9,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindNext, false);
			waitForPass(() -> assertSingleSelection(1, 1, 6,
				term.provider.panel.fieldPanel.getSelection()));

			// NB. the o is optional, so it finds a subrange of the previous result
			performAction(term.provider.actionFindNext, false);
			waitForPass(() -> assertSingleSelection(1, 2, 6,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindNext, false);
			OkDialog dialog = waitForInfoDialog();
			assertEquals("String not found", dialog.getMessage());
			dialog.close();
		}
	}

	@Test
	@SuppressWarnings("resource")
	public void testFindPrevious() throws Exception {
		terminalService = addPlugin(tool, TerminalPlugin.class);

		try (DefaultTerminal term = (DefaultTerminal) terminalService
				.createNullTerminal(Charset.forName("UTF-8"), buf -> {
				})) {
			term.setFixedSize(80, 25);
			term.injectDisplayOutput(TEST_CONTENTS);

			term.provider.findDialog.txtFind.setText("term");

			performAction(term.provider.actionFindPrevious, false);
			waitForPass(() -> assertSingleSelection(1, 2, 6,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindPrevious, false);
			waitForPass(() -> assertSingleSelection(0, 5, 9,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindPrevious, false);
			waitForPass(() -> assertSingleSelection(0, 0, 4,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindPrevious, false);
			OkDialog dialog = waitForInfoDialog();
			assertEquals("String not found", dialog.getMessage());
			dialog.close();
		}
	}

	@Test
	@SuppressWarnings("resource")
	public void testFindPreviousWrap() throws Exception {
		terminalService = addPlugin(tool, TerminalPlugin.class);

		try (DefaultTerminal term = (DefaultTerminal) terminalService
				.createNullTerminal(Charset.forName("UTF-8"), buf -> {
				})) {
			term.setFixedSize(80, 25);
			term.injectDisplayOutput(TEST_CONTENTS);

			term.provider.findDialog.txtFind.setText("term");
			term.provider.findDialog.cbWrapSearch.setSelected(true);

			performAction(term.provider.actionFindPrevious, false);
			waitForPass(() -> assertSingleSelection(1, 2, 6,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindPrevious, false);
			waitForPass(() -> assertSingleSelection(0, 5, 9,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindPrevious, false);
			waitForPass(() -> assertSingleSelection(0, 0, 4,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindPrevious, false);
			waitForPass(() -> assertSingleSelection(1, 2, 6,
				term.provider.panel.fieldPanel.getSelection()));
		}
	}

	@Test
	@SuppressWarnings("resource")
	public void testFindPreviousRegex() throws Exception {
		terminalService = addPlugin(tool, TerminalPlugin.class);

		try (DefaultTerminal term = (DefaultTerminal) terminalService
				.createNullTerminal(Charset.forName("UTF-8"), buf -> {
				})) {
			term.setFixedSize(80, 25);
			term.injectDisplayOutput(TEST_CONTENTS);

			term.provider.findDialog.txtFind.setText("o?term");
			term.provider.findDialog.cbRegex.setSelected(true);

			// NB. the o is optional, so it finds a subrange of the next result
			performAction(term.provider.actionFindPrevious, false);
			waitForPass(() -> assertSingleSelection(1, 2, 6,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindPrevious, false);
			waitForPass(() -> assertSingleSelection(1, 1, 6,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindPrevious, false);
			waitForPass(() -> assertSingleSelection(0, 5, 9,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindPrevious, false);
			waitForPass(() -> assertSingleSelection(0, 0, 4,
				term.provider.panel.fieldPanel.getSelection()));

			performAction(term.provider.actionFindPrevious, false);
			OkDialog dialog = waitForInfoDialog();
			assertEquals("String not found", dialog.getMessage());
			dialog.close();
		}
	}

	protected String csi(char f, int... params) {
		return "\033[" +
			IntStream.of(params).mapToObj(Integer::toString).collect(Collectors.joining(";")) + f;
	}

	protected String title(String title) {
		return "\033]0;" + title + "\007";
	}

	protected final static String HIDE_CURSOR = "\033[?25l";
	protected final static String SHOW_CURSOR = "\033[?25h";

	protected void send(Terminal term, String... parts) throws Exception {
		String joined = Stream.of(parts).collect(Collectors.joining());
		term.injectDisplayOutput(joined.getBytes("UTF-8"));
	}

	@Test
	@SuppressWarnings("resource")
	public void testSimulateLinuxPtyResetAndEol() throws Exception {
		terminalService = addPlugin(tool, TerminalPlugin.class);

		try (DefaultTerminal term = (DefaultTerminal) terminalService
				.createNullTerminal(Charset.forName("UTF-8"), buf -> {
				})) {
			term.setFixedSize(40, 25);

			send(term,
				csi('J', 3), csi('H'), csi('J', 2),
				title(name.getMethodName()),
				/**
				 * Linux/bash goes one character past, sends CR, repeats the character, and
				 * continues. No LF. The line feed occurs by virtue of the local line wrap.
				 */
				"12345678901234567890123456789012345678901",
				"\r",
				"1234567890");

			assertEquals("1234567890123456789012345678901234567890", term.getLineText(0));
			assertEquals("1234567890", term.getLineText(1));
			assertEquals(10, term.getCursorColumn());
			assertEquals(1, term.getCursorRow());
		}
	}

	@Test
	@SuppressWarnings("resource")
	public void testSimulateLinuxPtyTypePastEol() throws Exception {
		terminalService = addPlugin(tool, TerminalPlugin.class);

		try (DefaultTerminal term = (DefaultTerminal) terminalService
				.createNullTerminal(Charset.forName("UTF-8"), buf -> {
				})) {
			term.setFixedSize(40, 25);

			send(term,
				title(name.getMethodName()),
				/**
				 * Echoing characters back works similarly to sending characters. When the last
				 * column is filled (the application knows the terminal width) Linux/bash sends an
				 * extra space to induce a line wrap, then sends CR.
				 */
				"123456789012345678901234567890123456789", // One before the last column
				"0 \r");

			assertEquals("1234567890123456789012345678901234567890", term.getLineText(0));
			assertEquals(" ", term.getLineText(1));
			assertEquals(0, term.getCursorColumn());
			assertEquals(1, term.getCursorRow());
		}
	}

	@Test
	@SuppressWarnings("resource")
	public void testSimulateLinuxPtyEchoPastEol() throws Exception {
		terminalService = addPlugin(tool, TerminalPlugin.class);

		try (DefaultTerminal term = (DefaultTerminal) terminalService
				.createNullTerminal(Charset.forName("UTF-8"), buf -> {
				})) {
			term.setFixedSize(40, 25);

			send(term,
				title(name.getMethodName()),
				/**
				 * The echo command itself pays no heed to the terminal width. Wrapping is purely
				 * terminal side.
				 */
				"1234567890123456789012345678901234567890asdfasdf\r\n");

			assertEquals("1234567890123456789012345678901234567890", term.getLineText(0));
			assertEquals("asdfasdf", term.getLineText(1));
			assertEquals("", term.getLineText(2));
			assertEquals(0, term.getCursorColumn());
			assertEquals(2, term.getCursorRow());
		}
	}

	@Test
	@SuppressWarnings("resource")
	public void testSimulateLinuxPtyTypePastEolLastLine() throws Exception {
		terminalService = addPlugin(tool, TerminalPlugin.class);

		try (DefaultTerminal term = (DefaultTerminal) terminalService
				.createNullTerminal(Charset.forName("UTF-8"), buf -> {
				})) {
			term.setFixedSize(40, 25);

			send(term,
				title(name.getMethodName()),
				"top line\r\n",
				StringUtils.repeat("\r\n", 23),
				"123456789012345678901234567890123456789", // One before the last column
				"0 \r");

			assertEquals(1, term.getScrollBackRows());
			assertEquals("top line", term.getLineText(-1));
			assertEquals("1234567890123456789012345678901234567890", term.getLineText(23));
			assertEquals(" ", term.getLineText(24));
			assertEquals(0, term.getCursorColumn());
			assertEquals(24, term.getCursorRow());
		}
	}

	@Test
	@SuppressWarnings("resource")
	public void testSimulateWindowsPtyStartCmd() throws Exception {
		terminalService = addPlugin(tool, TerminalPlugin.class);

		try (DefaultTerminal term = (DefaultTerminal) terminalService
				.createNullTerminal(Charset.forName("UTF-8"), buf -> {
				})) {
			term.setFixedSize(80, 25);

			send(term,
				csi('J', 2), HIDE_CURSOR, csi('m'), csi('H'),
				StringUtils.repeat("\r\n", 32), // for a 25-line terminal? No matter.
				csi('H'),
				title("C:\\Windows\\system32\\cmd.exe\0"),
				SHOW_CURSOR, HIDE_CURSOR,
				// Line 1: Length is 43
				"Microsoft Windows [Version XXXXXXXXXXXXXXX]",
				csi('X', 37), csi('C', 37), "\r\n", // 37 + 43 = 80
				// Line 2: Length is 52
				"(c) 20XX Microsoft Corporation. All rights reserved.",
				csi('X', 28), csi('C', 28), "\r\n", // 28 + 52 = 80
				// Line 3: Blank
				csi('X', 80), csi('C', 80), "\r\n", // 80 + 0 = 80
				// Line 4: No X or C sequences. Probably because shorter to put literal "  "
				"C:\\XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX> ");
			send(term, " ");
			send(term, "\r\n");
			send(term,
				csi('X', 80), csi('C', 80), "\r\n",
				csi('X', 80), csi('C', 80), "\r\n",
				csi('X', 80), csi('C', 80), "\r\n",
				csi('X', 80), csi('C', 80), "\r\n",
				csi('X', 80), csi('C', 80), "\r\n",
				csi('X', 80), csi('C', 80), "\r\n",
				csi('X', 80), csi('C', 80), "\r\n",
				csi('X', 80), csi('C', 80), "\r\n",
				csi('X', 80), csi('C', 80), "\r\n",
				csi('X', 80), csi('C', 80), "\r\n",
				csi('X', 80), csi('C', 80), "\r\n",
				csi('X', 80), csi('C', 80), "\r\n",
				csi('X', 80), csi('C', 80), "\r\n",
				csi('X', 80), csi('C', 80), "\r\n",
				csi('X', 80), csi('C', 80), "\r\n",
				csi('X', 80), csi('C', 80), "\r\n",
				csi('X', 80), csi('C', 80), "\r\n",
				csi('X', 80), csi('C', 80), "\r\n",
				csi('X', 80), csi('C', 80), "\r\n",
				csi('X', 80), csi('C', 80), "\r\n",

				csi('X', 80), csi('C', 80),
				csi('H', 4, 79),
				SHOW_CURSOR);

			assertEquals(
				"C:\\XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX>  ",
				term.getLineText(3));
			assertEquals(78, term.getCursorColumn());
			assertEquals(3, term.getCursorRow());
		}
	}
}
