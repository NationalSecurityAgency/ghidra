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

import org.junit.Test;

import docking.widgets.OkDialog;
import docking.widgets.fieldpanel.support.*;
import ghidra.app.plugin.core.clipboard.ClipboardPlugin;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.services.*;
import ghidra.framework.OperatingSystem;
import ghidra.pty.*;
import ghidra.util.SystemUtilities;

public class TerminalProviderTest extends AbstractGhidraHeadedDebuggerGUITest {
	protected static byte[] ascii(String str) {
		try {
			return str.getBytes("US-ASCII");
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
			try (Terminal term = terminalService.createWithStreams(Charset.forName("US-ASCII"),
				parent.getInputStream(), parent.getOutputStream())) {
				term.addTerminalListener(new TerminalListener() {
					@Override
					public void resized(int cols, int rows) {
						parent.setWindowSize(cols, rows);
					}
				});
				session.waitExited();
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
				pty.getChild().session(new String[] { "C:\\Windows\\cmd.exe" }, env);

			PtyParent parent = pty.getParent();
			try (Terminal term = terminalService.createWithStreams(Charset.forName("US-ASCII"),
				parent.getInputStream(), parent.getOutputStream())) {
				term.addTerminalListener(new TerminalListener() {
					@Override
					public void resized(int cols, int rows) {
						parent.setWindowSize(cols, rows);
					}
				});
				session.waitExited();
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
	public void testFindSimple() throws Exception {
		terminalService = addPlugin(tool, TerminalPlugin.class);

		try (DefaultTerminal term = (DefaultTerminal) terminalService
				.createNullTerminal(Charset.forName("US-ASCII"), buf -> {
				})) {
			term.setFixedSize(25, 80);
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
	public void testFindCaseSensitive() throws Exception {
		terminalService = addPlugin(tool, TerminalPlugin.class);

		try (DefaultTerminal term = (DefaultTerminal) terminalService
				.createNullTerminal(Charset.forName("US-ASCII"), buf -> {
				})) {
			term.setFixedSize(25, 80);
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
				.createNullTerminal(Charset.forName("US-ASCII"), buf -> {
				})) {
			term.setFixedSize(25, 80);
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
				.createNullTerminal(Charset.forName("US-ASCII"), buf -> {
				})) {
			term.setFixedSize(25, 80);
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
				.createNullTerminal(Charset.forName("US-ASCII"), buf -> {
				})) {
			term.setFixedSize(25, 80);
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
	public void testFindPrevious() throws Exception {
		terminalService = addPlugin(tool, TerminalPlugin.class);

		try (DefaultTerminal term = (DefaultTerminal) terminalService
				.createNullTerminal(Charset.forName("US-ASCII"), buf -> {
				})) {
			term.setFixedSize(25, 80);
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
				.createNullTerminal(Charset.forName("US-ASCII"), buf -> {
				})) {
			term.setFixedSize(25, 80);
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
				.createNullTerminal(Charset.forName("US-ASCII"), buf -> {
				})) {
			term.setFixedSize(25, 80);
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
}
