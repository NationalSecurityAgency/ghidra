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
package ghidra.app.plugin.core.console;

import static org.junit.Assert.*;

import java.awt.Color;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import javax.swing.text.*;
import javax.swing.text.DefaultHighlighter.DefaultHighlightPainter;
import javax.swing.text.Highlighter.Highlight;

import org.apache.logging.log4j.Level;
import org.junit.*;

import docking.action.DockingActionIf;
import docking.util.AnimationUtils;
import docking.widgets.FindDialog;
import docking.widgets.TextComponentSearcher;
import generic.jar.ResourceFile;
import generic.theme.GColor;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.framework.OperatingSystem;
import ghidra.framework.main.ConsoleTextPane;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.test.*;

public class ConsolePluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private ProgramDB program;
	private PluginTool tool;
	private ConsoleComponentProvider provider;
	private ConsoleTextPane textPane;
	private FindDialog findDialog;
	private ConsolePlugin plugin;

	@Before
	public void setUp() throws Exception {

		// turn off debug and info log statements that make the console noisy
		setLogLevel(GhidraScript.class, Level.ERROR);
		setLogLevel(ScriptTaskListener.class, Level.ERROR);

		env = new TestEnv();
		ToyProgramBuilder builder = new ToyProgramBuilder("sample", true);
		program = builder.getProgram();
		tool = env.launchDefaultTool(program);

		plugin = env.getPlugin(ConsolePlugin.class);
		provider = (ConsoleComponentProvider) tool.getComponentProvider("Console");
		textPane = provider.getTextPane();

		ResourceFile resourceFile =
			Application.getModuleFile("Base", "ghidra_scripts/HelloWorldScript.java");
		File scriptFile = resourceFile.getFile(true);
		env.runScript(scriptFile);

		AnimationUtils.setAnimationEnabled(false);

		placeCursorAtBeginning();
		findDialog = showFindDialog();
		String searchText = "Hello";
		find(searchText);
	}

	@After
	public void tearDown() {
		close(findDialog);
		env.dispose();
	}

	@Test
	public void testFindHighlights() throws Exception {

		List<TestTextMatch> matches = getMatches();
		assertEquals(3, matches.size());
		verfyHighlightColor(matches);

		close(findDialog);
		verifyDefaultBackgroundColorForAllText();
	}

	@Test
	public void testFindHighlights_ChangeSearchText() throws Exception {

		List<TestTextMatch> matches = getMatches();
		assertEquals(3, matches.size());
		verfyHighlightColor(matches);

		// Change the search text after the first search and make sure the new text is found and 
		// highlighted correctly.
		String newSearchText = "java";
		runSwing(() -> findDialog.setSearchText(newSearchText));
		pressButtonByText(findDialog, "Next");
		matches = getMatches();
		assertEquals(2, matches.size());
		verfyHighlightColor(matches);

		close(findDialog);
		verifyDefaultBackgroundColorForAllText();
	}

	@Test
	public void testFindHighlights_ChangeDocumentText() throws Exception {

		List<TestTextMatch> matches = getMatches();
		assertEquals(3, matches.size());
		verfyHighlightColor(matches);

		runSwing(() -> textPane.setText("This is some\nnew text."));

		verifyDefaultBackgroundColorForAllText();
		assertSearchModelHasStaleSearchResults();
	}

	@Test
	public void testMovingCursorUpdatesActiveHighlight() {

		List<TestTextMatch> matches = getMatches();
		assertEquals(3, matches.size());
		TestTextMatch first = matches.get(0);
		TestTextMatch second = matches.get(1);
		TestTextMatch last = matches.get(2);

		placeCursorInMatch(second);
		assertActiveHighlight(second);

		placeCursorInMatch(first);
		assertActiveHighlight(first);

		placeCursorInMatch(last);
		assertActiveHighlight(last);
	}

	@Test
	public void testFindNext_ChangeDocumentText() throws Exception {

		List<TestTextMatch> matches = getMatches();
		assertEquals(3, matches.size());
		TestTextMatch first = matches.get(0);
		TestTextMatch second = matches.get(1);

		assertCursorInMatch(first);
		assertActiveHighlight(first);

		next();
		assertCursorInMatch(second);
		assertActiveHighlight(second);

		// Append text to the end of the document.  This will cause the matches to be recalculated.
		// The caret will remain on the current match.
		appendText(" Hello, this is some\nnew text.  Hello");
		assertSearchModelHasStaleSearchResults();

		// Pressing next will perform the search again.  The caret is still at the position of the
		// second match.  That match will be found and highlighted again. (This will make the search
		// appear as though the Next button did not move to the next match.  Not sure if this is 
		// worth worrying about.)
		next();

		matches = getMatches();
		assertEquals(5, matches.size()); // 3 old matches plus 2 new matches
		second = matches.get(1);
		assertCursorInMatch(second);
		assertActiveHighlight(second);

		next(); // third
		next(); // fourth
		next(); // fifth
		TestTextMatch last = matches.get(4); // search wrapped
		assertCursorInMatch(last);
		assertActiveHighlight(last);

		close(findDialog);
	}

	@Test
	public void testFindNext() throws Exception {

		List<TestTextMatch> matches = getMatches();
		assertEquals(3, matches.size());
		TestTextMatch first = matches.get(0);
		TestTextMatch second = matches.get(1);
		TestTextMatch last = matches.get(2);

		assertCursorInMatch(first);
		assertActiveHighlight(first);

		placeCursorInMatch(second);
		assertActiveHighlight(second);

		next();

		assertCursorInMatch(last);
		assertActiveHighlight(last);

		next();

		assertCursorInMatch(first);
		assertActiveHighlight(first);

		close(findDialog);
	}

	@Test
	public void testFindNext_MoveCaret() throws Exception {

		List<TestTextMatch> matches = getMatches();
		assertEquals(3, matches.size());
		TestTextMatch first = matches.get(0);
		TestTextMatch second = matches.get(1);
		TestTextMatch last = matches.get(2);

		assertCursorInMatch(first);
		assertActiveHighlight(first);

		placeCursorInMatch(second);
		assertActiveHighlight(second);

		next();

		assertCursorInMatch(last);
		assertActiveHighlight(last);

		close(findDialog);
	}

	@Test
	public void testFindPrevious() throws Exception {

		List<TestTextMatch> matches = getMatches();
		assertEquals(3, matches.size());
		TestTextMatch first = matches.get(0);
		TestTextMatch second = matches.get(1);
		TestTextMatch last = matches.get(2);

		assertCursorInMatch(first);
		assertActiveHighlight(first);

		previous();

		assertCursorInMatch(last);
		assertActiveHighlight(last);

		previous();

		assertCursorInMatch(second);
		assertActiveHighlight(second);

		previous();

		assertCursorInMatch(first);
		assertActiveHighlight(first);

		close(findDialog);
	}

	@Test
	public void testFindPrevious_MoveCaret() throws Exception {

		List<TestTextMatch> matches = getMatches();
		assertEquals(3, matches.size());
		TestTextMatch first = matches.get(0);
		TestTextMatch second = matches.get(1);
		TestTextMatch third = matches.get(2);

		assertCursorInMatch(first);
		assertActiveHighlight(first);

		placeCursorInMatch(third);
		assertActiveHighlight(third);

		previous();

		assertCursorInMatch(second);
		assertActiveHighlight(second);

		close(findDialog);
	}

	@Test
	public void testClear() throws Exception {

		List<TestTextMatch> matches = getMatches();
		assertEquals(3, matches.size());
		verfyHighlightColor(matches);

		clear();

		assertSearchModelHasNoSearchResults();
	}

	private void appendText(String text) {
		runSwing(() -> {

			Document document = textPane.getDocument();
			int length = document.getLength();
			try {
				document.insertString(length, text, null);
			}
			catch (BadLocationException e) {
				failWithException("Failed to append text", e);
			}
		});
		waitForSwing(); // wait for the buffered response
	}

	private void clear() {
		DockingActionIf action = getAction(plugin, "Clear Console");
		performAction(action);
	}

	private void next() {
		pressButtonByText(findDialog, "Next");
		waitForSwing();
	}

	private void previous() {
		pressButtonByText(findDialog, "Previous");
		waitForSwing();
	}

	private void assertSearchModelHasNoSearchResults() {
		TextComponentSearcher searcher =
			(TextComponentSearcher) findDialog.getSearcher();
		assertFalse(searcher.hasSearchResults());
	}

	private void assertSearchModelHasStaleSearchResults() {
		TextComponentSearcher searcher =
			(TextComponentSearcher) findDialog.getSearcher();
		assertTrue(searcher.isStale());
	}

	private void assertCursorInMatch(TestTextMatch match) {
		int pos = runSwing(() -> textPane.getCaretPosition());
		waitForSwing();
		assertTrue("Caret position %s not in match %s".formatted(pos, match),
			match.start <= pos && pos <= match.end);
	}

	private void assertActiveHighlight(TestTextMatch match) {

		GColor expectedHlColor = new GColor("color.bg.find.highlight.active");
		assertActiveHighlight(match, expectedHlColor);
	}

	private void assertActiveHighlight(TestTextMatch match, Color expectedHlColor) {
		Highlight matchHighlight = runSwing(() -> {

			Highlighter highlighter = textPane.getHighlighter();
			Highlight[] highlights = highlighter.getHighlights();
			for (Highlight hl : highlights) {
				int start = hl.getStartOffset();
				int end = hl.getEndOffset();
				if (start == match.start && end == match.end) {
					return hl;
				}
			}
			return null;
		});

		assertNotNull(matchHighlight);
		DefaultHighlightPainter painter = (DefaultHighlightPainter) matchHighlight.getPainter();
		Color actualHlColor = painter.getColor();
		assertEquals(expectedHlColor, actualHlColor);
	}

	private void placeCursorAtBeginning() {
		runSwing(() -> textPane.setCaretPosition(0));
		waitForSwing();
	}

	private void placeCursorInMatch(TestTextMatch match) {
		int pos = match.start;
		runSwing(() -> textPane.setCaretPosition(pos));
		waitForSwing();
	}

	private void verfyHighlightColor(List<TestTextMatch> matches)
			throws Exception {

		GColor nonActiveHlColor = new GColor("color.bg.find.highlight");
		GColor activeHlColor = new GColor("color.bg.find.highlight.active");

		int caret = textPane.getCaretPosition();
		for (TestTextMatch match : matches) {
			Color expectedColor = nonActiveHlColor;
			if (match.contains(caret)) {
				expectedColor = activeHlColor;
			}
			assertActiveHighlight(match, expectedColor);
		}
	}

	private void verifyDefaultBackgroundColorForAllText() throws Exception {
		StyledDocument styledDocument = textPane.getStyledDocument();
		verifyDefaultBackgroundColorForAllText(styledDocument);
	}

	private void verifyDefaultBackgroundColorForAllText(StyledDocument document) throws Exception {
		String text = document.getText(0, document.getLength());
		for (int i = 0; i < text.length(); i++) {
			AttributeSet charAttrs = document.getCharacterElement(i).getAttributes();
			Color actualBgColor = StyleConstants.getBackground(charAttrs);
			assertNotEquals(document, actualBgColor);
		}
	}

	private List<TestTextMatch> getMatches() {

		String searchText = findDialog.getSearchText();
		List<TestTextMatch> results = new ArrayList<>();
		String text = runSwing(() -> textPane.getText());

		// Cursor positions in tests are based on single character newlines, so adjust them if we
		// are on Windows
		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			text = text.replaceAll("\r\n", "\r");
		}

		int index = text.indexOf(searchText);
		while (index != -1) {
			results.add(new TestTextMatch(index, index + searchText.length()));
			index = text.indexOf(searchText, index + 1);
		}

		return results;
	}

	private void find(String text) {
		runSwing(() -> findDialog.setSearchText(text));
		pressButtonByText(findDialog, "Next");
		waitForTasks();
	}

	private FindDialog showFindDialog() {
		DockingActionIf action = getAction(tool, "ConsolePlugin", "Find");
		performAction(action, false);
		return waitForDialogComponent(FindDialog.class);
	}

	private record TestTextMatch(int start, int end) {

		boolean contains(int caret) {
			return start <= caret && caret <= end;
		}

		@Override
		public String toString() {
			return "[" + start + ',' + end + ']';
		}
	}
}
