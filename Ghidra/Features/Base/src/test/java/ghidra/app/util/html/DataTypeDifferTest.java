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
package ghidra.app.util.html;

import static org.junit.Assert.*;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import org.junit.Assert;
import org.junit.Test;

import docking.widgets.label.GHtmlLabel;
import ghidra.app.util.html.diff.*;

public class DataTypeDifferTest {

	@Test
	public void testDiffBody_EmptyInputs() {

		List<ValidatableLine> leftLines = new ArrayList<>();
		List<ValidatableLine> rightLines = new ArrayList<>();

		DataTypeDiffInput left = new DiffInputTestStub(leftLines);
		DataTypeDiffInput right = new DiffInputTestStub(rightLines);

		DataTypeDiff diff = DataTypeDiffBuilder.diffBody(left, right);
		assertNotNull(diff);
	}

	@Test
	public void testDiffBody_SingleInput_Same() {

		List<ValidatableLine> leftLines = new ArrayList<>();
		addLine(leftLines, "Line One");

		List<ValidatableLine> rightLines = new ArrayList<>();
		addLine(rightLines, "Line One");

		DataTypeDiffInput leftInput = new DiffInputTestStub(leftLines);
		DataTypeDiffInput rightInput = new DiffInputTestStub(rightLines);

		DataTypeDiff diff = DataTypeDiffBuilder.diffBody(leftInput, rightInput);
		assertNotNull(diff);

		DiffLines left = diff.getLeftLines();
		DiffLines right = diff.getRightLines();

		assertEquals(left.size(), right.size());
		assertNotDiffColored(left);
		assertNotDiffColored(right);
	}

	@Test
	public void testDiffBody_SingleInput_Different() {

		List<ValidatableLine> leftLines = new ArrayList<>();
		addLine(leftLines, "Left One");

		List<ValidatableLine> rightLines = new ArrayList<>();
		addLine(rightLines, "Right One");

		DataTypeDiffInput leftInput = new DiffInputTestStub(leftLines);
		DataTypeDiffInput rightInput = new DiffInputTestStub(rightLines);

		DataTypeDiff diff = DataTypeDiffBuilder.diffBody(leftInput, rightInput);
		assertNotNull(diff);

		DiffLines left = diff.getLeftLines();
		DiffLines right = diff.getRightLines();

		assertEquals(left.size(), right.size());
		assertDiffColored(left);
		assertDiffColored(right);
	}

	@Test
	public void testDiffBody_DifferentSize_SameStart() {

		List<ValidatableLine> leftLines = new ArrayList<>();
		addLine(leftLines, "Line One");

		List<ValidatableLine> rightLines = new ArrayList<>();
		TestLine r1 = addLine(rightLines, "Line One");
		TestLine r2 = addLine(rightLines, "Line Two");

		DataTypeDiffInput leftInput = new DiffInputTestStub(leftLines);
		DataTypeDiffInput rightInput = new DiffInputTestStub(rightLines);

		DataTypeDiff diff = DataTypeDiffBuilder.diffBody(leftInput, rightInput);
		assertNotNull(diff);

		DiffLines left = diff.getLeftLines();
		DiffLines right = diff.getRightLines();

		assertEquals(left.size(), right.size());

		assertFalse(r1.isDiffColored());
		assertTrue(r2.isDiffColored());

		assertPlaceholder(left.get(1));
	}

	@Test
	public void testDiffBody_TrippleInput_AllDifferentButLast() {

		List<ValidatableLine> leftLines = new ArrayList<>();
		TestLine l1 = addLine(leftLines, "Left One");
		TestLine l2 = addLine(leftLines, "Left Two");
		TestLine l3 = addLine(leftLines, "Same");

		List<ValidatableLine> rightLines = new ArrayList<>();
		TestLine r1 = addLine(rightLines, "Right One");
		TestLine r2 = addLine(rightLines, "Right Two");
		TestLine r3 = addLine(rightLines, "Same");

		DataTypeDiffInput leftInput = new DiffInputTestStub(leftLines);
		DataTypeDiffInput rightInput = new DiffInputTestStub(rightLines);

		DataTypeDiff diff = DataTypeDiffBuilder.diffBody(leftInput, rightInput);
		assertNotNull(diff);

		DiffLines left = diff.getLeftLines();
		DiffLines right = diff.getRightLines();

		assertEquals(left.size(), right.size());

		assertDiffColored(l1, l2, r1, r2);
		assertNotDiffColored(l3, r3);
	}

	@Test
	public void testDiffBody_DifferentSize_SameTopAndBottom() {
		List<ValidatableLine> leftLines = new ArrayList<>();
		TestLine l1 = addLine(leftLines, "Line One");
		TestLine l2 = addLine(leftLines, "Line Two");
		TestLine l3 = addLine(leftLines, "Line Three");

		List<ValidatableLine> rightLines = new ArrayList<>();
		TestLine r1 = addLine(rightLines, "Line One");
		TestLine r2 = addLine(rightLines, "Insert A");
		TestLine r3 = addLine(rightLines, "Line Two");
		TestLine r4 = addLine(rightLines, "Insert B");
		TestLine r5 = addLine(rightLines, "Line Three");

		DataTypeDiffInput leftInput = new DiffInputTestStub(leftLines);
		DataTypeDiffInput rightInput = new DiffInputTestStub(rightLines);

		DataTypeDiff diff = DataTypeDiffBuilder.diffBody(leftInput, rightInput);
		assertNotNull(diff);

		DiffLines left = diff.getLeftLines();
		DiffLines right = diff.getRightLines();

		assertEquals(left.size(), right.size());

		assertDiffColored(r2, r4);// inserted lines are different; other should be matched
		assertNotDiffColored(l1, l2, l3, r1, r3, r5);
	}

	@Test
	public void testDiffBody_DifferentSize_AllDifferent() {
		List<ValidatableLine> leftLines = new ArrayList<>();
		addLine(leftLines, "Left One");
		addLine(leftLines, "Left Two");

		List<ValidatableLine> rightLines = new ArrayList<>();
		addLine(rightLines, "Right One");
		addLine(rightLines, "Right Two");
		addLine(rightLines, "Right Three");
		addLine(rightLines, "Right Four");
		addLine(rightLines, "Right Five");

		DataTypeDiffInput leftInput = new DiffInputTestStub(leftLines);
		DataTypeDiffInput rightInput = new DiffInputTestStub(rightLines);

		DataTypeDiff diff = DataTypeDiffBuilder.diffBody(leftInput, rightInput);
		assertNotNull(diff);

		DiffLines left = diff.getLeftLines();
		DiffLines right = diff.getRightLines();

		assertEquals(left.size(), right.size());

		assertDiffColored(left);
		assertDiffColored(right);
	}

	@Test
	public void testDiffBody_SameInitialLines_InsertsToBothAtDifferentOffsets() {
		//
		// This test is a bit peculiar.  It intends to test that the diffs generated will not
		// be the same size when there are different inserted elements at indices that overlap.
		// This test is really to achieve code coverage.
		//

		List<ValidatableLine> leftLines = new ArrayList<>();
		TestLine l1 = addLine(leftLines, "Line One");
		TestLine l2 = addLine(leftLines, "Left One - A");
		TestLine l3 = addLine(leftLines, "Left One - B");
		TestLine l4 = addLine(leftLines, "Left One - C");
		TestLine l5 = addLine(leftLines, "Line Two");
		TestLine l6 = addLine(leftLines, "Line Three");
		TestLine l7 = addLine(leftLines, "Line Four");

		List<ValidatableLine> rightLines = new ArrayList<>();
		TestLine r1 = addLine(rightLines, "Line One");
		TestLine r2 = addLine(rightLines, "Line Two");
		TestLine r3 = addLine(rightLines, "Right Two - A");
		TestLine r4 = addLine(rightLines, "Right Two - B");
		TestLine r5 = addLine(rightLines, "Line Three");
		TestLine r6 = addLine(rightLines, "Line Four");

		DataTypeDiffInput leftInput = new DiffInputTestStub(leftLines);
		DataTypeDiffInput rightInput = new DiffInputTestStub(rightLines);

		DataTypeDiff diff = DataTypeDiffBuilder.diffBody(leftInput, rightInput);
		assertNotNull(diff);

		DiffLines left = diff.getLeftLines();
		DiffLines right = diff.getRightLines();

		assertEquals("Expected left side to be 1 larger due to conflicting inserted items",
			left.size() - right.size(), 1);

		showDiffs(diff);

		// Items matched:     'Line One', 'Line Two', 'Line Three', 'Line Four'
		// Items not matched: 'Left One - *', 'Right Two - *'
		assertNotDiffColored(l1, l5, l6, l7, r1, r2, r5, r6);// these items were matched-up
		assertDiffColored(l2, l3, l4, r3, r4);// these were not

		assertNoDuplicates(left);
		assertNoDuplicates(right);
	}

	@Test
	public void testHeaderLines_Same() {
		List<ValidatableLine> leftLines = new ArrayList<>();
		addLine(leftLines, "Line One");
		addLine(leftLines, "Line Two");

		List<ValidatableLine> rightLines = new ArrayList<>();
		addLine(rightLines, "Line One");
		addLine(rightLines, "Line Two");

		DataTypeDiffInput leftInput = new DiffInputTestStub(leftLines);
		DataTypeDiffInput rightInput = new DiffInputTestStub(rightLines);

		DataTypeDiff diff = DataTypeDiffBuilder.diffBody(leftInput, rightInput);
		assertNotNull(diff);
		showDiffs(diff);

		DiffLines left = diff.getLeftLines();
		DiffLines right = diff.getRightLines();
		assertEquals(left.size(), right.size());

		assertNotDiffColored(left);
		assertNotDiffColored(right);
	}

	@Test
	public void testHeaderLines_Different_SameSize() {
		List<ValidatableLine> leftLines = new ArrayList<>();
		TestLine l1 = addLine(leftLines, "Line One");
		TestLine l2 = addLine(leftLines, "Left Two");

		List<ValidatableLine> rightLines = new ArrayList<>();
		TestLine r1 = addLine(rightLines, "Line One");
		TestLine r2 = addLine(rightLines, "Right Two");

		DataTypeDiffInput leftInput = new DiffInputTestStub(leftLines);
		DataTypeDiffInput rightInput = new DiffInputTestStub(rightLines);

		DataTypeDiff diff = DataTypeDiffBuilder.diffBody(leftInput, rightInput);
		assertNotNull(diff);
		showDiffs(diff);

		DiffLines left = diff.getLeftLines();
		DiffLines right = diff.getRightLines();
		assertEquals(left.size(), right.size());

		assertNotDiffColored(l1, r1);
		assertDiffColored(l2, r2);
	}

	@Test
	public void testHeaderLines_Different_DifferentSize() {
		List<ValidatableLine> leftLines = new ArrayList<>();
		TestLine l1 = addLine(leftLines, "Line One");
		TestLine l2 = addLine(leftLines, "Left Two");

		List<ValidatableLine> rightLines = new ArrayList<>();
		TestLine r1 = addLine(rightLines, "Line One");
		TestLine r2 = addLine(rightLines, "Right Two");
		TestLine r3 = addLine(rightLines, "Right Three");
		TestLine r4 = addLine(rightLines, "Right Four");

		DataTypeDiffInput leftInput = new DiffInputTestStub(leftLines);
		DataTypeDiffInput rightInput = new DiffInputTestStub(rightLines);

		DataTypeDiff diff = DataTypeDiffBuilder.diffBody(leftInput, rightInput);
		assertNotNull(diff);
		showDiffs(diff);

		DiffLines left = diff.getLeftLines();
		DiffLines right = diff.getRightLines();
		assertEquals(left.size(), right.size());

		assertNotDiffColored(l1, r1);
		assertDiffColored(l2, r2, r3, r4);
	}

	@Test
	public void testHighlightDifferences_Same() {
		List<ValidatableLine> leftLines = new ArrayList<>();
		TestLine l1 = addLine(leftLines, "Line One");
		TestLine l2 = addLine(leftLines, "Line Two");

		List<ValidatableLine> rightLines = new ArrayList<>();
		TestLine r1 = addLine(rightLines, "Line One");
		TestLine r2 = addLine(rightLines, "Line Two");

		DataTypeDiffBuilder.highlightDifferences(leftLines, rightLines);

		assertNotDiffColored(l1, l2, r1, r2);
	}

	@Test
	public void testHighlightDifferences_Different() {
		List<ValidatableLine> leftLines = new ArrayList<>();
		TestLine l1 = addLine(leftLines, "Line One");
		TestLine l2 = addLine(leftLines, "Left Two");

		List<ValidatableLine> rightLines = new ArrayList<>();
		TestLine r1 = addLine(rightLines, "Line One");
		TestLine r2 = addLine(rightLines, "Right Two");

		DataTypeDiffBuilder.highlightDifferences(leftLines, rightLines);

		assertNotDiffColored(l1, r1);
		assertDiffColored(l2, r2);
	}

	@Test
	public void testHighlightDifferences_DifferentSizes() {
		List<ValidatableLine> leftLines = new ArrayList<>();
		addLine(leftLines, "Line One");

		List<ValidatableLine> rightLines = new ArrayList<>();
		addLine(rightLines, "Line One");
		addLine(rightLines, "Right Two");

		try {
			DataTypeDiffBuilder.highlightDifferences(leftLines, rightLines);
			Assert.fail("Did not get expected exception");
		}
		catch (IllegalArgumentException e) {
			// good!
		}
	}

	// TODO testHighlightDifferences

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void assertNoDuplicates(DiffLines lines) {
		List<ValidatableLine> temp = new ArrayList<>();
		for (ValidatableLine line : lines) {
			if (temp.contains(line)) {
				Assert.fail("Encountered duplicate line: " + line + " inside of: " + lines);
			}
			temp.add(line);
		}
	}

	private TestLine addLine(List<ValidatableLine> list, String text) {
		TestLine line = new TestLine(text);
		list.add(line);
		return line;
	}

	private void assertPlaceholder(ValidatableLine... lines) {
		for (ValidatableLine line : lines) {
			assertTrue(line instanceof PlaceHolderLine);
		}
	}

	private void assertDiffColored(ValidatableLine... lines) {
		for (ValidatableLine line : lines) {
			assertTrue("Line is not diff colored; should be different lines" + line,
				isDiffColored(line));
		}
	}

	private void assertNotDiffColored(ValidatableLine... lines) {
		for (ValidatableLine line : lines) {
			assertFalse("Line is diff colored; should be the same line " + line,
				isDiffColored(line));
		}
	}

	private void assertNotDiffColored(DiffLines lines) {
		for (ValidatableLine line : lines) {
			assertFalse("Line is diff colored when it is not different: " + line,
				isDiffColored(line));
		}
	}

	private void assertDiffColored(DiffLines lines) {
		for (ValidatableLine line : lines) {
			assertTrue("Line is different, but not diff colored: " + line, isDiffColored(line));
		}
	}

	private boolean isDiffColored(ValidatableLine line) {
		if (line instanceof PlaceHolderLine) {
			return true;// placeholder means that it is different than the opposite side
		}

		return line.isDiffColored();
	}

	@SuppressWarnings("unused")
	private void showDiffs(DataTypeDiff diff) {

		// debug
		if (true) {
			return;
		}

		DiffLines leftLines = diff.getLeftLines();
		DiffLines rightLines = diff.getRightLines();

		JFrame frame = new JFrame("HTML Highlighter Tester");

		JComponent content = buildSplitPane(toHTML(leftLines), toHTML(rightLines));

		frame.getContentPane().add(content);
		int width = 600;
		int height = 500;
		frame.setSize(width, height);
		Toolkit defaultToolkit = Toolkit.getDefaultToolkit();
		Dimension screenSize = defaultToolkit.getScreenSize();
		int x = (screenSize.width >> 1) - (width >> 1);
		int y = (screenSize.height >> 1) - (height >> 1);
		frame.setLocation(x, y);
		frame.setVisible(true);
	}

	private String toHTML(DiffLines lines) {
		StringBuilder buffy = new StringBuilder("<html>");

		for (ValidatableLine line : lines) {
			if (line.isDiffColored()) {
				buffy.append("<font color=\"red\">");
			}

			buffy.append(line.getText());

			if (line.isDiffColored()) {
				buffy.append("</font>");
			}

			buffy.append("<br>");
		}

		return buffy.toString();
	}

	private static JComponent buildSplitPane(String htmlLeft, String htmlRight) {
		JPanel panel = new JPanel(new BorderLayout());

		JPanel rightPanel = new JPanel(new BorderLayout());
		JLabel rightLabel = new GHtmlLabel(htmlLeft);
		rightLabel.setOpaque(true);
		rightLabel.setBackground(Color.WHITE);
		rightLabel.setVerticalAlignment(SwingConstants.TOP);
		rightPanel.add(rightLabel);

		JPanel leftPanel = new JPanel(new BorderLayout());
		JLabel leftLabel = new GHtmlLabel(htmlRight);
		leftLabel.setOpaque(true);
		leftLabel.setBackground(Color.WHITE);
		leftLabel.setVerticalAlignment(SwingConstants.TOP);
		leftPanel.add(leftLabel);

		JSplitPane pane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(leftPanel),
			new JScrollPane(rightPanel));
		pane.setResizeWeight(.5);
		panel.add(pane);

		return panel;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class TestLine extends TextLine {
		public TestLine(String text) {
			super(text);
		}

		@Override
		public String toString() {
			return getText() + (isDiffColored() ? " <diff> " : "");
		}
	}

	private class DiffInputTestStub implements DataTypeDiffInput {

		private List<ValidatableLine> lines;

		DiffInputTestStub(List<ValidatableLine> lines) {
			this.lines = lines;
		}

		@Override
		public List<ValidatableLine> getLines() {
			return lines;
		}

		@Override
		public PlaceHolderLine createPlaceHolder(ValidatableLine oppositeLine) {
			return new EmptyTextLine(1);
		}
	}
}
