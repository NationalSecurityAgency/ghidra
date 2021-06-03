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
package ghidra.app.plugin.core.comments;

import java.awt.BorderLayout;
import java.awt.Color;

import javax.swing.JPanel;
import javax.swing.JTextPane;
import javax.swing.text.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentHistory;
import ghidra.program.model.listing.Program;
import ghidra.util.DateUtils;
import ghidra.util.Msg;

/**
 * Panel that shows comment history for a particular comment type; uses
 * a JTextPane to show information in different colors and fonts for
 * readability.
 */
class CommentHistoryPanel extends JPanel {

	private final static String NO_HISTORY = "No History Found";
	private SimpleAttributeSet userAttrSet;
	private SimpleAttributeSet dateAttrSet;
	private SimpleAttributeSet textAttrSet;
	private SimpleAttributeSet tabAttrSet;

	private StyledDocument doc;
	private JTextPane textPane;

	private int commentType;

	/**
	 * Construct a new CommentHistoryPanel 
	 * @param commentType comment type
	 */
	CommentHistoryPanel(int commentType) {

		super(new BorderLayout());
		setUpAttributes();
		this.commentType = commentType;
		create();
	}

	/**
	 * Show the comment history
	 * @param program program 
	 * @param addr address of comment history
	 */
	void showCommentHistory(Program program, Address addr) {

		textPane.setText("");

		CommentHistory[] historyItems = program.getListing().getCommentHistory(addr, commentType);
		try {
			if (historyItems.length == 0) {
				doc.insertString(0, NO_HISTORY, null);
				doc.setCharacterAttributes(0, NO_HISTORY.length(), textAttrSet, true);
				return;
			}
			for (CommentHistory historyItem : historyItems) {
				formatHistory(historyItem);
			}
		}
		catch (BadLocationException e) {
			// shouldn't happen
			Msg.debug(this, "Error setting comment text field text", e);
		}
		textPane.setCaretPosition(0);
	}

	private void create() {
		textPane = new JTextPane();
		textPane.setEditable(false);
		add(textPane, BorderLayout.CENTER);
		doc = textPane.getStyledDocument();
	}

	private void formatHistory(CommentHistory history) throws BadLocationException {

		int offset = doc.getLength();
		String userName = history.getUserName();

		if (offset > 0) {
			userName = "\n" + userName;
		}
		doc.insertString(offset, userName, userAttrSet);

		offset = doc.getLength();
		doc.insertString(offset,
			"\t" + DateUtils.formatDateTimestamp(history.getModificationDate()), dateAttrSet);
		doc.setParagraphAttributes(offset, 1, tabAttrSet, false);

		offset = doc.getLength();
		doc.insertString(offset, "\n" + history.getComments() + "\n", textAttrSet);
	}

	private void setUpAttributes() {
		textAttrSet = new SimpleAttributeSet();
		textAttrSet.addAttribute(StyleConstants.FontFamily, "Monospaced");
		textAttrSet.addAttribute(StyleConstants.FontSize, Integer.valueOf(12));
		textAttrSet.addAttribute(StyleConstants.Foreground, Color.BLUE);

		userAttrSet = new SimpleAttributeSet();
		userAttrSet.addAttribute(StyleConstants.FontFamily, "Tahoma");
		userAttrSet.addAttribute(StyleConstants.FontSize, Integer.valueOf(12));
		userAttrSet.addAttribute(StyleConstants.Bold, Boolean.TRUE);

		dateAttrSet = new SimpleAttributeSet();
		dateAttrSet.addAttribute(StyleConstants.FontFamily, "Tahoma");
		dateAttrSet.addAttribute(StyleConstants.FontSize, Integer.valueOf(11));
		dateAttrSet.addAttribute(StyleConstants.Bold, Boolean.TRUE);
		dateAttrSet.addAttribute(StyleConstants.Foreground, new Color(124, 37, 18));

		tabAttrSet = new SimpleAttributeSet();
		TabStop tabs = new TabStop(100, StyleConstants.ALIGN_LEFT, TabStop.LEAD_NONE);
		StyleConstants.setTabSet(tabAttrSet, new TabSet(new TabStop[] { tabs }));
	}

}
