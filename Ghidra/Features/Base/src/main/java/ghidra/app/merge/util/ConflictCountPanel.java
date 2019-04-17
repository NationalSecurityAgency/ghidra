/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.merge.util;

import java.awt.BorderLayout;
import java.awt.Color;

import javax.swing.*;
import javax.swing.text.*;

import ghidra.app.merge.MergeConstants;

/**
 * Panel that shows the current conflict number and the total number of
 * conflicts.
 * 
 * 
 */
public class ConflictCountPanel extends JPanel {

	private JTextPane textPane;
	private StyledDocument doc;
	private SimpleAttributeSet textAttrSet;
	private SimpleAttributeSet countAttrSet;

	/**
	 * Constructor
	 *
	 */
	public ConflictCountPanel() {
		super(new BorderLayout());
		create();
	}
	/**
	 * Update the counts, e.g., Conflict # 1 of 3.
	 * @param currentCount current
	 * @param totalCount total
	 */
	public void updateCount(int currentCount, int totalCount) {
		textPane.setText("");
		
		int offset = doc.getLength();
		try {
			doc.insertString(offset, "Conflict # ", textAttrSet);
			offset = doc.getLength();
			doc.insertString(offset, " "+currentCount +" ", countAttrSet);
			offset = doc.getLength();
			doc.insertString(offset, " of ", textAttrSet);
			offset = doc.getLength();
			doc.insertString(offset, " "+totalCount +" ", countAttrSet);
		} catch (BadLocationException e) {
		}
	
	}

	private void create() {
		
		setBorder(BorderFactory.createTitledBorder("Current Conflict"));
		textPane = new JTextPane();
		textPane.setBorder(BorderFactory.createEmptyBorder(10, 5, 10, 0));
		textPane.setEditable(false);
		add(textPane);
		
		doc = textPane.getStyledDocument();
		
		textPane.setBackground(getBackground());
		
		SimpleAttributeSet set = new SimpleAttributeSet();
		set.addAttribute(StyleConstants.Bold, Boolean.TRUE);
		set.addAttribute(StyleConstants.Foreground, Color.RED);

		textAttrSet = new SimpleAttributeSet();
		textAttrSet.addAttribute(StyleConstants.FontSize, new Integer(12));

		countAttrSet = new SimpleAttributeSet();
		countAttrSet.addAttribute(StyleConstants.Bold, Boolean.TRUE);
		countAttrSet.addAttribute(StyleConstants.Foreground, MergeConstants.CONFLICT_COLOR);
		updateCount(0, 10);
	}

}
