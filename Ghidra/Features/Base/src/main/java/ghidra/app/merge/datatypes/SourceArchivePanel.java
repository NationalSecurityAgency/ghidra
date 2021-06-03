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
package ghidra.app.merge.datatypes;

import ghidra.program.model.data.ArchiveType;
import ghidra.program.model.data.SourceArchive;

import java.awt.BorderLayout;
import java.awt.Color;
import java.util.Date;

import javax.swing.JPanel;
import javax.swing.JTextPane;
import javax.swing.text.*;

/**
 * Panel to show the contents of a Source Archive.
 */
class SourceArchivePanel extends JPanel {

	private SourceArchive sourceArchive;
	private JTextPane textPane;
	private StyledDocument doc;
	private SimpleAttributeSet headingAttrSet;
	private SimpleAttributeSet valueAttrSet;
	private SimpleAttributeSet deletedAttrSet;
	
	SourceArchivePanel() {
		super(new BorderLayout());
		create();
	}
	
	public void setSourceArchive(SourceArchive sourceArchive) {
		this.sourceArchive = sourceArchive;
		textPane.setText("");
		formatSourceArchive(); 
		textPane.setCaretPosition(0);
	}
	
	private void create() {
		textPane = new JTextPane(); 
		doc = textPane.getStyledDocument();
		add(textPane, BorderLayout.CENTER);
		textPane.setEditable(false);
		
		headingAttrSet = new SimpleAttributeSet();
		headingAttrSet.addAttribute(StyleConstants.FontFamily, "Monospaced");
		headingAttrSet.addAttribute(StyleConstants.FontSize, new Integer(12));
		headingAttrSet.addAttribute(StyleConstants.Foreground, Color.BLUE);
		
		valueAttrSet = new SimpleAttributeSet();
		valueAttrSet.addAttribute(StyleConstants.FontFamily, "Tahoma");
		valueAttrSet.addAttribute(StyleConstants.FontSize, new Integer(11));
		valueAttrSet.addAttribute(StyleConstants.Bold, Boolean.TRUE);

		deletedAttrSet = new SimpleAttributeSet();
		deletedAttrSet.addAttribute(StyleConstants.FontFamily, "Tahoma");
		deletedAttrSet.addAttribute(StyleConstants.FontSize, new Integer(12));
		deletedAttrSet.addAttribute(StyleConstants.Bold, Boolean.TRUE);
		deletedAttrSet.addAttribute(StyleConstants.Foreground, Color.RED);
		
		setSourceArchive(null);
	}
	
	private void formatSourceArchive() {
		if (sourceArchive == null) {
			insertString("\n\nDeleted", deletedAttrSet); 
			return;
		}
//		formatArchiveID();
		formatName();
//		formatFileID();
//		formatType();
		formatSyncTime();
		formatDirtyFlag();
	}
	
	@SuppressWarnings("unused")
	private void formatArchiveID() {
		insertString("    Archive ID: ", headingAttrSet);
		insertString(sourceArchive.getSourceArchiveID().getValue() + "\n", valueAttrSet);
	}
	
	private void formatName() {
		insertString("Name: ", headingAttrSet);
		insertString(sourceArchive.getName() + "\n", valueAttrSet);
	}
	
	@SuppressWarnings("unused")
	private void formatFileID() {
		insertString("       File ID: ", headingAttrSet);
		insertString(sourceArchive.getDomainFileID() + "\n", valueAttrSet);
	}
	
	@SuppressWarnings("unused")
	private void formatType() {
		ArchiveType archiveType = sourceArchive.getArchiveType();
		String typeString = (archiveType == ArchiveType.FILE) ? "File Archive"
				: (archiveType == ArchiveType.PROGRAM) ? "Program"
				: (archiveType == ArchiveType.PROJECT) ? "Project Archive"
				: (archiveType == ArchiveType.BUILT_IN) ? "Built-In"
				: "Invalid";
		insertString("          Type: ", headingAttrSet);
		insertString(typeString + "\n", valueAttrSet);
	}
	
	private void formatSyncTime() {
		String syncTime = new Date(sourceArchive.getLastSyncTime()).toString();
		insertString("Last Sync Time: ", headingAttrSet);
		insertString(syncTime + "\n", valueAttrSet);
	}
	
	private void formatDirtyFlag() {
		insertString("Changed Since Last Sync? ", headingAttrSet);
		insertString((sourceArchive.isDirty() ? "yes" : "no") + "\n", valueAttrSet);
	}
	
//	private String pad(String str, int length) {
//		StringBuffer sb = new StringBuffer(str);
//		int len = length - str.length();
//		for (int i=0; i<len; i++) {
//			sb.append(" ");
//		}
//		return sb.toString();
//	}
//	
	private void insertString(String str, SimpleAttributeSet attributeSet) {
		int offset = doc.getLength();

		try {
			doc.insertString(offset, str, attributeSet);
		} catch (BadLocationException e1) {
		}
	}
}
