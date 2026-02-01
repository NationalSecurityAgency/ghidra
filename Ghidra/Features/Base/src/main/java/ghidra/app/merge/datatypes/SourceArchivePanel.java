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

import java.awt.BorderLayout;
import java.awt.Font;
import java.util.Date;

import javax.swing.JPanel;
import javax.swing.JTextPane;
import javax.swing.text.*;

import generic.theme.GAttributes;
import generic.theme.GThemeDefaults.Colors.Palette;
import generic.theme.Gui;
import ghidra.program.model.data.ArchiveType;
import ghidra.program.model.data.SourceArchive;
import ghidra.util.Msg;

/**
 * Panel to show the contents of a Source Archive.
 */
class SourceArchivePanel extends JPanel {

	private SourceArchive sourceArchive;
	private JTextPane textPane;
	private StyledDocument doc;
	private SimpleAttributeSet headingAttrs;
	private SimpleAttributeSet valueAttrs;
	private SimpleAttributeSet deletedAttrs;

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

		Font monospaced = Gui.getFont("font.monospaced");
		Font bold = Gui.getFont("font.standard.bold");

		headingAttrs = new GAttributes(monospaced, Palette.BLUE);
		valueAttrs = new GAttributes(bold);
		deletedAttrs = new GAttributes(bold, Palette.RED);

		setSourceArchive(null);
	}

	private void formatSourceArchive() {
		if (sourceArchive == null) {
			insertString("\n\nDeleted", deletedAttrs);
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
		insertString("    Archive ID: ", headingAttrs);
		insertString(sourceArchive.getSourceArchiveID().getValue() + "\n", valueAttrs);
	}

	private void formatName() {
		insertString("Name: ", headingAttrs);
		insertString(sourceArchive.getName() + "\n", valueAttrs);
	}

	@SuppressWarnings("unused")
	private void formatFileID() {
		insertString("       File ID: ", headingAttrs);
		insertString(sourceArchive.getDomainFileID() + "\n", valueAttrs);
	}

	@SuppressWarnings("unused")
	private void formatType() {
		ArchiveType archiveType = sourceArchive.getArchiveType();
		String typeString = (archiveType == ArchiveType.FILE) ? "File Archive"
				: (archiveType == ArchiveType.PROGRAM) ? "Program"
						: (archiveType == ArchiveType.PROJECT) ? "Project Archive"
								: (archiveType == ArchiveType.BUILT_IN) ? "Built-In" : "Invalid";
		insertString("          Type: ", headingAttrs);
		insertString(typeString + "\n", valueAttrs);
	}

	private void formatSyncTime() {
		String syncTime = new Date(sourceArchive.getLastSyncTime()).toString();
		insertString("Last Sync Time: ", headingAttrs);
		insertString(syncTime + "\n", valueAttrs);
	}

	private void formatDirtyFlag() {
		insertString("Changed Since Last Sync? ", headingAttrs);
		insertString((sourceArchive.isDirty() ? "yes" : "no") + "\n", valueAttrs);
	}

	private void insertString(String str, SimpleAttributeSet attributeSet) {
		int offset = doc.getLength();

		try {
			doc.insertString(offset, str, attributeSet);
		}
		catch (BadLocationException e1) {
			Msg.debug(this, "Exception entering text", e1);
		}
	}
}
