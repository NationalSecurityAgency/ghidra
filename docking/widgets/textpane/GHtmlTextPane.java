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
package docking.widgets.textpane;

import java.io.IOException;
import java.io.StringWriter;

import javax.swing.JTextPane;
import javax.swing.text.*;

import ghidra.util.HTMLUtilities;
import ghidra.util.Msg;

/**
 * A JTextPane for rendering HTML, as well as copying WYSIWYG text copying.
 */
public class GHtmlTextPane extends JTextPane {

	public GHtmlTextPane() {
		setContentType("text/html");
	}

	/** 
	 * Overridden to allow copying HTML content in its display form, without formatting.  The
	 * default Java copy action will call this method.
	 */
	@Override
	public String getSelectedText() {

		String html = getPrettifiedHtml();
		if (html != null) {
			return html;
		}
		return super.getSelectedText();
	}

	private String getPrettifiedHtml() {

		String selectedHtml = getSelectedHtmlText();
		String converted = HTMLUtilities.fromHTML(selectedHtml);
		return converted;
	}

	private String getSelectedHtmlText() {
		Document doc = getDocument();
		int start = getSelectionStart();
		int end = getSelectionEnd();
		try {
			Position startPos = doc.createPosition(start);
			Position endPos = doc.createPosition(end);

			int startOffset = startPos.getOffset();
			int endOffset = endPos.getOffset();
			int size = endOffset - startOffset;
			StringWriter stringWriter = new StringWriter(size);
			getEditorKit().write(stringWriter, doc, startOffset, size);
			String text = stringWriter.toString();
			return text;
		}
		catch (BadLocationException | IOException e) {
			Msg.error(this, "Unable to extract HTML text from editor pane", e);
		}
		return null;
	}
}
