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
package ghidra.app.plugin.core.byteviewer;

import java.awt.Color;

import docking.widgets.fieldpanel.support.Highlight;
import generic.theme.GColor;

class ByteViewerHighlighter {

	private static Highlight[] NO_HIGHLIGHTS = new Highlight[0];
	private String highlightText;
	private Color highlightColor = new GColor("color.bg.byteviewer.highlight");

	public Highlight[] createHighlights(String text) {

		if (text.equals(highlightText)) {
			return new Highlight[] { new Highlight(0, text.length() - 1, highlightColor) };
		}
		return NO_HIGHLIGHTS;
	}

	void setText(String text) {
		highlightText = text;
	}

	String getText() {
		return highlightText;
	}

	void setHighlightColor(Color color) {
		this.highlightColor = color;
	}
}
