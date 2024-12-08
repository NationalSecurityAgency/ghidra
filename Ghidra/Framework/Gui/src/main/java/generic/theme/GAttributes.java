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
package generic.theme;

import java.awt.Font;

import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;

import ghidra.util.HTMLUtilities;

/**
 * A drop-in replacement for clients using {@link SimpleAttributeSet}s.  This class will apply a
 * default set of font attributes based on the given font and optional color.
 */
public class GAttributes extends SimpleAttributeSet {

	public GAttributes(Font f) {
		this(f, null);
	}

	public GAttributes(Font f, GColor c) {
		addAttribute(StyleConstants.FontFamily, f.getFamily());
		addAttribute(StyleConstants.FontSize, f.getSize());
		addAttribute(StyleConstants.Bold, f.isBold());
		addAttribute(StyleConstants.Italic, f.isItalic());

		if (c != null) {
			addAttribute(StyleConstants.Foreground, c);
		}
	}

	/**
	 * A convenience method to style the given text in HTML using the font and color attributes
	 * defined in this attribute set.  The text will be HTML escaped.
	 *
	 * @param content the content
	 * @return the styled content
	 * @see HTMLUtilities#styleText(SimpleAttributeSet, String)
	 */
	public String toStyledHtml(String content) {
		return HTMLUtilities.styleText(this, content);
	}
}
