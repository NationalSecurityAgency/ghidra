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
package ghidra.app.decompiler.component;

import java.awt.Color;
import java.awt.Graphics;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.field.*;
import ghidra.app.decompiler.ClangToken;

public class ClangFieldElement extends AbstractTextFieldElement {

	private final ClangToken token;

	public ClangFieldElement(ClangToken token, AttributedString as, int col) {
		super(as, 0, col);
		this.token = token;
	}

	ClangToken getToken() {
		return token;
	}

	@Override
	public void paint(JComponent c, Graphics g, int x, int y) {
		Color highlightColor = token.getHighlight();
		if (highlightColor != null) {
			g.setColor(highlightColor);
			g.fillRect(x, y - getHeightAbove(), getStringWidth(),
				getHeightAbove() + getHeightBelow());
		}

		super.paint(c, g, x, y);

		if (token.isMatchingToken()) {
			// paint a bounding box around the token
			g.setColor(Color.GRAY);
			int offset = 1;
			g.drawRect(x - offset, y - getHeightAbove() - offset, getStringWidth() + (offset * 2),
				getHeightAbove() + getHeightBelow() + (offset * 2));
		}
	}

	@Override
	public FieldElement substring(int start, int end) {
		AttributedString as = attributedString.substring(start, end);
		if (as == attributedString) {
			return this;
		}
		return new ClangFieldElement(token, as, column + start);
	}

	@Override
	public FieldElement replaceAll(char[] targets, char replacement) {
		return new ClangFieldElement(token, attributedString.replaceAll(targets, replacement),
			column);
	}
}
