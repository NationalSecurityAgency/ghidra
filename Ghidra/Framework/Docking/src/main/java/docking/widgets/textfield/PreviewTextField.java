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
package docking.widgets.textfield;

import java.awt.*;
import java.util.Objects;

import javax.swing.InputVerifier;
import javax.swing.SwingConstants;

import ghidra.util.HTMLUtilities;

/**
 * Abstract base class for text fields that can show a preview of a modified version of their text
 * when it does not have focus.
 * <p>
 * The tool tip of the field is updated to include the full value of the field if the preview was
 * truncated during painting.  Override {@link #getPreviewToolTipAdditionalText()} to control
 * what text is added to the tool tip in those cases.
 * <p>
 * NOTE: using an ending &lt;/HTML&gt; tag in a tool tip string is not recommended as it will
 * defeat PreviewTextField's updated information from being displayed to the user.
 */
public abstract class PreviewTextField extends HintTextField {

	private String origToolTip;
	private boolean previewWasTruncated;

	protected PreviewTextField(String text, String hint, boolean required, InputVerifier verifier) {
		super(text, hint, required, verifier);
	}

	/**
	 * Generates a modified version of the specified string in a usage-specific manner.  The 
	 * returned string will be used as a preview of the text field's value
	 * (when the text field does not have focus).
	 * 
	 * @param s string to base the preview value on
	 * @param fm FontMetrics to use when measuring the length of the string
	 * @param maxWidth maximum desired width of the string that should be returned by this method 
	 * @return shortened version of parameter s
	 */
	protected abstract String getPreviewString(String s, FontMetrics fm, int maxWidth);

	@Override
	public void paintComponent(Graphics g) {
		boolean oldTrucatedFlag = previewWasTruncated;
		previewWasTruncated = false;
		if (isFocusOwner() || getText().isEmpty()) {
			super.paintComponent(g);
		}
		else {
			paintPreviewText((Graphics2D) g);
		}
		if (oldTrucatedFlag != previewWasTruncated) {
			updatePreviewToolTip();
		}
	}

	private void paintPreviewText(Graphics2D g2) {

		g2.setColor(getForeground());
		g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

		FontMetrics fm = g2.getFontMetrics();
		Dimension size = getSize();
		Insets insets = getInsets();
		int fontHt = fm.getDescent() + fm.getAscent();
		int compHt = size.height - insets.top - insets.bottom;
		int compW = size.width - insets.left - insets.right;
		int baselineY = insets.top + fm.getAscent() + ((compHt - fontHt) / 2);

		String s = getText();
		int strW = fm.stringWidth(s);
		if (strW > compW) {
			previewWasTruncated = true;
			s = getPreviewString(s, fm, compW);
			strW = fm.stringWidth(s);
		}
		int x = insets.left + switch (getHorizontalAlignment()) {
			case SwingConstants.LEFT -> 0;
			case SwingConstants.CENTER -> compW / 2 - strW / 2;
			case SwingConstants.RIGHT -> compW - strW;
			default -> 0;
		};
		g2.drawString(s, x, baselineY);
	}

	/**
	 * {@return string that should be appended to the tool tip when the text field preview has been
	 * truncated.  Defaults to the plain text of the field.}
	 */
	protected String getPreviewToolTipAdditionalText() {
		return getText();
	}

	private void updatePreviewToolTip() {
		super.setToolTipText(getPreviewToolTip());
	}

	private String getPreviewToolTip() {
		String text = previewWasTruncated
				? Objects.requireNonNullElse(getPreviewToolTipAdditionalText(), "")
				: "";
		if ( text.isEmpty()) {
			return origToolTip;
		}
		String s = Objects.requireNonNullElse(origToolTip, "");
		if (!s.isEmpty()) {
			s += HTMLUtilities.isHTML(s) ? "<br><br>" : "\n\n";
		}
		s += text;
		return s;
	}

	@Override
	public void setText(String text) {
		super.setText(text);
		updatePreviewToolTip();
	}

	@Override
	public void setToolTipText(String text) {
		this.origToolTip = text;
		updatePreviewToolTip();
	}
}
