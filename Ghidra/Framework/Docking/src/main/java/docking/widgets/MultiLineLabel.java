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
package docking.widgets;

import java.awt.*;

import javax.swing.JFrame;
import javax.swing.JPanel;

import docking.util.GraphicsUtils;
import ghidra.util.Msg;
import utilities.util.reflection.ReflectionUtilities;

/**
 *  
 * Class to render a String that has new line characters as a multi-line
 * label. Calculates the resizing and centering characteristics.
 * <p>
 * Not affected by HTML formatting.
 */

public class MultiLineLabel extends JPanel {
	/**
	 * Indicator for left alignment.
	 */
	public static final int LEFT = 0;
	/**
	 * Indicator for centering each line.
	 */
	public static final int CENTER = 1;
	/**
	 * Indicator for right alignment.
	 */
	public static final int RIGHT = 2;

	protected String[] lines; // lines to text to display
	protected int num_lines; // number of lines
	protected int margin_width; // left and right margins
	protected int margin_height; // top and bottom margins
	protected int line_height; // total height of font
	protected int line_ascent; // font height above baseline
	protected int[] line_widths; // how wide each line is
	protected int max_width; // width of widest line
	protected int alignment = CENTER; // default alignment of text
	private VerticalAlignment verticalAlignment = VerticalAlignment.MIDDLE;

	/** Values for controlling vertical alignment of the text */
	public enum VerticalAlignment {
		TOP,
		MIDDLE;
	}

	/**
	 * Default constructor.
	 */
	public MultiLineLabel() {
	}

	/**
	 * Construct a new MultiLineLabel.
	 *
	 * @param label String to split up if it contains new line characters
	 * @param margin_width width of label
	 * @param margin_height height of label
	 * @param alignment alignment of label, LEFT, CENTER, or RIGHT
	 */
	public MultiLineLabel(String label, int margin_width, int margin_height, int alignment) {
		super();
		setDoubleBuffered(false);
		newLabel(label);
		this.margin_width = margin_width;
		this.margin_height = margin_height;
		this.alignment = alignment;

	}

	/**
	 * Construct a new MultiLineLabel that is left aligned with the default
	 * width and height margins.
	 *
	 * @param label String to split up if it contains new line characters
	 */
	public MultiLineLabel(String label) {
		this(label, 10, 10, LEFT);
	}

	/**
	 * Breaks specified label into array of lines.
	 *
	 *@param label String to display.
	 */
	protected void newLabel(String label) {
		if (label == null) {
			label = "No label given for this dialog.\nThis was likely due to an " +
				"exception with no message from the line of code below:\n\n" + getCallerString();
			Msg.debug(label, label, new Throwable());
		}

		lines = label.split("\n");
		num_lines = lines.length;
		line_widths = new int[num_lines];
	}

	private String getCallerString() {
		String name = ReflectionUtilities.getClassNameOlderThan(OptionDialog.class);
		return name;
	}

	/**
	 * This method figures out how large the font is, and how wide
	 * each line of the label is, and how wide the widest line is.
	 */
	protected void measure() {

		FontMetrics fm = this.getFontMetrics(this.getFont());
		if (fm == null) {
			return;
		}

		line_height = fm.getHeight();
		line_ascent = fm.getAscent();
		max_width = 0;
		for (int i = 0; i < num_lines; i++) {
			line_widths[i] = fm.stringWidth(lines[i]);
			if (line_widths[i] > max_width) {
				max_width = line_widths[i];
			}
		}

	}

	/**
	 * Set a new label to display.
	 *
	 * @param label String to display
	 */
	public void setLabel(String label) {

		newLabel(label);
		measure();
		repaint();
	}

	/**
	 * Set the label text.
	 * @param text array of strings to display.
	 */
	public void setLabel(String[] text) {
		line_widths = new int[text.length];
		lines = text;
		num_lines = text.length;
		measure();
		repaint();
	}

	/**
	 * {@return the label text.}
	 */
	public String getLabel() {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < lines.length; i++) {
			sb.append(lines[i]);
			if (i < lines.length - 1) {
				sb.append("\n");
			}
		}
		return sb.toString();
	}

	/**
	 * Sets a new font for label
	 *
	 * @param f Font to set label
	 */
	@Override
	public void setFont(Font f) {

		super.setFont(f);
		measure();
		repaint();
	}

	@Override
	public void setForeground(Color c) {
		super.setForeground(c);
		repaint();
	}

	/**
	 * Set alignment for text, LEFT, RIGHT, CENTER.
	 * @param a the new alignment.
	 */
	public void setAlignment(int a) {
		alignment = a;
		repaint();
	}

	/**
	 * Sets the vertical alignment of the text.  The default is {@link VerticalAlignment#MIDDLE}.
	 * @param alignment the alignment
	 */
	public void setVerticalAlignment(VerticalAlignment alignment) {
		this.verticalAlignment = alignment;
		repaint();
	}

	/**
	 * Set margin width.
	 * @param mw the new margin width.
	 */
	public void setMarginWidth(int mw) {
		margin_width = mw;
		repaint();
	}

	/**
	 * Sets the margin height
	 * @param mh the new margin height.
	 */
	public void setMarginHeight(int mh) {
		margin_height = mh;
		repaint();
	}

	public final int getAlignment() {
		return alignment;
	}

	public final int getMarginWidth() {
		return margin_width;
	}

	public final int getMarginHeight() {
		return margin_height;
	}

	/**
	 * This method is invoked after this class is first created
	 * but before it can be actually displayed. After we have
	 * invoked our superclass's addNotify() method, we have font
	 * metrics and can successfully call measure() to figure out
	 * how big the label is.
	 */
	@Override
	public void addNotify() {
		super.addNotify();
		measure();
	}

	@Override
	public Dimension getPreferredSize() {
		return new Dimension(max_width + 2 * margin_width,
			num_lines * line_height + 2 * margin_height);

	}

	@Override
	public Dimension getMinimumSize() {

		return new Dimension(max_width, num_lines * line_height);
	}

	@Override
	public void paint(Graphics g) {

		paintBorder(g);

		Dimension d = this.getSize();

		int y;
		if (verticalAlignment == VerticalAlignment.MIDDLE) {
			y = line_ascent + (d.height - num_lines * line_height) / 2;
		}
		else {
			y = margin_height + line_ascent;
		}
		int x;
		for (int i = 0; i < num_lines; i++, y += line_height) {
			switch (alignment) {
				case LEFT:
					x = margin_width;
					break;
				case CENTER:
				default:
					x = (d.width - line_widths[i]) / 2;
					break;
				case RIGHT:
					x = d.width - margin_width - line_widths[i];
					break;

			}

			GraphicsUtils.drawString(this, g, lines[i], x, y);
		}
	}

	public static void main(String[] args) {

		MultiLineLabel mlab = new MultiLineLabel(
			"This is a test\nof a multi-line label\nLine One\n\nLine Two\nLine Three.", 20, 20,
			MultiLineLabel.CENTER);
		JFrame f = new JFrame("Test MultiLineLabel");
		f.getContentPane().add(mlab);
		f.pack();
		f.setVisible(true);
	}
}
