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
 * Class to render a String that has new line characters as a multiline
 * label. Calculates the resizing and centering characteristics.
 * <p>
 * Not affected by HTML formatting.
 * <p>
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
	protected int margin_height; // top and botton margins
	protected int line_height; // total height of font
	protected int line_ascent; // font height above baseline
	protected int[] line_widths; // how wide each line is
	protected int max_width; // width of widest line
	protected int alignment = CENTER; // default alignment of text

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
	 * breaks specified label into array of lines.
	 *
	 *@param label String to display in canvas.
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

		// if no font metrics yet, just return

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
	 * Set a new label for JPanel
	 *
	 * @param label String to display in canvas
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
	 * Get the label text.
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

	/**
	 * Sets a new color for Canvas
	 *
	 *@param c Color to display in canvas
	 */
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

	/**
	 * Get alignment for text, LEFT, CENTER, RIGHT.
	 */
	public final int getAlignment() {
		return alignment;
	}

	/**
	 * Get margin width.
	 */
	public final int getMarginWidth() {
		return margin_width;
	}

	/**
	 *Get margin height.
	 */
	public final int getMarginHeight() {
		return margin_height;
	}

	/**
	 * This method is invoked after Canvas is first created
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

	/**
	 * This method is called by a layout manager when it wants
	 * to know how big we'd like to be
	 */
	@Override
	public java.awt.Dimension getPreferredSize() {
		return new Dimension(max_width + 2 * margin_width,
			num_lines * line_height + 2 * margin_height);

	}

	/**
	 * This method is called when layout manager wants to
	 * know the bare minimum amount of space we need to get by.
	 */
	@Override
	public java.awt.Dimension getMinimumSize() {

		return new Dimension(max_width, num_lines * line_height);
	}

	/**
	 * This method draws label (applets use same method).
	 * Note that it handles the margins and the alignment, but
	 * that is does not have to worry about the color or font --
	 * the superclass takes care of setting those in the Graphics
	 * object we've passed.
	 * @param g the graphics context to paint with.
	 */
	@Override
	public void paint(Graphics g) {

		int x, y;
		Dimension d = this.getSize();
//		g.clearRect(0, 0, d.width, d.height);

		y = line_ascent + (d.height - num_lines * line_height) / 2;
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

	/**
	 * Simple test for the MultiLineLabel class.
	 * @param args not used
	 */
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
