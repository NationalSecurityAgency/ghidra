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
package docking.widgets.fieldpanel.support;

import java.awt.Color;

import generic.json.Json;

public class Highlight {
	private int start;
	private int end;
	private int offset;
	private Color color;

	/**
	 * Constructs a new Highlight that indicates where to highlight text in the listing fields.
	 * @param start the starting character position to highlight
	 * @param end the ending character position (inclusive) to highlight
	 * @param color the color to use for highlighting.
	 */
	public Highlight(int start, int end, Color color) {
		this.start = start;
		this.end = end;
		this.color = color;
	}

	/**
	 * {@return the starting position of the highlight}
	 */
	public int getStart() {
		return start + offset;
	}

	/**
	 * {@return the ending position (inclusive) of the highlight}
	 */
	public int getEnd() {
		return end + offset;
	}

	/**
	 * {@return the number of characters in the match.}
	 */
	public int length() {
		return (end - start) + 1; // +1 because 'end' is inclusive
	}

	/**
	 * {@return the color to use as the background highlight color.}
	 */
	public Color getColor() {
		return color;
	}

	/**
	 * Sets the offset of this highlights start and end values.  The effect of the offset is that
	 * calls to {@link #getStart()} and {@link #getEnd()} will return their values with the 
	 * offset added.  
	 * <p>
	 * This useful when highlights are using offsets for widgets that embedded inside of composite
	 * containers.  the parent container turn these relative values into absolute values that work
	 * when all sub-parts are combined.
	 * 
	 * @param newOffset The new offset into this highlight.
	 */
	public void setOffset(int newOffset) {
		offset = newOffset;
	}

	@Override
	public String toString() {
		return Json.toString(this);
	}
}
