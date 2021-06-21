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
package docking.widgets.shapes;

/**
 * Specifies location and metrics for {@link PopupWindowPlacer}.
 */
public enum Location {
	LEFT, RIGHT, TOP, BOTTOM, CENTER;

	static {
		LEFT.set(false, true, RIGHT, TOP);
		RIGHT.set(true, true, LEFT, BOTTOM);
		TOP.set(false, false, BOTTOM, RIGHT);
		BOTTOM.set(true, false, TOP, LEFT);
		CENTER.set(null, null, null, null);
	}

	// Tri-valued value: false === Lesser, and null === Center
	private Boolean isGreater;
	// Tri-valued value: false === Vertical, and null === either (e.g., Center)
	// Means it is a measure of horizontal (e.g., left right) as opposed to a left edge, which
	// is a vertical line (the minor elements which describe location on this edge are vertical).
	private Boolean isHorizontal;
	private Location match;
	private Location clockwiseNext;

	private void set(Boolean isGreater, Boolean isHorizontal, Location match,
			Location clockwiseNext) {
		this.isGreater = isGreater;
		this.isHorizontal = isHorizontal;
		this.match = match;
		this.clockwiseNext = clockwiseNext;
	}

	public boolean isGreater() {
		return isGreater != null && isGreater;
	}

	public boolean isLesser() {
		return isGreater != null && !isGreater;
	}

	public boolean isCenter() {
		return isGreater == null;
	}

	public Location match() {
		return match;
	}

	public Location clockwise() {
		return clockwiseNext;
	}

	public Location counterClockwise() {
		return clockwiseNext.match();
	}

	/**
	 * Assumes "this" is a major axis, and tells whether the minor axis argument is valid for
	 * the major value.  Cannot have both major and minor be the same horizontal/vertical bearing.
	 * Note that {@link #CENTER} can be horizontal or vertical, so this method should not count
	 * this value as a bad minor value, as it also represents a good value.
	 * @param minor the minor value to check
	 * @return true if valid.
	 */
	public boolean validMinor(Location minor) {
		return isHorizontal() && minor.isVertical() || isVertical() && minor.isHorizontal();
	}

	public boolean isHorizontal() {
		return isHorizontal == null || isHorizontal;
	}

	public boolean isVertical() {
		return isHorizontal == null || !isHorizontal;
	}
}
