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
package ghidra.util.database.spatial.rect;

import ghidra.util.database.spatial.AbstractConstraintsTreeSpatialMap;

/**
 * Specifies which element of a query is returned by
 * {@link AbstractConstraintsTreeSpatialMap#firstEntry()} and the like.
 */
public enum Rectangle2DDirection {
	/**
	 * Start with element having the least x1 value
	 */
	LEFTMOST(false),
	/**
	 * Start with element having the greatest x2 value
	 */
	RIGHTMOST(true),
	/**
	 * Start with element having the least y1 value
	 */
	BOTTOMMOST(false),
	/**
	 * Start with element having the greatest y2 value
	 */
	TOPMOST(true);

	private final boolean reversed;

	/**
	 * Constructor
	 * 
	 * @param reversed true if elements are sorted greatest first
	 */
	private Rectangle2DDirection(boolean reversed) {
		this.reversed = reversed;
	}

	/**
	 * Check if the direction implies the greatest elements come first
	 * 
	 * Implementors may find this useful for querying internal indices properly.
	 * 
	 * @return true if reversed
	 */
	public boolean isReversed() {
		return reversed;
	}
}
