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
package functioncalls.graph;

import static functioncalls.graph.FcgDirection.IN_AND_OUT;
import static functioncalls.graph.FcgDirection.OUT;

/**
 * A container class that represents a {@link FunctionCallGraph} level, or row.   A level 
 * is both the row of the vertex (the number of hops from the source vertex) and the 
 * direction.
 */
public class FcgLevel implements Comparable<FcgLevel> {

	/** A 1-based  */
	private int row;
	private FcgDirection direction;

	public static FcgLevel sourceLevel() {
		return new FcgLevel(0, IN_AND_OUT);
	}

	public FcgLevel(int distance, FcgDirection direction) {
		this.row = toRow(distance);
		this.direction = direction;

		if (row == 0) {
			throw new IllegalArgumentException("The FcgLevel uses a 1-based row system");
		}

		if (row == 1 && direction != IN_AND_OUT) {
			throw new IllegalArgumentException("Row 1 must be FcgDirection.IN_AND_OUT");
		}
	}

	private int toRow(int distance) {
		int oneBased = distance + 1;
		return (direction == OUT) ? -oneBased : oneBased;
	}

	public int getRow() {
		return row;
	}

	public int getDistance() {
		return Math.abs(row) - 1;
	}

	public FcgDirection getDirection() {
		return direction;
	}

	/**
	 * Returns true if this level represents the source level from which all other levels 
	 * emanate, which is row 1.
	 * 
	 * @return true if this level represents the source level
	 */
	public boolean isSource() {
		return direction.isSource();
	}

	/**
	 * Returns the parent level of this level.  The parent of a level has the same direction 
	 * as this level, with a distance of one less than this level.
	 * 
	 * @return returns the parent level of this level
	 * @throws IllegalArgumentException if this is the source level, which is row 1
	 */
	public FcgLevel parent() {
		if (direction == IN_AND_OUT) {
			// undefined--we are the parent of all
			throw new IllegalArgumentException(
				"To get the parent of the source level you must use the constructor directly");
		}

		int newDistance = getDistance() - 1;
		FcgDirection newDirection = direction;
		if (newDistance == 0) {
			newDirection = IN_AND_OUT;
		}
		return new FcgLevel(newDistance, newDirection);
	}

	/**
	 * Returns the child level of this level.  The child of a level has the same direction 
	 * as this level, with a distance of one more than this level.
	 * 
	 * @return returns the child level of this level
	 * @throws IllegalArgumentException if this is the source level, which is row 1
	 */
	public FcgLevel child() {
		if (direction == IN_AND_OUT) {
			// undefined--this node goes in both directions
			throw new IllegalArgumentException(
				"To get the child of the source level you " + "must use the constructor directly");
		}

		return child(direction);
	}

	/**
	 * Returns true if this level is the immediate predecessor of the given other level.
	 * 
	 * <P>The <tt>source</tt> level is the parent of the first level in either direction.
	 * 
	 * @param other the other level that is a potential child level
	 * @return true if this level is the immediate predecessor of the given other level
	 */
	public boolean isParentOf(FcgLevel other) {
		if (isSource()) {
			return other.getDistance() == 1;
		}

		if (direction != other.direction) {
			return false;
		}

		// e.g., row 2 - row 1 = 1
		return other.getDistance() - getDistance() == 1;
	}

	/**
	 * Returns true if this level is the immediate successor of the given other level
	 * 
	 * @param other the other level that is a potential child level
	 * @return true if this level is the immediate successor of the given other level
	 */
	public boolean isChildOf(FcgLevel other) {
		return other.isParentOf(this);
	}

	/**
	 * Returns the child level of this level.  The child of a level has the same direction 
	 * as this level, with a distance of one more than this level.
	 * 
	 * @param the direction of the child
	 * @return returns the child level of this level
	 * @throws IllegalArgumentException if this is the source level, which is row 1
	 */
	public FcgLevel child(FcgDirection newDirection) {
		if (newDirection == IN_AND_OUT) {
			// undefined--IN_AND_OUT goes in both directions
			throw new IllegalArgumentException("Direction cannot be IN_AND_OUT");
		}

		int newDistance = getDistance() + 1;
		return new FcgLevel(newDistance, newDirection);
	}

	@Override
	public String toString() {
		return direction + " - row " + Integer.toString(getRelativeRow());
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((direction == null) ? 0 : direction.hashCode());
		result = prime * result + row;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}

		FcgLevel other = (FcgLevel) obj;
		if (direction != other.direction) {
			return false;
		}
		if (row != other.row) {
			return false;
		}
		return true;
	}

	/**
	 * Returns the row of this vertex 
	 * @return the row of this vertex 
	 */
	private int getRelativeRow() {
		return direction == OUT ? -row : row;
	}

	@Override
	public int compareTo(FcgLevel l2) {

		int result = getDirection().compareTo(l2.getDirection());
		if (result != 0) {
			return result; // compare by direction first In on top; Out on bottom
		}

		// same direction, use row
		return -(getRelativeRow() - l2.getRelativeRow());
	}
}
