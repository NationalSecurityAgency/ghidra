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
package ghidra.graph.viewer.layout;

import java.util.Objects;

/**
 * Row and column information for points in a {@link GridLocationMap}. Using these instead
 * of java Points, makes the code that translates from grid space to layout space much less
 * confusing.
 */
public class GridPoint {

	public int row;
	public int col;

	public GridPoint(int row, int col) {
		this.row = row;
		this.col = col;
	}

	public GridPoint(GridPoint point) {
		this.row = point.row;
		this.col = point.col;
	}

	@Override
	public int hashCode() {
		return Objects.hash(col, row);
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
		GridPoint other = (GridPoint) obj;
		return col == other.col && row == other.row;
	}

	@Override
	public String toString() {
		return "(r=" + row + ",c=" + col + ")";
	}
}
