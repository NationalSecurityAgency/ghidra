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
 * Class for reporting the min/max columns in a row or the min/max rows in a column
 */
public class GridRange {
	public int min;
	public int max;

	public GridRange() {
		this(Integer.MAX_VALUE, Integer.MIN_VALUE);
	}

	public GridRange(int min, int max) {
		this.min = min;
		this.max = max;
	}

	public void add(int value) {
		min = Math.min(value, min);
		max = Math.max(value, max);
	}

	@Override
	public String toString() {
		return "[" + min + " -> " + max + "]";
	}

	public boolean isEmpty() {
		return min > max;
	}

	public boolean contains(int value) {
		return value >= min && value <= max;
	}

	@Override
	public int hashCode() {
		return Objects.hash(max, min);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		GridRange other = (GridRange) obj;
		return max == other.max && min == other.min;
	}

	public int width() {
		if (isEmpty()) {
			return 0;
		}
		return max - min + 1;
	}

}
