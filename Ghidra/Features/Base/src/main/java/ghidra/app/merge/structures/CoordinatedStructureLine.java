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
package ghidra.app.merge.structures;

import java.util.Objects;

/**
 * Base class for coordinating display lines of a left, right, and merged structure.
 */
public abstract class CoordinatedStructureLine {
	protected ComparisonItem left;
	protected ComparisonItem right;
	protected ComparisonItem merged;
	protected CoordinatedStructureModel model;

	public enum CompareId {
		LEFT, RIGHT, MERGED;
	}

	CoordinatedStructureLine(CoordinatedStructureModel model) {
		this.model = model;
	}

	/**
	 * Returns either the left, right, or merged comparison item for this line.
	 * @param id the id for which comparison item to return
	 * @return either the left, right, or merged comparison item for this line
	 */
	ComparisonItem getComparisonItem(CompareId id) {
		switch (id) {
			case LEFT:
				return left;
			case RIGHT:
				return right;
			case MERGED:
			default:
				return merged;
		}
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
		CoordinatedStructureLine other = (CoordinatedStructureLine) obj;
		return Objects.equals(left, other.left) &&
			Objects.equals(right, other.right) &&
			Objects.equals(merged, other.merged);
	}

	@Override
	public int hashCode() {
		return Objects.hash(left, right, merged);
	}

	protected void modelChanged() {
		model.rebuild();
	}

	protected void error(String errorMessage) {
		model.error(errorMessage);
	}
}
