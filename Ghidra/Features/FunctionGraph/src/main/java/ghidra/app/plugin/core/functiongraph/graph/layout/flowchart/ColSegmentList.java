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
package ghidra.app.plugin.core.functiongraph.graph.layout.flowchart;

import java.util.*;

import ghidra.graph.viewer.layout.GridPoint;

/**
 * Maintains a collection of ColumnSegments for the same grid column. 
 *
 * @param <E> edge type
 */
public class ColSegmentList<E> {
	private List<ColumnSegment<E>> edgeSegments = new ArrayList<>();
	private int col;
	private long minY = Integer.MAX_VALUE;
	private long maxY = Integer.MIN_VALUE;

	public ColSegmentList(int col) {
		this.col = col;
	}

	public int getCol() {
		return col;
	}

	public ColSegmentList(ColumnSegment<E> segment) {
		super();
		addSegment(segment);
		this.col = 0;
	}

	/**
	 * Assigns offsets for overlapping column segments. Parallel overlapping edges must be offset
	 * from each other when assigned to layout space to avoid drawing over each other. Each
	 * edge offset represents 1/2 the edge spacing distance. The reason offsets are assigned 2
	 * apart from each other is so that even numbers of columns can be centered. So for example,
	 * a column with 3 parallel edges are assigned offsets of -2,0,2, but 4 edges would be assigned
	 * -3,-1, 1, 3. (offset in each direction by 1/2 of an edge spacing)
	 */
	public void assignOffsets() {
		// First partition the column segments into non-overlapping groups. Since column segments
		// may attach to vertices, it is easier to center them on the vertices if not trying to
		// consider all the segments in a column at the same time.
		List<ColSegmentList<E>> groups = sortIntoNonOverlappingGroups(edgeSegments);
		for (ColSegmentList<E> group : groups) {
			assignOffsets(group);
		}
	}

	/**
	 * Checks if the the range of y values in a given column segment list intersects the
	 * range of y values in this column segment.
	 * @param other the column segment list to compare
	 * @return true if they intersect ranges.
	 */
	boolean intersects(ColSegmentList<E> other) {
		if (minY > other.maxY) {
			return false;
		}
		if (other.minY > maxY) {
			return false;
		}
		return true;
	}

	ColumnSegment<E> getSegment(E edge, GridPoint startPoint) {
		for (ColumnSegment<E> edgeSegment : edgeSegments) {
			if (edgeSegment.edge.equals(edge) && edgeSegment.startsAt(startPoint)) {
				return edgeSegment;
			}
		}
		return null;
	}

	@Override
	public String toString() {
		return edgeSegments.toString();
	}

	int getMinOffset() {
		int minOffset = 0;
		for (EdgeSegment<E> edgeSegment : edgeSegments) {
			minOffset = Math.min(minOffset, edgeSegment.getOffset());
		}
		return minOffset;
	}

	int getMaxOffset() {
		int maxOffset = 0;
		for (EdgeSegment<E> edgeSegment : edgeSegments) {
			maxOffset = Math.max(maxOffset, edgeSegment.getOffset());
		}
		return maxOffset;
	}

	void addSegment(ColumnSegment<E> segment) {
		edgeSegments.add(segment);
		minY = Math.min(minY, segment.getVirtualMinY());
		maxY = Math.max(maxY, segment.getVirtualMaxY());
	}

	private void assignOffsets(ColSegmentList<E> group) {
		// First sort the column segments in a left to right ordering.
		group.sort();

		// Column segments are extend both to the right and left of the grid line, so first
		// find a starting edge to assign to 0 and then work in both directions giving offsets
		// to columns to avoid overlaps.

		// see if there is a natural center line (from a vertex to vertex in one straight line)
		int naturalCenter = findNaturalCenter(group);
		int centerIndex = naturalCenter >= 0 ? naturalCenter : group.edgeSegments.size() / 2;
		assignOffsets(group, centerIndex);

		// if used an arbitrary center index, our edges might not be centered around
		// the grid line, so adjust the offsets so the are.
		if (naturalCenter < 0) {
			int bias = group.getMaxOffset() + group.getMinOffset();
			int adjustment = -bias / 2;
			for (EdgeSegment<E> segment : group.edgeSegments) {
				segment.setOffset(segment.getOffset() + adjustment);
			}
		}
	}

	private void sort() {
		if (isUniformFlow()) {
			Collections.sort(edgeSegments, (s1, s2) -> s1.compareToUsingFlows(s2));
		}
		else {
			Collections.sort(edgeSegments, (s1, s2) -> s1.compareToIgnoreFlows(s2));
		}
	}

	private boolean isUniformFlow() {
		if (edgeSegments.isEmpty()) {
			return true;
		}
		boolean firstSegmentIsUpwardFlowing = edgeSegments.get(0).isFlowingUpwards();
		for (ColumnSegment<E> columnSegment : edgeSegments) {
			if (columnSegment.isFlowingUpwards() != firstSegmentIsUpwardFlowing) {
				return false;
			}
		}
		return true;
	}

	private void assignOffsets(ColSegmentList<E> group, int center) {
		List<ColSegmentList<E>> nonOverlappingSegments = new ArrayList<>();

		// assign negative offsets to column segments to the left of the center segment.
		for (int i = center; i >= 0; i--) {
			ColumnSegment<E> segment = group.edgeSegments.get(i);
			assignOffsets(nonOverlappingSegments, segment, -2); // 2 to keep edges two offsets apart
		}

		// remove all the previous results except for the columm as we still need to check
		// for overlap against columns that have been assigned offset 0
		for (int i = nonOverlappingSegments.size() - 1; i > 0; i--) {
			nonOverlappingSegments.remove(i);
		}

		// assign positive offsets to column segments to the right of the center segment.
		for (int i = center + 1; i < group.edgeSegments.size(); i++) {
			ColumnSegment<E> segment = group.edgeSegments.get(i);
			assignOffsets(nonOverlappingSegments, segment, 2); // 2 to keep edges two offsets apart
		}
	}

	private void assignOffsets(List<ColSegmentList<E>> nonOverlappingSegments,
			ColumnSegment<E> segment, int stepSize) {

		// Find lowest offset group that the given segment can be added without an overlap.
		// Start looking at the group with highest offsets first and work towards the 0 
		// offset group to ensure that overlapping segments don't lose the ordering that
		// has already been establish. In other words, for a segment to be allowed to be
		// given a 0 offset (because it doesn't overlap any segments in that group), it must
		// also not overlap any existing groups with higher offsets. (Otherwise the ordering
		// we created to minimize edge crossings will be lost)

		int i = nonOverlappingSegments.size() - 1;
		for (; i >= 0; i--) {
			if (nonOverlappingSegments.get(i).hasOverlappingSegment(segment)) {
				break;
			}
		}

		// we either broke at a group we overlap or we are at -1. Either way, we get added
		// to the next offset group.
		i++;
		if (i >= nonOverlappingSegments.size()) {
			nonOverlappingSegments.add(new ColSegmentList<E>(i));
		}
		// if adjusting to the left, offsets are negative
		int offset = i * stepSize;
		segment.setOffset(offset);
		nonOverlappingSegments.get(i).addSegment(segment);
	}

	private boolean hasOverlappingSegment(ColumnSegment<E> segment) {
		for (ColumnSegment<E> edgeSegment : edgeSegments) {
			if (segment.overlaps(edgeSegment)) {
				return true;
			}
		}
		return false;

	}

	private int findNaturalCenter(ColSegmentList<E> group) {
		for (int i = 0; i < group.edgeSegments.size(); i++) {
			ColumnSegment<E> edgeSegment = group.edgeSegments.get(i);
			if (edgeSegment.points.size() == 2) {
				return i;
			}
		}
		return -1;
	}

	private List<ColSegmentList<E>> sortIntoNonOverlappingGroups(List<ColumnSegment<E>> segments) {
		List<ColSegmentList<E>> groups = new ArrayList<>(segments.size());
		for (ColumnSegment<E> segment : segments) {
			groupSegment(groups, segment);
		}
		return groups;
	}

	private void groupSegment(List<ColSegmentList<E>> groups, ColumnSegment<E> segment) {
		ColSegmentList<E> newGroup = new ColSegmentList<E>(segment);
		for (int i = groups.size() - 1; i >= 0; i--) {
			if (newGroup.intersects(groups.get(i))) {
				newGroup.merge(groups.get(i));
				groups.remove(i);
			}
		}
		groups.add(newGroup);
	}

	private void merge(ColSegmentList<E> segmentList) {
		edgeSegments.addAll(segmentList.edgeSegments);
		minY = Math.min(minY, segmentList.minY);
		maxY = Math.max(maxY, segmentList.maxY);
	}

}
