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

import org.apache.commons.collections4.map.LazyMap;

/**
 * Maintains a collection of RowSegments for the same grid row. 
 *
 * @param <E> edge type
 */
public class RowSegmentList<E> {
	protected List<RowSegment<E>> edgeSegments = new ArrayList<>();
	int row;

	public RowSegmentList(int row) {
		this.row = row;
	}

	protected void addSegment(RowSegment<E> segment) {
		edgeSegments.add(segment);
	}

	@Override
	public String toString() {
		return edgeSegments.toString();
	}

	public int getRow() {
		return row;
	}

	/**
	 * Returns the minimum offset of any edges in this segment list.
	 * @return the minimum offset of any edges in this segment list
	 */
	public int getMinOffset() {
		int minOffset = 0;
		for (EdgeSegment<E> edgeSegment : edgeSegments) {
			minOffset = Math.min(minOffset, edgeSegment.getOffset());
		}
		return minOffset;
	}

	/**
	 * Returns the maximum offset of any edges in this segment list.
	 * @return the maximum offset of any edges in this segment list
	 */
	public int getMaxOffset() {
		int maxOffset = 0;
		for (EdgeSegment<E> edgeSegment : edgeSegments) {
			maxOffset = Math.max(maxOffset, edgeSegment.getOffset());
		}
		return maxOffset;
	}

	/**
	 * Assigns offsets for overlapping row segments. Parallel overlapping edges must be offset
	 * from each other when assigned to layout space to avoid drawing over each other. Each
	 * edge offset represents 1/2 the edge spacing distance. The reason offsets are assigned 2
	 * apart from each other is to be consistent with column segment offsets which must be 2 apart
	 * so that even numbers of edges can be centered on the grid line.
	 */
	public void assignOffsets() {
		// sorts the row edge segments from top to bottom
		sort();

		Map<Integer, RowSegmentList<E>> offsetMap =
			LazyMap.lazyMap(new HashMap<>(), k -> new RowSegmentList<E>(0));
		for (int i = 0; i < edgeSegments.size(); i++) {
			RowSegment<E> segment = edgeSegments.get(i);
			assignOffset(offsetMap, segment);
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
		boolean firstSegmentIsFlowingLeft = edgeSegments.get(0).isFlowingLeft();
		for (RowSegment<E> rowSegment : edgeSegments) {
			if (rowSegment.isFlowingLeft() != firstSegmentIsFlowingLeft) {
				return false;
			}
		}
		return true;
	}

	protected void assignOffset(Map<Integer, RowSegmentList<E>> offsetMap, RowSegment<E> segment) {

		// assigning offsets to rows is easy, just find the first offset group that we don't
		// overlap with.

		int offset = 0;
		RowSegmentList<E> segments = offsetMap.get(offset);

		while (segments.hasOverlappingSegment(segment)) {
			offset += 2;
			segments = offsetMap.get(offset);
		}
		segment.setOffset(offset);
		segments.addSegment(segment);
	}

	private boolean hasOverlappingSegment(RowSegment<E> segment) {
		for (RowSegment<E> edgeSegment : edgeSegments) {
			if (segment.overlaps(edgeSegment)) {
				return true;
			}
		}
		return false;
	}

}
