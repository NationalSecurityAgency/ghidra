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

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Test;

import ghidra.graph.graphs.TestEdge;
import ghidra.graph.graphs.TestVertex;
import ghidra.graph.viewer.layout.GridPoint;

public class EdgeSegmentTest {
	private static int DOWN = 1;
	private static int UP = -1;
	private static int LEFT = -1;
	private static int RIGHT = 1;
	private static int UP_2 = -2;
	private static int DOWN_2 = 2;
	private static int LEFT_2 = -2;
	private static int RIGHT_2 = 2;

	private TestVertex v1 = v(1);
	private TestVertex v2 = v(2);
	private TestVertex v3 = v(3);
	private TestVertex v4 = v(4);
	private TestEdge e12 = e(v1, v2);
	private TestEdge e13 = e(v1, v3);
	private TestEdge e14 = e(v1, v4);
	private TestEdge e23 = e(v2, v3);
	private TestEdge e24 = e(v2, v4);
	private TestEdge e34 = e(v3, v4);

//==================================================================================================
// The following tests compare starting edge segments.
//=================================================================================================
	@Test
	public void testStartSegmentsInTotallyDifferentColumns() {
		ColumnSegment<TestEdge> col1 = segment(e12, p(0, 1), DOWN);
		ColumnSegment<TestEdge> col2 = segment(e13, p(0, 2), DOWN);

		assertLessThan(col1, col2);
		assertGreaterThan(col2, col1);
	}

	@Test
	public void testCompareStartSegmentByDirectionOfBottomRow() {
		GridPoint p = p(0, 0);
		ColumnSegment<TestEdge> down = segment(e12, p, DOWN_2);
		ColumnSegment<TestEdge> left = segment(e13, p, DOWN, LEFT, DOWN);
		ColumnSegment<TestEdge> right = segment(e14, p, DOWN, RIGHT, DOWN);

		assertLessThan(left, down);
		assertGreaterThan(down, left);

		assertLessThan(down, right);
		assertGreaterThan(right, down);

		assertLessThan(left, right);
		assertGreaterThan(right, left);

		// test edges are equals to themselves
		assertEquals(down, down);
		assertEquals(left, left);
		assertEquals(right, right);
	}

	@Test
	public void testCompareStartBothLeftButDifferentRowLevels() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> down1_left = segment(e13, p, DOWN, LEFT, DOWN);
		ColumnSegment<TestEdge> down2_left = segment(e14, p, DOWN_2, LEFT, DOWN);

		assertLessThan(down1_left, down2_left);
		assertGreaterThan(down2_left, down1_left);

	}

	@Test
	public void testCompareStartBothRightButDifferentRowLevels() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> down1_right = segment(e13, p, DOWN, RIGHT, DOWN);
		ColumnSegment<TestEdge> down2_right = segment(e14, p, DOWN_2, RIGHT, DOWN);

		assertLessThan(down2_right, down1_right);
		assertGreaterThan(down1_right, down2_right);

	}

	@Test
	public void testCompareStartBothLeftThenOppositeDirection() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> leftUp = segment(e13, p, DOWN, LEFT, UP);
		ColumnSegment<TestEdge> leftDown = segment(e14, p, DOWN, LEFT, DOWN);

		assertLessThan(leftUp, leftDown);
		assertGreaterThan(leftDown, leftUp);

	}

	@Test
	public void testCompareStartBothRightsThenOppositeDirection() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> rightUp = segment(e13, p, DOWN, RIGHT, UP);
		ColumnSegment<TestEdge> rightDown = segment(e14, p, DOWN, RIGHT, DOWN);

		assertLessThan(rightDown, rightUp);
		assertGreaterThan(rightUp, rightDown);

	}

	@Test
	public void testCompareLeftDownButDifferentLeftColumn() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> left1 = segment(e13, p, DOWN, LEFT, DOWN);
		ColumnSegment<TestEdge> left2 = segment(e14, p, DOWN, LEFT_2, DOWN);

		assertLessThan(left2, left1);
		assertGreaterThan(left1, left2);
	}

	@Test
	public void testCompareLeftUpButDifferentLeftColumn() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> left1 = segment(e13, p, DOWN, LEFT, UP);
		ColumnSegment<TestEdge> left2 = segment(e14, p, DOWN, LEFT_2, UP);

		assertLessThan(left1, left2);
		assertGreaterThan(left2, left1);
	}

	@Test
	public void testCompareRightDownButDifferentRightColumn() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> right1 = segment(e13, p, DOWN, RIGHT, DOWN);
		ColumnSegment<TestEdge> right2 = segment(e14, p, DOWN, RIGHT_2, DOWN);

		assertLessThan(right1, right2);
		assertGreaterThan(right2, right1);
	}

	@Test
	public void testCompareRightUpButDifferentRightColumn() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> right1 = segment(e13, p, DOWN, RIGHT, UP);
		ColumnSegment<TestEdge> right2 = segment(e14, p, DOWN, RIGHT_2, UP);

		assertLessThan(right2, right1);
		assertGreaterThan(right1, right2);
	}

	@Test
	public void testCompareLeftUpButUpperRowDifferentDirections() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> l_u_left = segment(e13, p, DOWN, LEFT, UP, LEFT);
		ColumnSegment<TestEdge> l_u_right = segment(e14, p, DOWN, LEFT, UP, RIGHT);

		assertLessThan(l_u_right, l_u_left);
		assertGreaterThan(l_u_left, l_u_right);
	}

	@Test
	public void testCompareLeftDownButLowerRowDifferentDirections() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> l_d_left = segment(e13, p, DOWN, LEFT, DOWN, LEFT);
		ColumnSegment<TestEdge> l_d_right = segment(e14, p, DOWN, LEFT, DOWN, RIGHT);

		assertLessThan(l_d_left, l_d_right);
		assertGreaterThan(l_d_right, l_d_left);
	}

	@Test
	public void testCompareRightUpButUpperRowDifferentDirections() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> r_u_left = segment(e13, p, DOWN, RIGHT, UP, LEFT);
		ColumnSegment<TestEdge> r_u_right = segment(e14, p, DOWN, RIGHT, UP, RIGHT);

		assertLessThan(r_u_right, r_u_left);
		assertGreaterThan(r_u_left, r_u_right);
	}

	@Test
	public void testCompareRightDownButLowerRowDifferentDirections() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> r_d_left = segment(e13, p, DOWN, RIGHT, DOWN, LEFT);
		ColumnSegment<TestEdge> r_d_right = segment(e14, p, DOWN, RIGHT, DOWN, RIGHT);

		assertLessThan(r_d_left, r_d_right);
		assertGreaterThan(r_d_right, r_d_left);
	}

	@Test
	public void testCompareLeftUpLeftButFinalColDiffers() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> l_u_left = segment(e13, p, DOWN, LEFT, UP, LEFT, DOWN);
		ColumnSegment<TestEdge> l_u_left2 = segment(e14, p, DOWN, LEFT, UP, LEFT_2, DOWN);

		assertLessThan(l_u_left2, l_u_left);
		assertGreaterThan(l_u_left, l_u_left2);
	}

	@Test
	public void testCompareLeftUpRightButFinalColDiffers() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> l_u_right = segment(e13, p, DOWN, LEFT, UP, RIGHT, DOWN);
		ColumnSegment<TestEdge> l_u_right2 = segment(e14, p, DOWN, LEFT, UP, RIGHT_2, DOWN);

		assertLessThan(l_u_right, l_u_right2);
		assertGreaterThan(l_u_right2, l_u_right);
	}

	@Test
	public void testCompareLeftDownLeftButFinalColDiffers() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> l_d_left = segment(e13, p, DOWN, LEFT, DOWN, LEFT, DOWN);
		ColumnSegment<TestEdge> l_d_left2 = segment(e14, p, DOWN, LEFT, DOWN, LEFT_2, DOWN);

		assertLessThan(l_d_left2, l_d_left);
		assertGreaterThan(l_d_left, l_d_left2);
	}

	@Test
	public void testCompareLeftDownRightButFinalColDiffers() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> l_d_right = segment(e13, p, DOWN, LEFT, DOWN, RIGHT, DOWN);
		ColumnSegment<TestEdge> l_d_right2 = segment(e14, p, DOWN, LEFT, DOWN, RIGHT_2, DOWN);

		assertLessThan(l_d_right, l_d_right2);
		assertGreaterThan(l_d_right2, l_d_right);
	}

	@Test
	public void testCompareRightUpLeftButFinalColDiffers() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> r_u_left = segment(e13, p, DOWN, RIGHT, UP, LEFT, DOWN);
		ColumnSegment<TestEdge> r_u_left2 = segment(e14, p, DOWN, RIGHT, UP, LEFT_2, DOWN);

		assertLessThan(r_u_left2, r_u_left);
		assertGreaterThan(r_u_left, r_u_left2);
	}

	@Test
	public void testCompareRightUpRightButFinalColDiffers() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> r_u_right = segment(e13, p, DOWN, RIGHT, UP, RIGHT, DOWN);
		ColumnSegment<TestEdge> r_u_right2 = segment(e14, p, DOWN, RIGHT, UP, RIGHT_2, DOWN);

		assertLessThan(r_u_right, r_u_right2);
		assertGreaterThan(r_u_right2, r_u_right);
	}

	@Test
	public void testCompareRightDownLeftButFinalColDiffers() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> r_d_left = segment(e13, p, DOWN, RIGHT, DOWN, LEFT, DOWN);
		ColumnSegment<TestEdge> r_d_left2 = segment(e14, p, DOWN, RIGHT, DOWN, LEFT_2, DOWN);

		assertLessThan(r_d_left2, r_d_left);
		assertGreaterThan(r_d_left, r_d_left2);
	}

	@Test
	public void testCompareRightDownRightButFinalColDiffers() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> r_d_right = segment(e13, p, DOWN, RIGHT, DOWN, RIGHT, DOWN);
		ColumnSegment<TestEdge> r_d_right2 = segment(e14, p, DOWN, RIGHT, DOWN, RIGHT_2, DOWN);

		assertLessThan(r_d_right, r_d_right2);
		assertGreaterThan(r_d_right2, r_d_right);
	}

//==================================================================================================
// The following tests compare ending edge segments.
//=================================================================================================

	@Test
	public void testCompareEndsInTotallyDifferentColumns() {
		GridPoint p1 = p(0, 0);
		GridPoint p2 = p(0, 1);

		ColumnSegment<TestEdge> col0 = endSegment(e12, p1, UP_2);
		ColumnSegment<TestEdge> col1 = endSegment(e12, p2, UP_2);
		assertLessThan(col0, col1);
		assertGreaterThan(col1, col0);
	}

	@Test
	public void testCompareEndsFromDifferentDirections() {
		GridPoint p = p(5, 5);

		ColumnSegment<TestEdge> fromRight = endSegment(e14, p, UP, RIGHT, UP);
		ColumnSegment<TestEdge> fromAbove = endSegment(e24, p, UP);
		ColumnSegment<TestEdge> fromLeft = endSegment(e34, p, UP, LEFT, UP);

		assertLessThan(fromLeft, fromAbove);
		assertLessThan(fromAbove, fromRight);
		assertLessThan(fromLeft, fromRight);

		assertGreaterThan(fromAbove, fromLeft);
		assertGreaterThan(fromRight, fromAbove);
		assertGreaterThan(fromRight, fromAbove);

	}

	@Test
	public void testCompareEndBothLeftButDifferentRowLevels() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> up1_left = endSegment(e13, p, UP, LEFT, UP);
		ColumnSegment<TestEdge> up2_left = endSegment(e23, p, UP_2, LEFT, UP);

		assertLessThan(up1_left, up2_left);
		assertGreaterThan(up2_left, up1_left);

	}

	@Test
	public void testCompareEndBothRightButDifferentRowLevels() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> up1_right = endSegment(e13, p, UP, RIGHT, UP);
		ColumnSegment<TestEdge> up2_right = endSegment(e23, p, UP_2, RIGHT, UP);

		assertLessThan(up2_right, up1_right);
		assertGreaterThan(up1_right, up2_right);

	}

	@Test
	public void testCompareEndBothLeftThenOppositeDirection() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> u_l_up = endSegment(e13, p, UP, LEFT, UP);
		ColumnSegment<TestEdge> u_l_down = endSegment(e14, p, UP, LEFT, DOWN);

		assertLessThan(u_l_down, u_l_up);
		assertGreaterThan(u_l_up, u_l_down);

	}

	@Test
	public void testCompareEndBothRightsThenOppositeDirection() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> u_r_up = endSegment(e13, p, UP, RIGHT, UP);
		ColumnSegment<TestEdge> u_r_down = endSegment(e14, p, UP, RIGHT, DOWN);

		assertLessThan(u_r_up, u_r_down);
		assertGreaterThan(u_r_down, u_r_up);

	}

	@Test
	public void testCompareEndsLeftDownButDifferentLeftColumn() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> left1 = endSegment(e13, p, UP, LEFT, DOWN);
		ColumnSegment<TestEdge> left2 = endSegment(e14, p, UP, LEFT_2, DOWN);

		assertLessThan(left1, left2);
		assertGreaterThan(left2, left1);
	}

	@Test
	public void testCompareEndsLeftUpButDifferentLeftColumn() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> left1 = endSegment(e13, p, UP, LEFT, UP);
		ColumnSegment<TestEdge> left2 = endSegment(e14, p, UP, LEFT_2, UP);

		assertLessThan(left2, left1);
		assertGreaterThan(left1, left2);
	}

	@Test
	public void testCompareEndsRightDownButDifferentRightColumn() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> right1 = endSegment(e13, p, UP, RIGHT, DOWN);
		ColumnSegment<TestEdge> right2 = endSegment(e14, p, UP, RIGHT_2, DOWN);

		assertLessThan(right2, right1);
		assertGreaterThan(right1, right2);
	}

	@Test
	public void testCompareEndsRightUpButDifferentRightColumn() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> right1 = endSegment(e13, p, UP, RIGHT, UP);
		ColumnSegment<TestEdge> right2 = endSegment(e14, p, UP, RIGHT_2, UP);

		assertLessThan(right1, right2);
		assertGreaterThan(right2, right1);
	}

	@Test
	public void testCompareEndsLeftUpButUpperRowDifferentDirections() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> l_u_left = endSegment(e13, p, UP, LEFT, UP, LEFT, UP);
		ColumnSegment<TestEdge> l_u_right = endSegment(e14, p, UP, LEFT, UP, RIGHT, UP);

		assertLessThan(l_u_left, l_u_right);
		assertGreaterThan(l_u_right, l_u_left);
	}

	@Test
	public void testCompareEndsLeftDownButLowerRowDifferentDirections() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> l_d_left = endSegment(e13, p, UP, LEFT, DOWN, LEFT, UP);
		ColumnSegment<TestEdge> l_d_right = endSegment(e14, p, UP, LEFT, DOWN, RIGHT, UP);

		assertLessThan(l_d_right, l_d_left);
		assertGreaterThan(l_d_left, l_d_right);
	}

	@Test
	public void testCompareEndsRightUpButUpperRowDifferentDirections() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> r_u_left = endSegment(e13, p, UP, RIGHT, UP, LEFT, UP);
		ColumnSegment<TestEdge> r_u_right = endSegment(e14, p, UP, RIGHT, UP, RIGHT, UP);

		assertLessThan(r_u_left, r_u_right);
		assertGreaterThan(r_u_right, r_u_left);
	}

	@Test
	public void testCompareEndsRightDownButLowerRowDifferentDirections() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> r_d_left = endSegment(e13, p, UP, RIGHT, DOWN, LEFT, UP);
		ColumnSegment<TestEdge> r_d_right = endSegment(e14, p, UP, RIGHT, DOWN, RIGHT, UP);

		assertLessThan(r_d_right, r_d_left);
		assertGreaterThan(r_d_left, r_d_right);
	}

	@Test
	public void testCompareEndsLeftUpLeftButFinalColDiffers() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> l_u_left = endSegment(e13, p, UP, LEFT, UP, LEFT, UP);
		ColumnSegment<TestEdge> l_u_left2 = endSegment(e14, p, UP, LEFT, UP, LEFT_2, UP);

		assertLessThan(l_u_left2, l_u_left);
		assertGreaterThan(l_u_left, l_u_left2);
	}

	@Test
	public void testCompareEndsLeftUpRightButFinalColDiffers() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> l_u_right = endSegment(e13, p, UP, LEFT, UP, RIGHT, UP);
		ColumnSegment<TestEdge> l_u_right2 = endSegment(e14, p, UP, LEFT, UP, RIGHT_2, UP);

		assertLessThan(l_u_right, l_u_right2);
		assertGreaterThan(l_u_right2, l_u_right);
	}

	@Test
	public void testCompareEndsLeftDownLeftButFinalColDiffers() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> l_d_left = endSegment(e13, p, UP, LEFT, DOWN, LEFT, UP);
		ColumnSegment<TestEdge> l_d_left2 = endSegment(e14, p, UP, LEFT, DOWN, LEFT_2, UP);

		assertLessThan(l_d_left2, l_d_left);
		assertGreaterThan(l_d_left, l_d_left2);
	}

	@Test
	public void testCompareEndsLeftDownRightButFinalColDiffers() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> l_d_right = endSegment(e13, p, UP, LEFT, DOWN, RIGHT, UP);
		ColumnSegment<TestEdge> l_d_right2 = endSegment(e14, p, UP, LEFT, DOWN, RIGHT_2, UP);

		assertLessThan(l_d_right, l_d_right2);
		assertGreaterThan(l_d_right2, l_d_right);
	}

	@Test
	public void testCompareEndsRightUpLeftButFinalColDiffers() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> r_u_left = endSegment(e13, p, UP, RIGHT, UP, LEFT, UP);
		ColumnSegment<TestEdge> r_u_left2 = endSegment(e14, p, UP, RIGHT, UP, LEFT_2, UP);

		assertLessThan(r_u_left2, r_u_left);
		assertGreaterThan(r_u_left, r_u_left2);
	}

	@Test
	public void testCompareEndsRightUpRightButFinalColDiffers() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> r_u_right = endSegment(e13, p, UP, RIGHT, UP, RIGHT, UP);
		ColumnSegment<TestEdge> r_u_right2 = endSegment(e14, p, UP, RIGHT, UP, RIGHT_2, UP);

		assertLessThan(r_u_right, r_u_right2);
		assertGreaterThan(r_u_right2, r_u_right);
	}

	@Test
	public void testCompareEndsRightDownLeftButFinalColDiffers() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> r_d_left = endSegment(e13, p, UP, RIGHT, DOWN, LEFT, UP);
		ColumnSegment<TestEdge> r_d_left2 = endSegment(e14, p, UP, RIGHT, DOWN, LEFT_2, UP);

		assertLessThan(r_d_left2, r_d_left);
		assertGreaterThan(r_d_left, r_d_left2);
	}

	@Test
	public void testCompareEndsRightDownRightButFinalColDiffers() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> r_d_right = endSegment(e13, p, UP, RIGHT, DOWN, RIGHT, UP);
		ColumnSegment<TestEdge> r_d_right2 = endSegment(e14, p, UP, RIGHT, DOWN, RIGHT_2, UP);

		assertLessThan(r_d_right, r_d_right2);
		assertGreaterThan(r_d_right2, r_d_right);
	}

//==================================================================================================
// The following tests compare interior edge segments are consistent with each other
//=================================================================================================
	@Test
	public void testInteriorRightDownRight() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> colSeg1 = segment(e13, p, DOWN, RIGHT, DOWN, RIGHT, DOWN);
		ColumnSegment<TestEdge> colSeg2 = segment(e14, p, DOWN, RIGHT, DOWN, RIGHT_2, DOWN);
		assertLessThan(colSeg1, colSeg2);
		assertGreaterThan(colSeg2, colSeg1);

		RowSegment<TestEdge> rowSeg1 = colSeg1.nextSegment();
		RowSegment<TestEdge> rowSeg2 = colSeg2.nextSegment();
		assertLessThan(rowSeg2, rowSeg1);
		assertGreaterThan(rowSeg1, rowSeg2);

		colSeg1 = rowSeg1.nextSegment();
		colSeg2 = rowSeg2.nextSegment();
		assertLessThan(colSeg1, colSeg2);
		assertGreaterThan(colSeg2, colSeg1);

		rowSeg1 = colSeg1.nextSegment();
		rowSeg2 = colSeg2.nextSegment();
		assertLessThan(rowSeg2, rowSeg1);
		assertGreaterThan(rowSeg1, rowSeg2);

		colSeg1 = rowSeg1.nextSegment();
		colSeg2 = rowSeg2.nextSegment();
		assertLessThan(colSeg1, colSeg2);
		assertGreaterThan(colSeg2, colSeg1);
	}

	@Test
	public void testInteriorRightDownLeft() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> colSeg1 = segment(e13, p, DOWN, RIGHT, DOWN, LEFT_2, DOWN);
		ColumnSegment<TestEdge> colSeg2 = segment(e14, p, DOWN, RIGHT, DOWN, LEFT, DOWN);
		assertLessThan(colSeg1, colSeg2);
		assertGreaterThan(colSeg2, colSeg1);

		RowSegment<TestEdge> rowSeg1 = colSeg1.nextSegment();
		RowSegment<TestEdge> rowSeg2 = colSeg2.nextSegment();
		assertLessThan(rowSeg2, rowSeg1);
		assertGreaterThan(rowSeg1, rowSeg2);

		colSeg1 = rowSeg1.nextSegment();
		colSeg2 = rowSeg2.nextSegment();
		assertLessThan(colSeg1, colSeg2);
		assertGreaterThan(colSeg2, colSeg1);

		rowSeg1 = colSeg1.nextSegment();
		rowSeg2 = colSeg2.nextSegment();
		assertLessThan(rowSeg1, rowSeg2);
		assertGreaterThan(rowSeg2, rowSeg1);

		colSeg1 = rowSeg1.nextSegment();
		colSeg2 = rowSeg2.nextSegment();
		assertLessThan(colSeg1, colSeg2);
		assertGreaterThan(colSeg2, colSeg1);
	}

	@Test
	public void testInteriorRightUpRight() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> colSeg1 = segment(e13, p, DOWN, RIGHT, UP, RIGHT, DOWN);
		ColumnSegment<TestEdge> colSeg2 = segment(e14, p, DOWN, RIGHT, UP, RIGHT_2, DOWN);
		assertLessThan(colSeg1, colSeg2);
		assertGreaterThan(colSeg2, colSeg1);

		RowSegment<TestEdge> rowSeg1 = colSeg1.nextSegment();
		RowSegment<TestEdge> rowSeg2 = colSeg2.nextSegment();
		assertLessThan(rowSeg2, rowSeg1);
		assertGreaterThan(rowSeg1, rowSeg2);

		colSeg1 = rowSeg1.nextSegment();
		colSeg2 = rowSeg2.nextSegment();
		assertLessThan(colSeg2, colSeg1);
		assertGreaterThan(colSeg1, colSeg2);

		rowSeg1 = colSeg1.nextSegment();
		rowSeg2 = colSeg2.nextSegment();
		assertLessThan(rowSeg2, rowSeg1);
		assertGreaterThan(rowSeg1, rowSeg2);

		colSeg1 = rowSeg1.nextSegment();
		colSeg2 = rowSeg2.nextSegment();
		assertLessThan(colSeg1, colSeg2);
		assertGreaterThan(colSeg2, colSeg1);
	}

	@Test
	public void testInteriorRightUpLeft() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> colSeg1 = segment(e13, p, DOWN, RIGHT, UP, LEFT_2, DOWN);
		ColumnSegment<TestEdge> colSeg2 = segment(e14, p, DOWN, RIGHT, UP, LEFT, DOWN);
		assertLessThan(colSeg1, colSeg2);
		assertGreaterThan(colSeg2, colSeg1);

		RowSegment<TestEdge> rowSeg1 = colSeg1.nextSegment();
		RowSegment<TestEdge> rowSeg2 = colSeg2.nextSegment();
		assertLessThan(rowSeg2, rowSeg1);
		assertGreaterThan(rowSeg1, rowSeg2);

		colSeg1 = rowSeg1.nextSegment();
		colSeg2 = rowSeg2.nextSegment();
		assertLessThan(colSeg2, colSeg1);
		assertGreaterThan(colSeg1, colSeg2);

		rowSeg1 = colSeg1.nextSegment();
		rowSeg2 = colSeg2.nextSegment();
		assertLessThan(rowSeg1, rowSeg2);
		assertGreaterThan(rowSeg2, rowSeg1);

		colSeg1 = rowSeg1.nextSegment();
		colSeg2 = rowSeg2.nextSegment();
		assertLessThan(colSeg1, colSeg2);
		assertGreaterThan(colSeg2, colSeg1);
	}

	@Test
	public void testInteriorLeftDownRight() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> colSeg1 = segment(e13, p, DOWN, LEFT, DOWN, RIGHT, DOWN);
		ColumnSegment<TestEdge> colSeg2 = segment(e14, p, DOWN, LEFT, DOWN, RIGHT_2, DOWN);
		assertLessThan(colSeg1, colSeg2);
		assertGreaterThan(colSeg2, colSeg1);

		RowSegment<TestEdge> rowSeg1 = colSeg1.nextSegment();
		RowSegment<TestEdge> rowSeg2 = colSeg2.nextSegment();
		assertLessThan(rowSeg1, rowSeg2);
		assertGreaterThan(rowSeg2, rowSeg1);

		colSeg1 = rowSeg1.nextSegment();
		colSeg2 = rowSeg2.nextSegment();
		assertLessThan(colSeg1, colSeg2);
		assertGreaterThan(colSeg2, colSeg1);

		rowSeg1 = colSeg1.nextSegment();
		rowSeg2 = colSeg2.nextSegment();
		assertLessThan(rowSeg2, rowSeg1);
		assertGreaterThan(rowSeg1, rowSeg2);

		colSeg1 = rowSeg1.nextSegment();
		colSeg2 = rowSeg2.nextSegment();
		assertLessThan(colSeg1, colSeg2);
		assertGreaterThan(colSeg2, colSeg1);
	}

	@Test
	public void testInteriorLeftDownLeft() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> colSeg1 = segment(e13, p, DOWN, LEFT, DOWN, LEFT_2, DOWN);
		ColumnSegment<TestEdge> colSeg2 = segment(e14, p, DOWN, LEFT, DOWN, LEFT, DOWN);
		assertLessThan(colSeg1, colSeg2);
		assertGreaterThan(colSeg2, colSeg1);

		RowSegment<TestEdge> rowSeg1 = colSeg1.nextSegment();
		RowSegment<TestEdge> rowSeg2 = colSeg2.nextSegment();
		assertLessThan(rowSeg1, rowSeg2);
		assertGreaterThan(rowSeg2, rowSeg1);

		colSeg1 = rowSeg1.nextSegment();
		colSeg2 = rowSeg2.nextSegment();
		assertLessThan(colSeg1, colSeg2);
		assertGreaterThan(colSeg2, colSeg1);

		rowSeg1 = colSeg1.nextSegment();
		rowSeg2 = colSeg2.nextSegment();
		assertLessThan(rowSeg1, rowSeg2);
		assertGreaterThan(rowSeg2, rowSeg1);

		colSeg1 = rowSeg1.nextSegment();
		colSeg2 = rowSeg2.nextSegment();
		assertLessThan(colSeg1, colSeg2);
		assertGreaterThan(colSeg2, colSeg1);
	}

	@Test
	public void testInteriorLeftUpRight() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> colSeg1 = segment(e13, p, DOWN, LEFT, UP, RIGHT, DOWN);
		ColumnSegment<TestEdge> colSeg2 = segment(e14, p, DOWN, LEFT, UP, RIGHT_2, DOWN);
		assertLessThan(colSeg1, colSeg2);
		assertGreaterThan(colSeg2, colSeg1);

		RowSegment<TestEdge> rowSeg1 = colSeg1.nextSegment();
		RowSegment<TestEdge> rowSeg2 = colSeg2.nextSegment();
		assertLessThan(rowSeg1, rowSeg2);
		assertGreaterThan(rowSeg2, rowSeg1);

		colSeg1 = rowSeg1.nextSegment();
		colSeg2 = rowSeg2.nextSegment();
		assertLessThan(colSeg2, colSeg1);
		assertGreaterThan(colSeg1, colSeg2);

		rowSeg1 = colSeg1.nextSegment();
		rowSeg2 = colSeg2.nextSegment();
		assertLessThan(rowSeg2, rowSeg1);
		assertGreaterThan(rowSeg1, rowSeg2);

		colSeg1 = rowSeg1.nextSegment();
		colSeg2 = rowSeg2.nextSegment();
		assertLessThan(colSeg1, colSeg2);
		assertGreaterThan(colSeg2, colSeg1);
	}

	@Test
	public void testInteriorLeftUpLeft() {
		GridPoint p = p(0, 0);

		ColumnSegment<TestEdge> colSeg1 = segment(e13, p, DOWN, LEFT, UP, LEFT_2, DOWN);
		ColumnSegment<TestEdge> colSeg2 = segment(e14, p, DOWN, LEFT, UP, LEFT, DOWN);
		assertLessThan(colSeg1, colSeg2);
		assertGreaterThan(colSeg2, colSeg1);

		RowSegment<TestEdge> rowSeg1 = colSeg1.nextSegment();
		RowSegment<TestEdge> rowSeg2 = colSeg2.nextSegment();
		assertLessThan(rowSeg1, rowSeg2);
		assertGreaterThan(rowSeg2, rowSeg1);

		colSeg1 = rowSeg1.nextSegment();
		colSeg2 = rowSeg2.nextSegment();
		assertLessThan(colSeg2, colSeg1);
		assertGreaterThan(colSeg1, colSeg2);

		rowSeg1 = colSeg1.nextSegment();
		rowSeg2 = colSeg2.nextSegment();
		assertLessThan(rowSeg1, rowSeg2);
		assertGreaterThan(rowSeg2, rowSeg1);

		colSeg1 = rowSeg1.nextSegment();
		colSeg2 = rowSeg2.nextSegment();
		assertLessThan(colSeg1, colSeg2);
		assertGreaterThan(colSeg2, colSeg1);
	}

//==================================================================================================
// The following tests are for miscellaneous methods in ColumnSegment or RowSegment
//=================================================================================================
	@Test
	public void testColumnSegmentOverlapColumn1TotallyAboveColumn2() {
		ColumnSegment<TestEdge> colSeg1 = segment(e13, p(0, 0), DOWN);
		ColumnSegment<TestEdge> colSeg2 = segment(e14, p(100, 0), DOWN);
		assertFalse(colSeg1.overlaps(colSeg2));
		assertFalse(colSeg2.overlaps(colSeg1));
	}

	@Test
	public void testColumnSegmentEndDoesNotOverlapColumnSegmentStartToSameVertex() {
		ColumnSegment<TestEdge> colSeg1 = segment(e13, p(0, 0), DOWN);
		ColumnSegment<TestEdge> colSeg2 = segment(e14, p(2, 0), DOWN);
		assertFalse(colSeg1.overlaps(colSeg2));
	}

	@Test
	public void testColumnStartSegmentToSharedRowFromEndSegmentDependsOnRowOffsets() {
		ColumnSegment<TestEdge> colSeg1 = segment(e13, p(0, 1), DOWN, RIGHT, DOWN);
		ColumnSegment<TestEdge> colSeg2 = segment(e14, p(0, 0), DOWN, RIGHT, DOWN);
		assertTrue(colSeg1.overlaps(colSeg2.last()));

		// now fix offset for secondRow to be down a bit
		colSeg2.nextSegment().setOffset(1);
		assertFalse(colSeg1.overlaps(colSeg2.last()));
	}

	@Test
	public void testRowSegmentOverlapSeg1TotallyBeforeSeg2() {
		ColumnSegment<TestEdge> colSeg1 = segment(e13, p(0, 0), DOWN, RIGHT, DOWN);
		ColumnSegment<TestEdge> colSeg2 = segment(e14, p(0, 10), DOWN, RIGHT, DOWN);
		assertFalse(colSeg1.nextSegment().overlaps(colSeg2.nextSegment()));
		assertFalse(colSeg2.nextSegment().overlaps(colSeg1.nextSegment()));
	}

	@Test
	public void testRowsLeavingSameVertexInOppositeDirectionsDontOverlap() {
		ColumnSegment<TestEdge> colSeg1 = segment(e13, p(0, 0), DOWN, LEFT, DOWN);
		ColumnSegment<TestEdge> colSeg2 = segment(e14, p(0, 0), DOWN, RIGHT, DOWN);
		assertFalse(colSeg1.nextSegment().overlaps(colSeg2.nextSegment()));
		assertFalse(colSeg2.nextSegment().overlaps(colSeg1.nextSegment()));
	}

	@Test
	public void testRowsLeavingSameVertexInSameDirectionOverlap() {
		ColumnSegment<TestEdge> colSeg1 = segment(e13, p(0, 0), DOWN, LEFT, DOWN);
		ColumnSegment<TestEdge> colSeg2 = segment(e14, p(0, 0), DOWN, LEFT, DOWN);
		assertTrue(colSeg1.nextSegment().overlaps(colSeg2.nextSegment()));
		assertTrue(colSeg2.nextSegment().overlaps(colSeg1.nextSegment()));
	}

	@Test
	public void testRowsEnteringSameVertexInOppositeDirectionsDontOverlap() {
		ColumnSegment<TestEdge> colSeg1 = segment(e13, p(0, 0), DOWN, RIGHT, DOWN);
		ColumnSegment<TestEdge> colSeg2 = segment(e14, p(0, 2), DOWN, LEFT, DOWN);
		assertFalse(colSeg1.nextSegment().overlaps(colSeg2.nextSegment()));
		assertFalse(colSeg2.nextSegment().overlaps(colSeg1.nextSegment()));
	}

	@Test
	public void testRowsEnteringSameVertexInSameDirectionsOverlap() {
		ColumnSegment<TestEdge> colSeg1 = segment(e13, p(0, 0), DOWN, RIGHT_2, DOWN);
		ColumnSegment<TestEdge> colSeg2 = segment(e14, p(0, 1), DOWN, RIGHT, DOWN);
		assertTrue(colSeg1.nextSegment().overlaps(colSeg2.nextSegment()));
		assertTrue(colSeg2.nextSegment().overlaps(colSeg1.nextSegment()));
	}

	@Test
	public void testRowsThatStartEndOnSameColumnAndOneIsTerminalAndOtherIsnt() {
		ColumnSegment<TestEdge> colSeg1 = segment(e13, p(0, 0), DOWN, RIGHT, DOWN, RIGHT, DOWN);
		ColumnSegment<TestEdge> colSeg2 = segment(e14, p(0, 1), DOWN, RIGHT, DOWN);
		assertTrue(colSeg1.nextSegment().overlaps(colSeg2.nextSegment()));
		assertTrue(colSeg2.nextSegment().overlaps(colSeg1.nextSegment()));

	}

	@Test
	public void testRowsThatStartEndOnSameColumnAndOneIsTerminalAndOtherIsntLeft() {
		ColumnSegment<TestEdge> colSeg1 = segment(e13, p(0, 1), DOWN, LEFT, DOWN, LEFT, DOWN);
		ColumnSegment<TestEdge> colSeg2 = segment(e14, p(0, 0), DOWN, LEFT, DOWN);
		assertTrue(colSeg1.nextSegment().overlaps(colSeg2.nextSegment()));
		assertTrue(colSeg2.nextSegment().overlaps(colSeg1.nextSegment()));

	}

	private void assertLessThan(ColumnSegment<TestEdge> s1, ColumnSegment<TestEdge> s2) {
		boolean sameFlow = s1.isFlowingUpwards() == s1.isFlowingUpwards();
		int result = sameFlow ? s1.compareToUsingFlows(s2) : s1.compareToIgnoreFlows(s2);
		if (result >= 0) {
			fail("Expected comparsion to be less than, but compareTo was " + result);
		}
	}

	private void assertGreaterThan(RowSegment<TestEdge> s1, RowSegment<TestEdge> s2) {
		boolean sameFlow = s1.isFlowingLeft() == s1.isFlowingLeft();
		int result = sameFlow ? s1.compareToUsingFlows(s2) : s1.compareToIgnoreFlows(s2);
		if (result <= 0) {
			fail("Expected comparsion to be greater than, but compareTo was " + result);
		}
	}

	private void assertLessThan(RowSegment<TestEdge> s1, RowSegment<TestEdge> s2) {
		int result = s1.compareToUsingFlows(s2);
		if (result >= 0) {
			fail("Expected comparsion to be less than, but compareTo was " + result);
		}
	}

	private void assertGreaterThan(ColumnSegment<TestEdge> s1, ColumnSegment<TestEdge> s2) {
		boolean sameFlow = s1.isFlowingUpwards() == s1.isFlowingUpwards();
		int result = sameFlow ? s1.compareToUsingFlows(s2) : s1.compareToIgnoreFlows(s2);
		if (result <= 0) {
			fail("Expected comparsion to be greater than, but compareTo was " + result);
		}
	}

	private ColumnSegment<TestEdge> segment(TestEdge e, GridPoint p, int... flows) {
		return new ColumnSegment<>(e, points(p, flows));
	}

	private ColumnSegment<TestEdge> endSegment(TestEdge e, GridPoint end, int... flows) {
		return new ColumnSegment<>(e, pointsReverseOrder(end, flows)).last();
	}

	private GridPoint p(int row, int col) {
		return new GridPoint(row, col);
	}

	private List<GridPoint> points(GridPoint start, int... flows) {
		List<GridPoint> points = new ArrayList<>();
		points.add(start);
		GridPoint next = new GridPoint(start.row, start.col);
		for (int i = 0; i < flows.length; i++) {
			if (i % 2 == 0) {
				next.row += flows[i];
			}
			else {
				next.col += flows[i];
			}
			points.add(new GridPoint(next.row, next.col));
		}
		return points;
	}

	private List<GridPoint> pointsReverseOrder(GridPoint end, int... flows) {
		List<GridPoint> points = new ArrayList<>();
		points.add(end);
		GridPoint next = new GridPoint(end.row, end.col);
		for (int i = 0; i < flows.length; i++) {
			if (i % 2 == 0) {
				next.row += flows[i];
			}
			else {
				next.col += flows[i];
			}
			points.add(new GridPoint(next.row, next.col));
		}
		Collections.reverse(points);
		return points;
	}

	private TestVertex v(int id) {
		return new TestVertex(Integer.toString(id));
	}

	private TestEdge e(TestVertex vertex1, TestVertex vertex2) {
		return new TestEdge(vertex1, vertex2);
	}

}
