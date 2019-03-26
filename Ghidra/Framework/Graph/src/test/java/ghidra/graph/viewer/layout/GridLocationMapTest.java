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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.List;

import org.junit.Test;

import ghidra.graph.graphs.TestEdge;
import ghidra.graph.graphs.TestVertex;

public class GridLocationMapTest {

	private GridLocationMap<V, E> locations = new GridLocationMap<>();

	@Test
	public void testGrid() {

		V v1 = new V("1");
		locations.set(v1, 0, 0);
		assertCoordinates(v1, 0, 0);
	}

	@Test
	public void testGrid_ReSet() {

		V v1 = new V("1");
		locations.set(v1, 0, 0);
		locations.set(v1, 1, 1);
		assertCoordinates(v1, 1, 1);
	}

	@Test
	public void testGrid_NegativeValues() {
		V v1 = new V("1");
		V v2 = new V("2");
		locations.set(v1, 0, -1);
		locations.set(v2, -1, 0);
		assertCoordinates(v1, 0, -1);
		assertCoordinates(v2, -1, 0);
	}

	@Test
	public void testGrid_CenterRows_SingleRow() {

		V v1 = new V("1");
		V v2 = new V("2");
		V v3 = new V("3");

		// one row; 3 columns; off center by 1
		locations.set(v1, 0, 1);
		locations.set(v2, 0, 2);
		locations.set(v3, 0, 3);

		locations.centerRows();

		assertCoordinates(v1, 0, 0);
		assertCoordinates(v2, 0, 1);
		assertCoordinates(v3, 0, 2);
	}

	@Test
	public void testGrid_CenterRows_SingleRow_AlreadyCentered() {

		V v1 = new V("1");
		V v2 = new V("2");
		V v3 = new V("3");

		// one row; 3 columns
		locations.set(v1, 0, 0);
		locations.set(v2, 0, 1);
		locations.set(v3, 0, 2);

		locations.centerRows();

		// no changes; already centered
		assertCoordinates(v1, 0, 0);
		assertCoordinates(v2, 0, 1);
		assertCoordinates(v3, 0, 2);
	}

	@Test
	public void testGrid_CenterRows_SingleRow_NegativeColumns() {
		V v1 = new V("1");
		V v2 = new V("2");
		V v3 = new V("3");

		// one row; 3 columns; off center by 1
		locations.set(v1, 0, -2);
		locations.set(v2, 0, -1);
		locations.set(v3, 0, 0);

		locations.centerRows();

		assertCoordinates(v1, 0, 0);
		assertCoordinates(v2, 0, 1);
		assertCoordinates(v3, 0, 2);
	}

	@Test
	public void testGrid_CenterRows_MultipleRows_PositiveColumns() {

		/*
		 	Turn this:
		 	
		 		v v v v v v v v v v
		 		v v v
		 		  v v v v
		 		          v v v v v
		 		v v v v v v v v v v          		 	
		 	
		 	Into this:
		 	
		 		v v v v v v v v v v
		 		      v v v
		 		      v v v v
		 		    v v v v v
		 		v v v v v v v v v v		 	
		 	
		 */

		int col = 0;
		int row = 0;
		int size = 10;
		row(row, col, size);

		col = 0;
		row = 1;
		size = 3;
		row(row, col, size);

		col = 1;
		row = 2;
		size = 4;
		row(row, col, size);

		col = 5;
		row = 3;
		size = 5;
		row(row, col, size);

		col = 0;
		row = 4;
		size = 10;
		row(row, col, size);

		locations.centerRows();

		col = 0;
		row = 0;
		size = 10;
		assertRow(row, col, size);

		col = 3;
		row = 1;
		size = 3;
		assertRow(row, col, size);

		col = 3;
		row = 2;
		size = 4;
		assertRow(row, col, size);

		col = 2;
		row = 3;
		size = 5;
		assertRow(row, col, size);

		col = 0;
		row = 4;
		size = 10;
		assertRow(row, col, size);
	}

	@Test
	public void testGrid_CenterRows_MultipleRows_MixedColumns_WithEmtpyColumns() {

		/*
		Turn this:
		
		  0,0
			v v - - v
		v - v
			    v - v  		 	
		
		Into this:
		
			v v - - v
		      v - v
			  v - v  			 	
		
		*/

		V v1 = new V("v1");
		V v2 = new V("v2");
		V v3 = new V("v3");
		V v4 = new V("v4");
		V v5 = new V("v5");
		V v6 = new V("v6");
		V v7 = new V("v7");

		int row = 0;
		locations.set(v1, row, 0);
		locations.set(v2, row, 1);
		locations.set(v3, row, 4);

		row = 1;
		locations.set(v4, row, -2);
		locations.set(v5, row, 0);

		row = 2;
		locations.set(v6, row, 2);
		locations.set(v7, row, 4);

		locations.centerRows();

		// unchanged
		assertCoordinates(v1, 0, 0);
		assertCoordinates(v2, 0, 1);
		assertCoordinates(v3, 0, 4);

		// moved to the right
		assertCoordinates(v4, 1, 1);
		assertCoordinates(v5, 1, 3);

		// moved to the left
		assertCoordinates(v6, 2, 1);
		assertCoordinates(v7, 2, 3);
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void assertRow(int rowIndex, int startColumnIndex, int size) {

		List<Row<V>> rows = locations.rows();
		Row<V> row = getRow(rows, rowIndex);
		assertEquals("Row " + rowIndex + " has wrong column count", size,
			(int) row.getColumnCount());
		assertEquals(startColumnIndex, (int) row.getStartColumn());
	}

	private Row<V> getRow(List<Row<V>> rows, int rowIndex) {
		for (Row<V> r : rows) {
			if (r.index == rowIndex) {
				return r;
			}
		}

		fail("Could not find row for index: " + rowIndex);
		return null;
	}

	// creates linear entries for a row--no empty columns
	private void row(int row, int col, int size) {

		int count = 0;
		for (int i = col; count < size; i++, count++) {
			V v = new V("[" + row + "," + i + "]");
			locations.set(v, row, i);
		}
	}

	private void assertCoordinates(V v, int row, int col) {
		assertEquals("Row not set for '" + v + "'", row, (int) locations.row(v));
		assertEquals("Column not set for '" + v + "'", col, (int) locations.col(v));
	}

	private class V extends TestVertex {

		protected V(String name) {
			super(name);
		}
	}

	private class E extends TestEdge {

		public E(V start, V end) {
			super(start, end);
		}
	}
}
