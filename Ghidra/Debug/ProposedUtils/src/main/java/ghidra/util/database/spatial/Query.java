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
package ghidra.util.database.spatial;

import java.util.Comparator;

public interface Query<DS, NS> {
	/**
	 * The result of testing a sub-tree for inclusion in a query
	 */
	enum QueryInclusion {
		/**
		 * The query certainly includes all data in the sub-tree
		 */
		ALL,
		/**
		 * The query may include some data in the sub-tree
		 */
		SOME,
		/**
		 * The query certainly excludes all data in the sub-tree
		 */
		NONE;
	}

	/**
	 * Test if internal data entry iteration can terminate early
	 * 
	 * @param shape the shape of the current data entry
	 * @return true if no entry to follow could possibly be included in the query
	 */
	boolean terminateEarlyData(DS shape);

	/**
	 * Test if the given data shape is included in the query
	 * 
	 * @param shape the shape of the data entry
	 * @return true if it is included
	 */
	boolean testData(DS shape);

	/**
	 * Test if internal node entry iteration can terminate early
	 * 
	 * @param shape the shape of the current node entry
	 * @return true if no entry to follow could possibly contain data entries included in the query
	 */
	boolean terminateEarlyNode(NS shape);

	/**
	 * Test if the given node shape has data entries included in the query
	 * 
	 * @param shape the shape (bounds) of the node entry
	 * @return a result as described in {@link QueryInclusion}
	 */
	QueryInclusion testNode(NS shape);

	/**
	 * If the query orders elements, get the (or an equivalent) comparator.
	 * 
	 * @return an comparator
	 */
	Comparator<NS> getBoundsComparator();
}
