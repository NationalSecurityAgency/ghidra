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
package datagraph.data.graph.panel.model.row;

import java.util.ArrayList;
import java.util.List;

/**
 * Cache for {@link DataRowObject}s.  DataRowObjects are created as needed to conserve space. The
 * visible rows are kept in this cache to avoid having to recreate them on each paint call. It uses
 * a simple premise that paint calls will paint rows in order. So anytime a put occurs that is not
 * one more than the previous call, the assumption is that the view was scrolled, so the cache
 * is cleared and a new cache sequence is started. 
 */
public class DataRowObjectCache {
	private static final int MAX_CACHE_SIZE = 300;
	List<DataRowObject> cachedRows = new ArrayList<>();
	int startIndex = 0;

	public boolean contains(int rowIndex) {
		int cacheIndex = rowIndex - startIndex;
		return cacheIndex >= 0 && cacheIndex < cachedRows.size();
	}

	public DataRowObject getDataRow(int rowIndex) {
		return cachedRows.get(rowIndex - startIndex);
	}

	public void putData(int rowIndex, DataRowObject row) {
		// This cache expects data to be put in sequentially from some start row. The idea is
		// to cache the rows that are currently in the scrolled view. So anytime we are putting
		// in a row that is not the next expected row in sequence, throw away the cache and
		// start over.
		if (rowIndex != startIndex + cachedRows.size() || cachedRows.size() > MAX_CACHE_SIZE) {
			clear();
			startIndex = rowIndex;
		}
		cachedRows.add(row);
	}

	public void clear() {
		startIndex = 0;
		cachedRows.clear();
	}

}
