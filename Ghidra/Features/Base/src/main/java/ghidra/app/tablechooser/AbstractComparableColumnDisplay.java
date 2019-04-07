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
package ghidra.app.tablechooser;

import ghidra.util.SystemUtilities;

/**
 * A version of {@link ColumnDisplay} to be used when the column value returned from
 * {@link #getColumnValue(AddressableRowObject)} is {@link Comparable}
 *
 * @param <COLUMN_TYPE> the column type
 */
public abstract class AbstractComparableColumnDisplay<COLUMN_TYPE extends Comparable<COLUMN_TYPE>>
		extends AbstractColumnDisplay<COLUMN_TYPE> {

	@Override
	public int compare(AddressableRowObject o1, AddressableRowObject o2) {
		COLUMN_TYPE v1 = getColumnValue(o1);
		COLUMN_TYPE v2 = getColumnValue(o2);
		return SystemUtilities.compareTo(v1, v2);
	}

}
