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

import java.util.Comparator;

/**
 * An interface that allows users to add columns to the {@link TableChooserDialog}.
 *
 * @param <COLUMN_TYPE> column type
 */
public interface ColumnDisplay<COLUMN_TYPE> extends Comparator<AddressableRowObject> {
	public COLUMN_TYPE getColumnValue(AddressableRowObject rowObject);

	public String getColumnName();

	public Class<COLUMN_TYPE> getColumnClass();
}
