/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.util.table.field;

import ghidra.util.classfinder.ExtensionPoint;

/**
 * NOTE:  ALL ProgramBasedDynamicTableColumnExtensionPoint CLASSES MUST END IN "TableColumn".  If not,
 * the ClassSearcher will not find them.
 */
public abstract class ProgramBasedDynamicTableColumnExtensionPoint<ROW_TYPE, COLUMN_TYPE> extends
		AbstractProgramBasedDynamicTableColumn<ROW_TYPE, COLUMN_TYPE> implements ExtensionPoint {

	// subclasses must implement

	public ProgramBasedDynamicTableColumnExtensionPoint() {
		super();
	}

	public ProgramBasedDynamicTableColumnExtensionPoint(String uniqueID) {
		super(uniqueID);
	}
}
