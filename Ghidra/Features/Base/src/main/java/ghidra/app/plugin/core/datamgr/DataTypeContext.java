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
package ghidra.app.plugin.core.datamgr;

import java.util.List;

import ghidra.program.model.data.DataType;

/**
 * A context interface that signals the context providers selected data types.
 */
public interface DataTypeContext {

	/**
	 * {@return the selected data type.  If more than one type is selected, then this method will 
	 * return null.}
	 */
	public DataType getSelectedDataType();

	/**
	 * {@return the selected data types}
	 */
	public List<DataType> getSelectedDataTypes();

	/**
	 * {@return true if one or more data types is selected. Use this over 
	 * {@link #getSelectedDataTypes()} when speed is important, such as when checking action 
	 * enablement.}
	 */
	public boolean hasSelectedDataTypes();
}
