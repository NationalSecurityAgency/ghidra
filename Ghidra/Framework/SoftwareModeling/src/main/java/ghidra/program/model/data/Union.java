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
package ghidra.program.model.data;

/**
 * The union interface
 */
public interface Union extends Composite {
	/**
	 * 
	 * @see ghidra.program.model.data.Composite#add(ghidra.program.model.data.DataType)
	 */
	public DataTypeComponent add(DataType dataType);

	/**
	 * @see ghidra.program.model.data.Composite#add(ghidra.program.model.data.DataType, int)
	 */
	public DataTypeComponent add(DataType dataType, int length);

	/**
	 * @see ghidra.program.model.data.Composite#add(ghidra.program.model.data.DataType, int, java.lang.String, java.lang.String)
	 */
	public DataTypeComponent add(DataType dataType, int length, String name, String comment);

	/**
	 * @see ghidra.program.model.data.Composite#insert(int, ghidra.program.model.data.DataType)
	 */
	public DataTypeComponent insert(int ordinal, DataType dataType);

	/**
	 * @see ghidra.program.model.data.Composite#insert(int, ghidra.program.model.data.DataType, int)
	 */
	public DataTypeComponent insert(int ordinal, DataType dataType, int length);

	/**
	 * @see ghidra.program.model.data.Composite#insert(int, ghidra.program.model.data.DataType, int, java.lang.String, java.lang.String)
	 */
	public DataTypeComponent insert(int ordinal, DataType dataType, int length, String name,
			String comment);

	/**
	 * 
	 * @see ghidra.program.model.data.Composite#delete(int)
	 */
	public void delete(int ordinal);

	/**
	 * 
	 * @see ghidra.program.model.data.Composite#getComponents()
	 */
	public abstract DataTypeComponent[] getComponents();

}
