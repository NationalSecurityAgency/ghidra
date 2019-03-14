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
package ghidra.program.model.data;

/**
 * Array interface
 */
public interface Array extends DataType {

	public static final String ARRAY_LABEL_PREFIX = "ARRAY";

	/**
	 * Returns the number of elements in the array
	 * @return the number of elements in the array
	 */
	int getNumElements();

	/**
	 * Returns the length of an element in the array
	 * @return the length of one element in the array.
	 */
	int getElementLength();

	/**
	 * Returns the dataType of the elements in the array.
	 * @return the dataType of the elements in the array
	 */
	DataType getDataType();

}
