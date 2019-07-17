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

import ghidra.util.classfinder.ExtensionPoint;

/**
 * NOTE:  ALL DATATYPE CLASSES MUST END IN "DataType".  If not,
 * the ClassSearcher will not find them.
 * 
 * Interface to mark classes as a built-in data type.
 */
public interface BuiltInDataType extends DataType, ExtensionPoint {

	/**
	 * Generate a suitable C-type declaration for this data-type as a #define or typedef.
	 * Since the length of a Dynamic datatype is unknown, such datatypes
	 * should only be referenced in C via a pointer.  FactoryDataTypes
	 * should never be referenced and will always return null.
	 * @param dataOrganization or null for default
	 * @return definition C-statement (e.g., #define or typedef) or null
	 * if type name is a standard C-primitive name or if type is FactoryDataType
	 * or Dynamic.
	 */
	public String getCTypeDeclaration(DataOrganization dataOrganization);

}
