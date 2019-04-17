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
 * NOTE:  ALL AnnotationHandler CLASSES MUST END IN "AnnotationHandler".  If not,
 * the ClassSearcher will not find them.
 * 
 * AnnotationHandlers provide prefix/suffix information for various datatypes
 * for specific C-like languages.
 */
public interface AnnotationHandler extends ExtensionPoint {

	/**
	 * Returns the prefix for type Enum
	 * @param e the Enum datatype
	 * @param member the name of the member of the Enum
	 * @return the prefix for type Enum
	 */
	public String getPrefix(Enum e, String member);

	/**
	 * Returns the suffix for type Enum
	 * @param e the Enum datatype
	 * @param member the name of the member of the Enum
	 * @return the suffix for type Enum
	 */
	public String getSuffix(Enum e, String member);

	/**
	 * Returns the prefix for type Composite
	 * @param c the Composite datatype
	 * @param dtc the name of the member of the Composite
	 * @return the prefix for type Composite
	 */
	public String getPrefix(Composite c, DataTypeComponent dtc);

	/**
	 * Returns the suffix for type Composite
	 * @param c the Composite datatype
	 * @param dtc the name of the member of the Composite
	 * @return the suffix for type Composite
	 */
	public String getSuffix(Composite c, DataTypeComponent dtc);

	/**
	 * Returns the description of the specific handler
	 * @return the description of the specific handler
	 */
	public String getDescription();

	/** 
	 * Returns the name of the C-like language that this handler supports
	 * @return the name of the C-like language that this handler supports
	 */
	public String getLanguageName();

	/**
	 * Returns an array of known extensions for the output file type.  If no extensions are 
	 * preferred, the an empty array should be returned.
	 * @return an array of known extensions for the output file type.
	 */
	public String[] getFileExtensions();

	/**
	 * Returns a string description of this handler.
	 * @return a string description of this handler
	 */
	public String toString();
}
