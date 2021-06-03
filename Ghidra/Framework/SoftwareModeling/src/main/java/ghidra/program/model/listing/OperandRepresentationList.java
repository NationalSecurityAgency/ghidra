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
package ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.List;

/**
 * <code>OperandRepresentation</code> provides a list for operand sub-elements.
 * The number of elements are expected to remain constant for a given code unit
 * operand regardless of its format.
 * <br>
 * The list may contain various Objects including any combination of Character,
 * String, VariableOffset, Register, Address, Scalar, LabelString, and 
 * nesting of other OperandRepresentationList objects.
 * <br> 
 * All objects returned must support the toString() method for producing
 * an appropriate listing representation. 
 */
public class OperandRepresentationList extends ArrayList<Object> {

	private boolean primaryReferenceIsHidden;
	private boolean hasError;
	
	OperandRepresentationList(List<?> opList, boolean primaryReferenceIsHidden) {
		super(opList);
		this.primaryReferenceIsHidden = primaryReferenceIsHidden;
	}
	
	OperandRepresentationList(boolean primaryReferenceIsHidden) {
		super();
		this.primaryReferenceIsHidden = primaryReferenceIsHidden;
	}
	
	OperandRepresentationList(List<?> opList) {
		super(opList);
	}
	
	OperandRepresentationList(String error) {
		super();
		add(error);
		hasError = true;
	}
	
	OperandRepresentationList() {
		super();
	}
	
	/**
	 * Set flag indicating that representation does not include primary
	 * reference representation.
	 * @param primaryReferenceIsHidden
	 */
	void setPrimaryReferenceHidden(boolean primaryReferenceIsHidden) {
		this.primaryReferenceIsHidden = primaryReferenceIsHidden;
	}
	
	/**
	 * Returns true if the primary reference is not reflected in the representation.
	 */
	public boolean isPrimaryReferenceHidden() {
		return primaryReferenceIsHidden;
	}
	
	/**
	 * Set flag indicating that representation encountered an error.
	 * @param hasError
	 */
	void setHasError(boolean hasError) {
		this.hasError = hasError;
	}
	
	/**
	 * Returns true if the representation encountered an error.
	 * Error will be reflected within the representation as a String.
	 */
	public boolean hasError() {
		return hasError;
	}
	
	/**
	 * Returns a formatted string representation of the specified code unit operand.
	 * @return formatted code unit representation
	 */
	@Override
    public String toString() {
		StringBuffer strBuf = new StringBuffer();
		for (Object opElem : this) {
			strBuf.append(opElem.toString());
		}
		return strBuf.toString();	
	}
	
}
