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
package ghidra.app.plugin.core.functioncompare;

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;

/**
 * Defines the information being displayed in the left or right panels
 * of a {@link FunctionComparisonPanel}, which can display either
 * {@link Function functions}, {@link Data data}, or specified
 * {@link AddressSet address sets}. At any given time, only one of the 
 * Function or Data attributes may be set; the other will be 
 * set to null.
 */
class FunctionComparisonData {

	protected Program program;
	protected Function function;
	protected Data data;
	protected AddressSetView addressSet = new AddressSet();

	/**
	 * Returns the program for this model
	 * 
	 * @return the program, or null if not set
	 */
	public Program getProgram() {
		return program;
	}

	/**
	 * Sets the program for this model
	 * 
	 * @param program the program to set
	 */
	public void setProgram(Program program) {
		this.program = program;
	}

	/**
	 * Returns the function for this model
	 * 
	 * @return the function, or null if not set
	 */
	public Function getFunction() {
		return function;
	}

	/**
	 * Sets the function for this model
	 * 
	 * @param function the function to set
	 */
	public void setFunction(Function function) {
		if (function == null) {
			clear();
			return;
		}
		this.function = function;
		this.data = null;
		this.program = function.getProgram();
		this.addressSet = function.getBody();
	}

	/**
	 * Returns the data for this model
	 * 
	 * @return the data, or null if not set
	 */
	public Data getData() {
		return data;
	}

	/**
	 * Sets the data for this model
	 * 
	 * @param data the data to set
	 */
	public void setData(Data data) {
		if (data == null) {
			clear();
			return;
		}
		this.data = data;
		this.function = null;
		this.program = data.getProgram();
		this.addressSet = new AddressSet(data.getMinAddress(), data.getMaxAddress());
	}

	/**
	 * Returns the address set for this model
	 * 
	 * @return the address set, or null if not set
	 */
	public AddressSetView getAddressSet() {
		return addressSet;
	}

	/**
	 * Sets the address for this model
	 * 
	 * @param addressSet the addressSet to set
	 */
	public void setAddressSet(AddressSetView addressSet) {
		this.addressSet = addressSet;
		this.data = null;
		this.function = null;
	}

	/**
	 * Returns true if the data being managed by this model is of type
	 * {@link Data}
	 * 
	 * @return true if this model is set to display {@link Data}
	 */
	public boolean isData() {
		return data != null;
	}

	/**
	 * Returns true if the data being managed by this model is of type
	 * {@link Function}
	 * 
	 * @return true if this model is set to display a {@link Function}
	 */
	public boolean isFunction() {
		return function != null;
	}

	/**
	 * Returns true if this class holds no function, data or address set
	 * information
	 * 
	 * @return true if this class holds no function, data or address set
	 * information
	 */
	public boolean isEmpty() {
		return function == null && data == null && addressSet == null;
	}

	/**
	 * Resets all fields in this model to a nominal state
	 */
	public void clear() {
		this.function = null;
		this.data = null;
		this.addressSet = new AddressSet();
		this.program = null;
	}

	public String toString() {
		String str = "";

		if (function != null) {
			str = function.getName();
		}
		else if (data != null) {
			str = data.getAddress().toString();
		}
		else if (addressSet != null) {
			str = addressSet.toString();
		}
		else {
			str = "none";
		}

		return str;
	}
}
