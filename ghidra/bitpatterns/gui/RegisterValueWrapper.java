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
package ghidra.bitpatterns.gui;

import java.math.BigInteger;

import docking.widgets.combobox.GhidraComboBox;

/**
 * This class simply wraps {@link BigInteger}.  It's used in the {@link GhidraComboBox} in the 
 * {@link ContextRegisterFilterInputDialog} so that null filters display something other
 * than the empty string
 */

public class RegisterValueWrapper {

	private BigInteger value;

	/**
	 * Create a wrapper for the given value
	 * @param value value to wrap
	 */
	public RegisterValueWrapper(BigInteger value) {
		this.value = value;
	}

	/**
	 * Get the wrapped value
	 * @return value
	 */
	public BigInteger getValue() {
		return value;
	}

	@Override
	public String toString() {
		if (value == null) {
			return "unconstrained";
		}
		return value.toString();
	}
}
