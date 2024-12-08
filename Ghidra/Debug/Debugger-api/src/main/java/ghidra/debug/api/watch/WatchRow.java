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
package ghidra.debug.api.watch;

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.symbol.Symbol;

/**
 * A row in the Watches table
 */
public interface WatchRow {

	/**
	 * Get the Sleigh expression
	 * 
	 * @return the expression
	 */
	String getExpression();

	/**
	 * Set the Sleigh expression
	 * 
	 * @param expression the expression
	 */
	void setExpression(String expression);

	/**
	 * Get the data type for interpreting the value
	 * 
	 * @return the data type
	 */
	DataType getDataType();

	/**
	 * Set the data type for interpreting the value
	 * 
	 * @param dataType the data type
	 */
	void setDataType(DataType dataType);

	/**
	 * Get the settings on the data type
	 * 
	 * <p>
	 * The returned settings may be modified, after which {@link #settingsChanged()} must be called.
	 * There is no {@code setSettings} method.
	 * 
	 * @return the settings
	 */
	Settings getSettings();

	/**
	 * Notify the row that the settings were changed
	 * 
	 * @see #getSettings()
	 */
	void settingsChanged();

	/**
	 * Get the address of the value, if it exists at one (memory or register)
	 * 
	 * @return the address, or null
	 */
	Address getAddress();

	/**
	 * Get the address range of the value, if it exists at an address (memory or register)
	 * 
	 * @return the range, or null
	 */
	AddressRange getRange();

	/**
	 * Get the complete set of all addresses read to evaluate the expression
	 * 
	 * @return the address set, or null
	 */
	AddressSetView getReads();

	/**
	 * Get the nearest symbol before the value's address, if applicable
	 * 
	 * @return the symbol, or null
	 */
	Symbol getSymbol();

	/**
	 * Get the raw value
	 * 
	 * @return the value, or null
	 */
	byte[] getValue();

	/**
	 * Get the raw value displayed as a string
	 * 
	 * <p>
	 * For values in memory, this is a list of hex bytes. For others, it is a hex integer subject to
	 * the platform's endian.
	 * 
	 * @return the value, or null
	 */
	String getRawValueString();

	/**
	 * Get the number of bytes in the value
	 * 
	 * @return the length, or 0 if evaluation failed
	 */
	int getValueLength();

	/**
	 * Patch memory or register values such that the expression evaluates to the given raw value
	 * 
	 * <p>
	 * This is only supported when {@link #isRawValueEditable} returns true. The given value must be
	 * a list of hex bytes (as returned by {@link #getRawValueString()}), or a hex integer subject
	 * to the platform's endian. Either is accepted, regardless of whether the value resides in
	 * memory.
	 * 
	 * @see #getAddress()
	 * @param value the raw value as returned by {@link #getRawValueString()}
	 */
	void setRawValueString(String value);

	/**
	 * Check if {@link #setRawValueString(String)} is supported
	 * 
	 * <p>
	 * Setting the value may not be supported for many reasons: 1) The expression is not valid, 2)
	 * The expression could not be evaluated, 3) The value has no address or register. Reason 3 is
	 * somewhat strict, but reasonable, lest we have to implement a solver.
	 * 
	 * @return whether or not the value can be modified
	 */
	boolean isRawValueEditable();

	/**
	 * Get the value as returned by the data type
	 * 
	 * @return the data-type defined value
	 */
	Object getValueObject();

	/**
	 * Get the value as represented by the data type
	 * 
	 * @return the value's data-type-defined representation
	 */
	String getValueString();

	/**
	 * Patch memory or register values such that the expression evaluates to the given value
	 * 
	 * <p>
	 * This is only supported when {@link #isValueEditable()} returns true. The given value must be
	 * encodable by the data type.
	 * 
	 * @param value the desired value, as returned by {@link #getValueString()}
	 */
	void setValueString(String value);

	/**
	 * Check if {@link #setValueString(String)} is supported
	 * 
	 * <p>
	 * In addition to those reasons given in {@link #isRawValueEditable()}, setting the value may
	 * not be supported because: 1) No data type is set, or 2) The selected data type does not
	 * support encoding.
	 * 
	 * @return whether or not the data-type interpreted value can be modified
	 */
	boolean isValueEditable();

	/**
	 * If the watch could not be evaluated, get the cause
	 * 
	 * @return the error
	 */
	Throwable getError();

	/**
	 * If the watch could not be evaluated, get a message explaining why
	 * 
	 * <p>
	 * This is essentially the message given by {@link #getError()}. If the exception does not
	 * provide a message, this will at least give the name of the exception class.
	 * 
	 * @return the error message, or an empty string
	 */
	String getErrorMessage();

	/**
	 * Check if the value given is actually known to be the value
	 * 
	 * <p>
	 * If the value itself or any value encountered during the evaluation of the expression is
	 * stale, then the final value is considered stale, i.e., not known.
	 * 
	 * @return true all memory and registers involved in the evaluation are known, false otherwise.
	 */
	boolean isKnown();

	/**
	 * Check if the value has changed
	 * 
	 * <p>
	 * "Changed" technically deals in navigation. In the case of a step, resume-and-break, patch,
	 * etc. This will detect the changes as expected. When manually navigating, this compares the
	 * two most recent times visited. Only the value itself is compared, without consideration for
	 * any intermediate values encountered during evaluation. Consider an array whose elements are
	 * all currently 0. An expression that dereferences an index in that array will be considered
	 * unchanged, even if the index did change.
	 * 
	 * @return true if the value changed, false otherwise.
	 */
	boolean isChanged();
}
