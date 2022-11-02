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
package ghidra.app.plugin.core.debug.gui.register;

import java.math.BigInteger;
import java.util.Objects;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.services.DebuggerStateEditingService;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.trace.model.Trace;
import ghidra.util.Msg;

/**
 * A row displayed in the registers table of the Debugger
 */
public class RegisterRow {
	private final DebuggerRegistersProvider provider;
	private boolean favorite;
	private final int number;
	private final Register register;

	protected RegisterRow(DebuggerRegistersProvider provider, int number, Register register) {
		this.provider = provider;
		this.number = number;
		this.register = Objects.requireNonNull(register);
		this.favorite = provider.isFavorite(register);
	}

	/**
	 * Set whether this register is one of the user's favorites
	 * 
	 * <p>
	 * Note: Favorites are memorized on a per-compiler-spec (ABI, almost) basis.
	 * 
	 * @param favorite true if favorite
	 */
	public void setFavorite(boolean favorite) {
		this.favorite = favorite;
		provider.setFavorite(register, favorite);
	}

	/**
	 * Check if this register is one of the user's favorites
	 * 
	 * @return true if favorite
	 */
	public boolean isFavorite() {
		return favorite;
	}

	/**
	 * The index where this register appears in the language's {@link Language#getRegisters()} list
	 * 
	 * @return the index
	 */
	public int getNumber() {
		return number;
	}

	/**
	 * Get the register
	 * 
	 * @return the register
	 */
	public Register getRegister() {
		return register;
	}

	/**
	 * Get the register's name
	 * 
	 * @return the name
	 */
	public String getName() {
		return register.getName();
	}

	/**
	 * Check if the register can be edited
	 * 
	 * @return true if editable
	 */
	public boolean isValueEditable() {
		return provider.canWriteRegister(register);
	}

	/**
	 * Attempt to set the register's value
	 * 
	 * <p>
	 * The edit will be directed according to the tool's current edit mode. See
	 * {@link DebuggerStateEditingService#getCurrentMode(Trace)}
	 * 
	 * @param value the value
	 */
	public void setValue(BigInteger value) {
		try {
			provider.writeRegisterValue(register, value);
		}
		catch (Throwable t) {
			// Catch this here so cell editor relinquishes focus
			Msg.showError(this, null, "Cannot edit Register Value", t.getMessage(), t);
		}
	}

	/**
	 * Get the value of the register
	 * 
	 * <p>
	 * TODO: Perhaps some caching for all these getters which rely on the DB, since they could be
	 * invoked on every repaint.
	 * 
	 * @return the value
	 */
	public BigInteger getValue() {
		return provider.getRegisterValue(register);
	}

	public Data getData() {
		return provider.getRegisterData(register);
	}

	/**
	 * Assign a data type to the register
	 * 
	 * <p>
	 * This is memorized in the trace for the current and future snaps
	 * 
	 * @param dataType the data type
	 */
	public void setDataType(DataType dataType) {
		provider.writeRegisterDataType(register, dataType);
	}

	/**
	 * Get the data type of the register
	 * 
	 * @return the data type
	 */
	public DataType getDataType() {
		return provider.getRegisterDataType(register);
	}

	/**
	 * Set the value of the register as represented by its data type
	 * 
	 * @param representation the value to set
	 */
	public void setRepresentation(String representation) {
		provider.writeRegisterValueRepresentation(register, representation);
	}

	/**
	 * Check if the register's value can be set via its data type's representation
	 * 
	 * @return
	 */
	public boolean isRepresentationEditable() {
		return provider.canWriteRegisterRepresentation(register);
	}

	/**
	 * Get the value of the register as represented by its data type
	 * 
	 * @return the value
	 */
	public String getRepresentation() {
		return provider.getRegisterValueRepresentation(register);
	}

	/**
	 * Check if the register's value is (completely) known
	 * 
	 * @return true if known
	 */
	public boolean isKnown() {
		return provider.isRegisterKnown(register);
	}

	/**
	 * Check if the register's value changed since last navigation or command
	 * 
	 * @return true if changed
	 */
	public boolean isChanged() {
		return provider.isRegisterChanged(register);
	}

	/**
	 * Get the table's current coordinates (usually also the tool's)
	 * 
	 * @return the coordinates
	 */
	public DebuggerCoordinates getCurrent() {
		return provider.getCurrent();
	}
}
