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

import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.util.Msg;

public class RegisterRow {
	private final DebuggerRegistersProvider provider;
	private boolean favorite;
	private final int number;
	private final Register register;

	public RegisterRow(DebuggerRegistersProvider provider, int number, Register register) {
		this.provider = provider;
		this.number = number;
		this.register = register;
		this.favorite = provider.isFavorite(register);
	}

	public void setFavorite(boolean favorite) {
		this.favorite = favorite;
		provider.setFavorite(register, favorite);
	}

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

	public Register getRegister() {
		return register;
	}

	public String getName() {
		return register.getName();
	}

	public boolean isValueEditable() {
		return provider.canWriteTargetRegister(register);
	}

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
	 * TODO: Perhaps some caching for all these getters which rely on the DB, since they could be
	 * invoked on every repaint.
	 */
	public BigInteger getValue() {
		return provider.getRegisterValue(register);
	}

	public void setDataType(DataType dataType) {
		provider.writeRegisterDataType(register, dataType);
	}

	public DataType getDataType() {
		return provider.getRegisterDataType(register);
	}

	// TODO: setValueRepresentation. Requires support from data types.

	public String getRepresentation() {
		return provider.getRegisterValueRepresentation(register);
	}

	public boolean isKnown() {
		return provider.isRegisterKnown(register);
	}

	public boolean isChanged() {
		return provider.isRegisterChanged(register);
	}
}
