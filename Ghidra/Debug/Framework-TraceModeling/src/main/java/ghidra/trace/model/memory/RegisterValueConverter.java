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
package ghidra.trace.model.memory;

import java.math.BigInteger;

import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.trace.model.target.TraceObjectValue;

public class RegisterValueConverter {
	private final TraceObjectValue registerValue;
	private BigInteger value;
	private int bitLength = -1;
	private byte[] be;
	private byte[] le;

	public RegisterValueConverter(TraceObjectValue registerValue) {
		this.registerValue = registerValue;
	}

	public static BigInteger convertValueToBigInteger(Object val) throws RegisterValueException {
		if (val instanceof String s) {
			try {
				return new BigInteger(s, 16);
			}
			catch (NumberFormatException e) {
				throw new RegisterValueException(
					"Invalid register value " + s + ". Must be hex digits only.");
			}
		}
		else if (val instanceof byte[] arr) {
			// NOTE: Reg object values are always big endian
			return new BigInteger(1, arr);
		}
		else if (val instanceof Byte b) {
			return BigInteger.valueOf(b);
		}
		else if (val instanceof Short s) {
			return BigInteger.valueOf(s);
		}
		else if (val instanceof Integer i) {
			return BigInteger.valueOf(i);
		}
		else if (val instanceof Long l) {
			return BigInteger.valueOf(l);
		}
		else if (val instanceof Address a) {
			return a.getOffsetAsBigInteger();
		}
		throw new RegisterValueException(
			"Cannot convert register value: (" + val.getClass() + ") '" + val + "'");
	}

	BigInteger convertRegisterValueToBigInteger() throws RegisterValueException {
		return convertValueToBigInteger(registerValue.getValue());
	}

	int getRegisterValueBitLength() throws RegisterValueException {
		Object objBitLength = registerValue.getParent()
				.getValue(registerValue.getMinSnap(), TraceRegister.KEY_BITLENGTH)
				.getValue();
		if (!(objBitLength instanceof Number numBitLength)) {
			throw new RegisterValueException(
				"Register length is not numeric: (" + objBitLength.getClass() + ") '" +
					objBitLength + "'");
		}
		return numBitLength.intValue();
	}

	public BigInteger getValue() throws RegisterValueException {
		if (value != null) {
			return value;
		}
		return value = convertRegisterValueToBigInteger();
	}

	int getBitLength() throws RegisterValueException {
		if (bitLength != -1) {
			return bitLength;
		}
		return bitLength = getRegisterValueBitLength();
	}

	int getByteLength() throws RegisterValueException {
		return (getBitLength() + 7) / 8;
	}

	public byte[] getBytesBigEndian() throws RegisterValueException {
		if (be != null) {
			return be;
		}
		return be = Utils.bigIntegerToBytes(getValue(), getByteLength(), true);
	}

	public byte[] getBytesLittleEndian() throws RegisterValueException {
		if (le != null) {
			return le;
		}
		return le = Utils.bigIntegerToBytes(getValue(), getByteLength(), false);
	}

	public byte[] getBytes(boolean isBigEndian) throws RegisterValueException {
		return isBigEndian ? getBytesBigEndian() : getBytesLittleEndian();
	}
}
