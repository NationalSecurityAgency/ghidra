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
package ghidra.app.plugin.core.debug.gui.emulation;

import java.math.BigInteger;
import java.util.Arrays;

import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.util.NumericUtilities;

// LATER: Move this into some utilities and have DefaultWatchRow use it, too?
enum RawStyle {
	INTEGER {
		@Override
		String toString(byte[] value, Language language) {
			if (value == null) {
				return "";
			}
			BigInteger asInt =
				Utils.bytesToBigInteger(value, value.length, language.isBigEndian(), false);
			return "0x" + asInt.toString(16);
		}

		@Override
		byte[] fromString(String string, int length, Language language) {
			string = string.trim();
			final BigInteger asInt = string.startsWith("0x")
					? new BigInteger(string.substring(2), 16)
					: new BigInteger(string, 10);
			return Utils.bigIntegerToBytes(asInt, length, language.isBigEndian());
		}
	},
	BYTES {
		@Override
		String toString(byte[] value, Language language) {
			if (value == null) {
				return "";
			}
			return "{ %s }".formatted(NumericUtilities.convertBytesToString(value, " "));
		}

		@Override
		byte[] fromString(String string, int length, Language language) {
			string = string.trim();
			if (!string.startsWith("{") && string.endsWith("}")) {
				throw new IllegalArgumentException(string);
			}
			string = string.substring(1, string.length() - 1);
			byte[] data = NumericUtilities.convertStringToBytes(string);
			if (data.length == length) {
				return data;
			}
			return Arrays.copyOf(data, length);
		}
	};

	static RawStyle defaultForSpace(AddressSpace space) {
		return space.isMemorySpace() ? BYTES : INTEGER;
	}

	static RawStyle fromString(String string) {
		return string.trim().startsWith("{") ? BYTES : INTEGER;
	}

	abstract String toString(byte[] value, Language language);

	abstract byte[] fromString(String string, int length, Language language);
}
