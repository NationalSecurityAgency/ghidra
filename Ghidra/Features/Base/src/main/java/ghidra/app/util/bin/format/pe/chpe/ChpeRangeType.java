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
package ghidra.app.util.bin.format.pe.chpe;

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
import java.io.IOException;
import java.util.Arrays;

/**
 * CHPE range types
 */
public enum ChpeRangeType {

	ARM64(0x0),
	ARM64EC(0x1),
	X86_64(0x2),
	UNKNOWN(0x100); // made up to handle unknown types

	private long value;

	/**
	 * Creates a new {@link ChpeRangeType}
	 * 
	 * @param value The defined value of the type
	 */
	private ChpeRangeType(long value) {
		this.value = value;
	}

	/**
	 * {@return the type's defined value}
	 */
	public long getValue() {
		return value;
	}

	/**
	 * Reads a {@link ChpeRangeType}
	 * 
	 * @param value The defined value of the type
	 * @return The type of the given value, or {@link #UNKNOWN} if the value does not correspond to 
	 *   a known type
	 * @throws IOException if there was an IO-related error
	 */
	public static ChpeRangeType type(int value) throws IOException {
		return Arrays.stream(ChpeRangeType.values())
				.filter(e -> value == e.getValue())
				.findFirst()
				.orElse(UNKNOWN);
	}
}

