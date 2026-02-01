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
package ghidra.pcode.emu.jit.var;

import java.math.BigInteger;

/**
 * A p-code constant use-def node.
 */
public class JitConstVal extends AbstractJitVal {
	private final BigInteger value;

	/**
	 * Construct a constant.
	 * 
	 * <p>
	 * Use {@link JitVal#constant(int, BigInteger)} instead.
	 * 
	 * @param size the size in bytes
	 * @param value the value
	 */
	public JitConstVal(int size, BigInteger value) {
		super(size);
		this.value = value;
	}

	@Override
	public String toString() {
		return "%s[value=%s]".formatted(getClass().getSimpleName(), value);
	}

	/**
	 * The value of this constant.
	 * 
	 * @return the value
	 */
	public BigInteger value() {
		return value;
	}
}
