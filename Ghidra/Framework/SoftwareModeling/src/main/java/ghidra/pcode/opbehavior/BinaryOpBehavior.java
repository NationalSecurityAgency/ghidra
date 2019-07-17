/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.pcode.opbehavior;

import ghidra.pcode.utils.Utils;

import java.math.BigInteger;

public abstract class BinaryOpBehavior extends OpBehavior {

	BinaryOpBehavior(int opcode) {
		super(opcode);
	}

	/**
	 * Evaluate the binary (2 input args) operation using long data
	 * @param sizeout intended output size (bytes)
	 * @param sizein in1 size (bytes)
	 * @param unsignedIn1 unsigned input 1
	 * @param unsignedIn2 unsigned input 2
	 * @return operation result.  NOTE: if the operation overflows bits may be
	 * set beyond the specified sizeout.  Even though results should be treated
	 * as unsigned it may be returned as a signed long value.  It is expected that the 
	 * returned result always be properly truncated by the caller since the evaluation
	 * may not - this is done to conserve emulation cycles.
	 * @see Utils#longToBytes(long, int, boolean)
	 * @see Utils#bytesToLong(byte[], int, boolean)
	 */

	public abstract long evaluateBinary(int sizeout, int sizein, long unsignedIn1, long unsignedIn2);

	/**
	 * Evaluate the binary (2 input args) operation using BigInteger data
	 * @param sizeout intended output size (bytes)
	 * @param sizein in1 size (bytes)
	 * @param unsignedIn1 unsigned input 1
	 * @param unsignedIn2 unsigned input 2
	 * @return operation result.  NOTE: if the operation overflows bits may be
	 * set beyond the specified sizeout.  Even though results should be treated
	 * as unsigned it may be returned as a signed value.  It is expected that the 
	 * returned result always be properly truncated by the caller since the evaluation
	 * may not - this is done to conserve emulation cycles.
	 * @see Utils#bigIntegerToBytes(BigInteger, int, boolean)
	 * @see Utils#bytesToBigInteger(byte[], int, boolean, boolean) 
	 */
	public abstract BigInteger evaluateBinary(int sizeout, int sizein, BigInteger unsignedIn1,
			BigInteger unsignedIn2);

}
