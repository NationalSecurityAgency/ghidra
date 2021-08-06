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
package ghidra.pcode.exec;

import java.math.BigInteger;

import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.UnaryOpBehavior;

public interface PcodeArithmetic<T> {
	PcodeArithmetic<byte[]> BYTES_BE = BytesPcodeArithmetic.BIG_ENDIAN;
	PcodeArithmetic<byte[]> BYTES_LE = BytesPcodeArithmetic.LITTLE_ENDIAN;
	PcodeArithmetic<BigInteger> BIGINT = BigIntegerPcodeArithmetic.INSTANCE;

	T unaryOp(UnaryOpBehavior op, int sizeout, int sizein1, T in1);

	T binaryOp(BinaryOpBehavior op, int sizeout, int sizein1, T in1, int sizein2, T in2);

	T fromConst(long value, int size);

	T fromConst(BigInteger value, int size);

	/**
	 * Make concrete, if possible, the given abstract condition to a boolean value
	 * 
	 * @param cond the abstract condition
	 * @return the boolean value
	 */
	boolean isTrue(T cond);

	/**
	 * Make concrete, if possible, the given abstract value
	 * 
	 * <p>
	 * If the conversion is not possible, throw an exception. TODO: Decide on conventions of which
	 * exception to throw and/or establish a hierarchy of checked exceptions.
	 * 
	 * @param value the abstract value
	 * @return the concrete value
	 */
	BigInteger toConcrete(T value);
}
