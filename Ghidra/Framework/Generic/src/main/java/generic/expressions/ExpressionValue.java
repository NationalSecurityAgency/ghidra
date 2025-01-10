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
package generic.expressions;

/**
 *  Operand types use by the {@link ExpressionEvaluator} must implement this interface.
 */
public interface ExpressionValue extends ExpressionElement {

	/**
	 * Method called to apply a unary operator to this value.
	 * @param operator the operator being applied
	 * @return the new value after the operator is applied to this value
	 * @throws ExpressionException if the operator is not applicable for this value
	 */
	public ExpressionValue applyUnaryOperator(ExpressionOperator operator) throws ExpressionException;

	/**
	 * Method called to apply a binary operator to this value.
	 * @param operator the binary operator being applied.
	 * @param value the other value to combine with this value by the operator
	 * @return the new value after the operator is applied to this value
	 * @throws ExpressionException if the operator is not applicable for this value or the the other
	 * value is not applicable for this operand and operator
	 */
	public ExpressionValue applyBinaryOperator(ExpressionOperator operator, ExpressionValue value)
			throws ExpressionException;

}
