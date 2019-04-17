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
package ghidra.app.util.bin.format.dwarf4.expression;

/**
 * A exception that is thrown when dealing with {@link DWARFExpression DWARF expressions}
 * or when they are {@link DWARFExpressionEvaluator evaluated.}
 * <p>
 * Use this class when you want to pass the {@link DWARFExpression expression} and
 * the opcode / step in the expression that caused the problem back up the call chain.
 */
public class DWARFExpressionException extends Exception {

	private DWARFExpression expr;
	private int step = -1;

	public DWARFExpressionException() {
		super();
	}

	public DWARFExpressionException(String message, DWARFExpression expr, int step) {
		this(message, expr, step, null);
	}

	public DWARFExpressionException(String message, DWARFExpression expr, int step,
			Throwable cause) {
		super(message, cause);
		this.expr = expr;
		this.step = step;
	}

	public DWARFExpressionException(String message, Throwable cause) {
		super(message, cause);
	}

	public DWARFExpressionException(String message) {
		super(message);
	}

	public DWARFExpressionException(Throwable cause) {
		super(cause);
	}

	public DWARFExpression getExpression() {
		return expr;
	}

	public void setExpression(DWARFExpression expr) {
		this.expr = expr;
	}

	public void setStep(int step) {
		this.step = step;
	}

	public int getStep() {
		return step;
	}

	public String getMessage() {
		return super.getMessage() + (expr != null ? "\n" + expr.toString(step, false, false) : "");
	}

}
