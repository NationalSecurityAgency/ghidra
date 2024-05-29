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
package ghidra.app.util.bin.format.dwarf;

import java.util.Arrays;

import ghidra.app.util.bin.format.dwarf.expression.*;

/**
 * Represents the location of an item that is only valid for a certain range of program-counter
 * locations.
 * <p>
 * An instance that does not have a DWARFRange is considered valid for any pc. 
 */
public class DWARFLocation {
	private DWARFRange addressRange;
	private byte[] expr;

	/**
	 * Create a Location given an address range and location expression.
	 * 
	 * @param start start address range
	 * @param end end of address range
	 * @param expr bytes of a DWARFExpression
	 */
	public DWARFLocation(long start, long end, byte[] expr) {
		this(new DWARFRange(start, end), expr);
	}

	public DWARFLocation(DWARFRange addressRange, byte[] expr) {
		this.addressRange = addressRange;
		this.expr = expr;
	}

	public DWARFRange getRange() {
		return this.addressRange;
	}

	public byte[] getExpr() {
		return this.expr;
	}

	public boolean isWildcard() {
		return addressRange == null;
	}

	public long getOffset(long pc) {
		return addressRange != null ? addressRange.getFrom() - pc : 0;
	}

	public boolean contains(long addr) {
		return isWildcard() || addressRange.contains(addr);
	}

	public DWARFExpressionResult evaluate(DWARFCompilationUnit cu) throws DWARFExpressionException {
		DWARFExpressionEvaluator evaluator = new DWARFExpressionEvaluator(cu);
		return evaluator.evaluate(evaluator.readExpr(this.expr));
	}

	@Override
	public String toString() {
		return "DWARFLocation: range: %s, expr: %s".formatted(addressRange, Arrays.toString(expr));
	}
}
