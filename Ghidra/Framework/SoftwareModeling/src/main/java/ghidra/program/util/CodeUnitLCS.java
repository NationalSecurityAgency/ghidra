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
package ghidra.program.util;

import generic.algorithms.Lcs;

import java.util.List;

public class CodeUnitLCS extends Lcs<CodeUnitContainer> {

	private List<CodeUnitContainer> xList;
	private List<CodeUnitContainer> yList;

	public CodeUnitLCS(List<CodeUnitContainer> xList, List<CodeUnitContainer> yList) {
		this.xList = xList;
		this.yList = yList;
	}

	@Override
	protected int lengthOfX() {
		return xList.size();
	}

	@Override
	protected int lengthOfY() {
		return yList.size();
	}

	@Override
	public boolean matches(CodeUnitContainer x, CodeUnitContainer y) {
		return x.getArity() == y.getArity() && x.getMnemonic().equals(y.getMnemonic());
	}

	@Override
	protected CodeUnitContainer valueOfX(int index) {
		return xList.get(index - 1);
	}

	@Override
	protected CodeUnitContainer valueOfY(int index) {
		return yList.get(index - 1);
	}
}
