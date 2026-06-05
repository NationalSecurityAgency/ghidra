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
package ghidra.lisa.pcode.contexts;

import ghidra.program.model.pcode.Varnode;

public class VarnodeContext {

	protected Varnode vn;

	public VarnodeContext(Varnode vn) {
		this.vn = vn;
	}

	public boolean isConstant() {
		return vn.isConstant();
	}

	public int getSize() {
		return vn.getSize();
	}

	public long getOffset() {
		return vn.getOffset();
	}

	public String getText() {
		return vn.getAddress().toString();
	}

}
