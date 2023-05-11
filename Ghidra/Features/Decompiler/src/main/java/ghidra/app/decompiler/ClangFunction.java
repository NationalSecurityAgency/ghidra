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
package ghidra.app.decompiler;

import ghidra.program.model.pcode.HighFunction;

/**
 * A grouping of source code tokens representing an entire function
 */
public class ClangFunction extends ClangTokenGroup {
	private final HighFunction hfunc;

	public ClangFunction(ClangNode parent, HighFunction hfunc) {
		super(parent);
		this.hfunc = hfunc;
	}

	@Override
	public ClangFunction getClangFunction() {
		return this;
	}

	/**
	 * @return the HighFunction object represented by this source code
	 */
	public HighFunction getHighFunction() {
		return hfunc;
	}
}
