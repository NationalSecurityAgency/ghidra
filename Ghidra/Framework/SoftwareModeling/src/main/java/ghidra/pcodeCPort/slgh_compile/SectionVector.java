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
package ghidra.pcodeCPort.slgh_compile;

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.semantics.ConstructTpl;
import ghidra.pcodeCPort.slghsymbol.SymbolScope;

public class SectionVector {
	private int nextindex;
	private RtlPair main;
	private VectorSTL<RtlPair> named;

	public SectionVector(ConstructTpl rtl, SymbolScope scope) {
		nextindex = -1;
		main = new RtlPair();
		named = new VectorSTL<RtlPair>();
		main.section = rtl;
		main.scope = scope;
	}

	public ConstructTpl getMainSection() {
		return main.section;
	}

	public ConstructTpl getNamedSection(int index) {
		return named.get(index).section;
	}

	public RtlPair getMainPair() {
		return main;
	}

	public RtlPair getNamedPair(int i) {
		return named.get(i);
	}

	public void setNextIndex(int i) {
		nextindex = i;
	}

	public int getMaxId() {
		return named.size();
	}

	public void append(ConstructTpl rtl, SymbolScope scope) {
		while (named.size() <= nextindex) {
			named.push_back(new RtlPair());
		}
		named.set(nextindex, new RtlPair(rtl, scope));
	}
}
