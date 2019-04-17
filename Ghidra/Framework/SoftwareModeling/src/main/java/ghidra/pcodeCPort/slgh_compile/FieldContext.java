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

import ghidra.pcodeCPort.slghsymbol.VarnodeSymbol;

class FieldContext implements Comparable<FieldContext> {
	VarnodeSymbol sym;
	FieldQuality qual;

	FieldContext(VarnodeSymbol s, FieldQuality q) {
		sym = s;
		qual = q;
	}

	@Override
	public int compareTo(FieldContext o) {
		int compare = sym.getName().compareTo(o.sym.getName());
		if (compare == 0) {
			return qual.low - o.qual.low;
		}
		return compare;
	}

	@Override
	public String toString() {
		return sym.getName() + "/" + qual.toString();
	}
}
