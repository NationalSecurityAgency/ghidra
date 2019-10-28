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
package ghidra.pcodeCPort.slghsymbol;

import generic.stl.VectorSTL;
import ghidra.pcode.utils.MessageFormattingUtils;
import ghidra.pcodeCPort.slghpattern.DisjointPattern;

public class DecisionProperties {
	private VectorSTL<String> identerrors = new VectorSTL<>();
	private VectorSTL<String> conflicterrors = new VectorSTL<>();

	public VectorSTL<String> getIdentErrors() {
		return identerrors;
	}

	public VectorSTL<String> getConflictErrors() {
		return conflicterrors;
	}

	public void identicalPattern(Constructor a, Constructor b) {
		// Note that -a- and -b- have identical patterns
		if ((!a.isError()) && (!b.isError())) {
			a.setError(true);
			b.setError(true);

			String msg = "Constructors with identical patterns:\n   " + a + "\n   " + b;
			identerrors.push_back(MessageFormattingUtils.format(a.location, msg));
			identerrors.push_back(MessageFormattingUtils.format(b.location, msg));
		}
	}

	public void conflictingPattern(DisjointPattern pa, Constructor a, DisjointPattern pb,
			Constructor b) {
		// Note that -a- and -b- have (potentially) conflicting patterns
		if ((!a.isError()) && (!b.isError())) {
			a.setError(true);
			b.setError(true);

			String msg = "Constructor patterns cannot be distinguished: \n" //
				+ "   " + pa + " " + a + "\n" //
				+ "   " + pb + " " + b;
			conflicterrors.push_back(MessageFormattingUtils.format(a.location, msg));
			conflicterrors.push_back(MessageFormattingUtils.format(b.location, msg));
		}
	}
}
