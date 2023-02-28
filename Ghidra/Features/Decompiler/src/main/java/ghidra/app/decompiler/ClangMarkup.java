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

import ghidra.program.model.pcode.*;

public abstract class ClangMarkup {			// Placeholder for CLANG XML identifiers

	public static ClangTokenGroup buildClangTree(Decoder decoder, HighFunction hfunc)
			throws DecoderException {
		ClangTokenGroup docroot;
		int el = decoder.openElement();
		if (el == ElementId.ELEM_FUNCTION.id()) {
			docroot = new ClangFunction(null, hfunc);
		}
		else {
			docroot = new ClangTokenGroup(null);
		}

		docroot.decode(decoder, hfunc);
		decoder.closeElement(el);
		return docroot;
	}
}
