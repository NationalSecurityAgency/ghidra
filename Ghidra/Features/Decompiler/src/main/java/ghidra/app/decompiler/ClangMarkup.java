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
/*
 * Created on Jun 18, 2003
 *
 * To change the template for this generated file go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
package ghidra.app.decompiler;

import ghidra.program.model.pcode.*;

public abstract class ClangMarkup {			// Placeholder for CLANG XML identifiers

// Attribute values
	public static final String KEYWORD_COLOR = "keyword";
	public static final String COMMENT_COLOR = "comment";
	public static final String TYPE_COLOR = "type";
	public static final String FUNCNAME_COLOR = "funcname";
	public static final String VARIABLE_COLOR = "var";
	public static final String CONST_COLOR = "const";
	public static final String PARAMETER_COLOR = "param";
	public static final String GLOBAL_COLOR = "global";

	public static ClangTokenGroup buildClangTree(Decoder decoder, HighFunction hfunc)
			throws PcodeXMLException {
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
