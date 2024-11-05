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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.IdentityNameTransformer;
import ghidra.program.model.symbol.NameTransformer;
import ghidra.util.StringUtilities;

/**
 * This class is used to convert a C/C++ language token group into readable C/C++ code.
 */
public class PrettyPrinter {

	private final static NameTransformer IDENTITY = new IdentityNameTransformer();

	public final static String INDENT_STRING = " ";

	private Function function;
	private ClangTokenGroup tokgroup;
	private List<ClangLine> lines = new ArrayList<>();
	private NameTransformer transformer;

	/**
	 * Constructs a new pretty printer using the specified C language token group.
	 * The printer takes a NameTransformer that will be applied to symbols, which can replace
	 * illegal characters in the symbol name for instance. A null indicates no transform is applied.
	 * @param function is the function to be printed
	 * @param tokgroup the C language token group
	 * @param transformer the transformer to apply to symbols
	 */
	public PrettyPrinter(Function function, ClangTokenGroup tokgroup, NameTransformer transformer) {
		this.function = function;
		this.tokgroup = tokgroup;
		this.transformer = transformer != null ? transformer : IDENTITY;
		flattenLines();
		padEmptyLines();
	}

	private void padEmptyLines() {
		for (ClangLine line : lines) {
			List<ClangToken> tokenList = line.getAllTokens();
			if (tokenList.size() == 0) {
				ClangToken spacer = ClangToken.buildSpacer(null, line.getIndent(), INDENT_STRING);
				spacer.setLineParent(line);
				tokenList.add(0, spacer);
			}
		}
	}

	public Function getFunction() {
		return function;
	}

	/**
	 * Returns a list of the C language lines contained in the C language token group.
	 * @return a list of the C language lines
	 */
	public List<ClangLine> getLines() {
		return lines;
	}

	/**
	 * Prints the C language token group into a string of C code.
	 * @return a string of readable C code
	 */
	public DecompiledFunction print() {
		StringBuilder buff = new StringBuilder();
		for (ClangLine line : lines) {
			getText(buff, line, transformer);
			buff.append(StringUtilities.LINE_SEPARATOR);
		}
		return new DecompiledFunction(findSignature(), buff.toString());
	}

	private static void getText(StringBuilder buff, ClangLine line, NameTransformer transformer) {
		buff.append(line.getIndentString());
		List<ClangToken> tokens = line.getAllTokens();

		for (ClangToken token : tokens) {
			boolean isToken2Clean = token instanceof ClangFuncNameToken ||
				token instanceof ClangVariableToken || token instanceof ClangTypeToken ||
				token instanceof ClangFieldToken || token instanceof ClangLabelToken;

			//do not clean constant variable tokens
			if (isToken2Clean && token.getSyntaxType() == ClangToken.CONST_COLOR) {
				isToken2Clean = false;
			}

			String tokenText = token.getText();
			if (isToken2Clean) {
				tokenText = transformer.simplify(tokenText);
			}
			buff.append(tokenText);
		}
	}

	/**
	 * Returns the text of the given line as seen in the UI.
	 * @param line the line
	 * @return the text
	 */
	public static String getText(ClangLine line) {
		StringBuilder buff = new StringBuilder();
		getText(buff, line, IDENTITY);
		return buff.toString();
	}

	private String findSignature() {
		int nChildren = tokgroup.numChildren();
		for (int i = 0; i < nChildren; ++i) {
			ClangNode node = tokgroup.Child(i);
			if (node instanceof ClangFuncProto) {
				return node.toString() + ";";
			}
		}
		return null;
	}

	private void flattenLines() {
		lines = DecompilerUtils.toLines(tokgroup);
	}
}
