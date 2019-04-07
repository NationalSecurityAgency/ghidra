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
import ghidra.util.StringUtilities;

/**
 * This class is used to convert a C language
 * token group into readable C code.
 */
public class PrettyPrinter {
	/**
	 * The indent string to use when printing.
	 */
	public final static String INDENT_STRING = " ";

	private Function function;
	private ClangTokenGroup tokgroup;
	private ArrayList<ClangLine> lines = new ArrayList<ClangLine>();

	/**
	 * Constructs a new pretty printer using the specified C language token group.
	 * @param tokgroup the C language token group
	 */
	public PrettyPrinter(Function function, ClangTokenGroup tokgroup) {
		this.function = function;
		this.tokgroup = tokgroup;
		flattenLines();
		padEmptyLines();
	}

    private void padEmptyLines() {
        for (ClangLine line : lines) {
			ArrayList<ClangToken> tokenList = line.getAllTokens();
			if (tokenList.size() == 0) {
				ClangToken spacer = ClangToken.buildSpacer(null, line.getIndent(), INDENT_STRING);
				spacer.setLineParent( line );
                tokenList.add(0, spacer);
			}
		}
    }

	public Function getFunction() {
		return function;
	}

	/**
	 * Returns an array list of the C language lines contained in the
	 * C language token group.
	 * @return an array list of the C language lines
	 */
	public ArrayList<ClangLine> getLines() {
		return lines;
	}

	/**
	 * Prints the C language token group
	 * into a string of C code.
	 * @param removeInvalidChars true if invalid character should be
	 * removed from functions and labels.
	 * @return a string of readable C code
	 */
	public DecompiledFunction print(boolean removeInvalidChars) {
		StringBuffer buff = new StringBuffer();

		for (ClangLine line : lines) {
			buff.append(line.getIndentString());
			List<ClangToken> tokens = line.getAllTokens();

			for (ClangToken token : tokens) {
				boolean isToken2Clean = token instanceof ClangFuncNameToken ||
										token instanceof ClangVariableToken || 
										token instanceof ClangTypeToken ||
										token instanceof ClangFieldToken || 
										token instanceof ClangLabelToken;

				//do not clean constant variable tokens
				if (isToken2Clean && token.getSyntaxType() == ClangToken.CONST_COLOR) {
					isToken2Clean = false;
				}

				if (removeInvalidChars && isToken2Clean) {
					String tokenText = token.getText();
					for (int i = 0 ; i < tokenText.length() ; ++i) {
						if (StringUtilities.isValidCLanguageChar(tokenText.charAt(i))) {
							buff.append(tokenText.charAt(i));
						}
						else {
							buff.append('_');
						}
					}
				}
				else {
					buff.append(token.getText());
				}
			}
			buff.append(StringUtilities.LINE_SEPARATOR);
		}
		return new DecompiledFunction(findSignature(), buff.toString());
	}

	private String findSignature() {
		int nChildren = tokgroup.numChildren();
		for (int i = 0 ; i < nChildren ; ++i) {
			ClangNode node = tokgroup.Child(i);
			if (node instanceof ClangFuncProto) {
				return node.toString()+";";
			}
		}
		return null;
	}

	private void flattenLines() {
		lines = DecompilerUtils.toLines(tokgroup);
	}
}
