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

import java.util.*;

/**
 * 
 *
 * A line of C code. This is an independent grouping
 * of C tokens from the statement, vardecl retype groups
 */
public class ClangLine {
	private int indent_level;
	private ArrayList<ClangToken> tokens;
	private int lineNumber;

	public ClangLine(int lineNumber, int indent) {
		tokens = new ArrayList<>();
		indent_level = indent;
		this.lineNumber = lineNumber;
	}

	public String getIndentString() {
		StringBuffer buffer = new StringBuffer();
		for (int i = 0; i < indent_level; i++) {
			buffer.append(PrettyPrinter.INDENT_STRING);
		}
		return buffer.toString();
	}

	public int getIndent() {
		return indent_level;
	}

	public void addToken(ClangToken tok) {
		tokens.add(tok);
		tok.setLineParent(this);
	}

	public ArrayList<ClangToken> getAllTokens() {
		return tokens;
	}

	public int getNumTokens() {
		return tokens.size();
	}

	public int getLineNumber() {
		return lineNumber;
	}

	public ClangToken getToken(int i) {
		return tokens.get(i);
	}

	public int indexOfToken(ClangToken token) {
		return tokens.indexOf(token);
	}

	public String toDebugString(List<ClangToken> calloutTokens) {

		return toDebugString(calloutTokens, "[", "]");
	}

	public String toDebugString(List<ClangToken> calloutTokens, String start, String end) {

		if (calloutTokens == null) {
			calloutTokens = Collections.emptyList();
		}

		StringBuilder buffy = new StringBuilder(getLineNumber() + ": ");
		for (ClangToken token : tokens) {

			boolean isCallout = calloutTokens.contains(token);
			if (isCallout) {
				buffy.append(start);
			}

			buffy.append(token.getText());

			if (isCallout) {
				buffy.append(end);
			}

		}

		return buffy.toString();
	}

	@Override
	public String toString() {
		return toDebugString(Collections.emptyList());
	}
}
