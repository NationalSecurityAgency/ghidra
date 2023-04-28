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
package ghidra.app.decompiler.component;

import java.util.List;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.FieldHighlightFactory;
import ghidra.app.decompiler.ClangToken;

public class ClangTextField extends WrappingVerticalLayoutTextField {

	private List<ClangToken> tokenList;
	private final int lineNumber;

	private static FieldElement createSingleLineElement(FieldElement[] textElements) {
		return new CompositeFieldElement(textElements);
	}

	public ClangTextField(List<ClangToken> tokenList, FieldElement[] fieldElements, int x,
			int lineNumber, int width, FieldHighlightFactory hlFactory) {
		super(createSingleLineElement(fieldElements), x, width - x, 30, hlFactory, false);
		this.tokenList = tokenList;
		this.lineNumber = lineNumber;
	}

	/**
	 * Gets the C language token at the indicated location.
	 * 
	 * @param loc the field location
	 * @return the token
	 */
	public ClangToken getToken(FieldLocation loc) {
		if (loc == null) {
			return null;
		}

		FieldElement clickedObject = getClickedObject(loc);
		if (clickedObject instanceof ClangFieldElement) {
			ClangFieldElement element = (ClangFieldElement) clickedObject;
			return element.getToken();
		}

		int index = getTokenIndex(loc);
		return tokenList.get(index);
	}

	/**
	 * Returns the token that is completely after the token that contains the given column location.
	 * In this case, 'contains' means any position <b>inside</b> of a token, but not at the
	 * beginning. So, if the column location is in the middle of a token, it will return the index
	 * of next token. But if the column location is at the beginning (just before the start) of a
	 * token, it will return the index of that token.
	 *
	 * @param location containing the column at which to beginning searching
	 * @return the next token starting after the given column
	 */
	int getNextTokenIndexStartingAfter(FieldLocation location) {

		int n = 0;
		for (int i = 0; i < tokenList.size(); i++) {

			if (location.col == n) {
				// the start of the token means we are on the next token (just as with the
				// current token)
				return i;
			}

			ClangToken token = tokenList.get(i);
			int length = n + token.getText().length();
			if (length >= location.col) {
				return i + 1; // this will be an invalid index when at the end of the list
			}
			n = length;
		}

		return tokenList.size(); // at the end; return the size, as it is used 'exclusive'ly
	}

	int getTokenIndex(FieldLocation location) {

		int n = 0;
		for (int i = 0; i < tokenList.size(); i++) {

			if (location.col == n) {
				// this is needed because tokens can have zero-width so
				return i;
			}

			ClangToken token = tokenList.get(i);
			int length = n + token.getText().length();
			if (length > location.col) {
				return i;
			}
			n = length;
		}

		return tokenList.size() - 1; // at the end--return the last token index
	}

	FieldElement getClickedObject(FieldLocation fieldLocation) {
		return getFieldElement(fieldLocation.row, fieldLocation.col);
	}

	List<ClangToken> getTokens() {
		return tokenList;
	}

	public int getLineNumber() {
		return lineNumber;
	}
}
