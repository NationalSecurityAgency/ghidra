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

import java.util.Objects;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;

// a key that allows us to equate tokens that are not the same instance
class TokenKey {
	private ClangToken token;

	TokenKey(ClangToken token) {
		this.token = Objects.requireNonNull(token);
	}

	public TokenKey(HighlightToken t) {
		this(t.getToken());
	}

	@Override
	public int hashCode() {
		String text = token.getText();
		return text == null ? 0 : text.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}

		if (getClass() != obj.getClass()) {
			return false;
		}

		ClangToken otherToken = ((TokenKey) obj).token;
		if (token.getClass() != otherToken.getClass()) {
			return false;
		}

		if (!Objects.equals(token.getText(), otherToken.getText())) {
			return false;
		}

		ClangLine lineParent = token.getLineParent();
		ClangLine otherLineParent = otherToken.getLineParent();
		if (!sameLines(lineParent, otherLineParent)) {
			return false;
		}
		if (lineParent == null) {
			return false;
		}

		int positionInLine = lineParent.indexOfToken(token);
		int otherPositionInLine = otherLineParent.indexOfToken(otherToken);
		return positionInLine == otherPositionInLine;
	}

	private boolean sameLines(ClangLine l1, ClangLine l2) {

		if (l1 == null) {
			if (l2 != null) {
				return false;
			}
			return true;
		}
		else if (l2 == null) {
			return false;
		}

		return l1.getLineNumber() == l2.getLineNumber();
	}

	@Override
	public String toString() {
		return token.toString();
	}
}
