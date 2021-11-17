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

import java.awt.Color;

import ghidra.app.decompiler.CTokenHighlightMatcher;
import ghidra.app.decompiler.ClangToken;

/**
 * Matcher used for secondary highlights in the Decompiler.
 */
class NameTokenMatcher implements CTokenHighlightMatcher {

	private ColorProvider colorProvider;
	private String name;

	NameTokenMatcher(String name, ColorProvider colorProvider) {
		this.name = name;
		this.colorProvider = colorProvider;
	}

	@Override
	public Color getTokenHighlight(ClangToken token) {
		if (name.equals(token.getText())) {
			return colorProvider.getColor(token);
		}
		return null;
	}
}
