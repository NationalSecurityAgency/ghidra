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

import ghidra.app.decompiler.ClangFunction;
import ghidra.app.decompiler.ClangToken;
import ghidra.program.model.listing.Function;

// TODO better name:  TokenHighlight
public class HighlightToken {

	private ClangToken token;
	private Color color;

	public HighlightToken(ClangToken token, Color color) {
		this.token = token;
		this.color = color;
	}

	public ClangToken getToken() {
		return token;
	}

	public Color getColor() {
		return color;
	}

	public Function getFunction() {
		if (token == null) {
			return null;
		}
		ClangFunction clangFunc = token.getClangFunction();
		if (clangFunc == null) {
			return null;
		}
		return clangFunc.getHighFunction().getFunction();
	}

	@Override
	public String toString() {
		return token.toString() + "; color=" + color;
	}
}
