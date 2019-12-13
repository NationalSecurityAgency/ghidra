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

import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.decompiler.ClangSyntaxToken;
import ghidra.app.decompiler.ClangToken;

/**
 * Class to handle location based highlights for a decompiled function.
 */
public class LocationClangHighlightController extends ClangHighlightController {

	@Override
	public void fieldLocationChanged(FieldLocation location, Field field, EventTrigger trigger) {

		clearPrimaryHighlights();

		if (!(field instanceof ClangTextField)) {
			return;
		}

		ClangToken tok = ((ClangTextField) field).getToken(location);
		if (tok == null) {
			return;
		}

		addPrimaryHighlight(tok, defaultHighlightColor);
		if (tok instanceof ClangSyntaxToken) {
			addPrimaryHighlightToTokensForParenthesis((ClangSyntaxToken) tok, defaultParenColor);
			addHighlightBrace((ClangSyntaxToken) tok, defaultParenColor);
		}
	}
}
