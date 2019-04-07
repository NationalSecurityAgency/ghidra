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
package ghidra.app.util.html;

import ghidra.util.HTMLUtilities;

public class CompletelyDifferentHTMLDataTypeRepresentationWrapper
		extends HTMLDataTypeRepresentation {

	CompletelyDifferentHTMLDataTypeRepresentationWrapper(
			HTMLDataTypeRepresentation wrappedRepresentation) {
		super(wrappedRepresentation.originalHTMLData);
	}

	@Override // overridden to just wrap all text in a red font
	public String getHTMLString() {
		return HTML_OPEN + HTMLUtilities.colorString(DIFF_COLOR, super.getHTMLContentString()) +
			HTML_CLOSE;
	}

	@Override
	public String getHTMLContentString() {
		return HTMLUtilities.colorString(DIFF_COLOR, super.getHTMLContentString());
	}

	@Override
	public HTMLDataTypeRepresentation[] diff(HTMLDataTypeRepresentation otherRepresentation) {
		if (!(otherRepresentation instanceof CompletelyDifferentHTMLDataTypeRepresentationWrapper)) {
			return new HTMLDataTypeRepresentation[] { this,
				new CompletelyDifferentHTMLDataTypeRepresentationWrapper(otherRepresentation) };
		}

		// this is already completely different, so no work needs to be done
		return new HTMLDataTypeRepresentation[] { this, otherRepresentation };
	}

}
