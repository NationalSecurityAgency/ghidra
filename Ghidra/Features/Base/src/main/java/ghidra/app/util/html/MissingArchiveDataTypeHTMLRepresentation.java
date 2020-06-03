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

import ghidra.program.model.data.SourceArchive;
import ghidra.util.HTMLUtilities;

public class MissingArchiveDataTypeHTMLRepresentation extends HTMLDataTypeRepresentation {

	public MissingArchiveDataTypeHTMLRepresentation(SourceArchive sourceArchive) {
		super(createMessge(sourceArchive));
	}

	private static String createMessge(SourceArchive sourceArchive) {
		if (sourceArchive == null) {
			return "<i>Could not find data type archive</i>";
		}
		return "<i>Could not access data type archive: " +
			HTMLUtilities.escapeHTML(sourceArchive.getName()) + "</i>";
	}

	@Override
	public HTMLDataTypeRepresentation[] diff(HTMLDataTypeRepresentation otherRepresentation) {
		if (this == otherRepresentation) {
			return new HTMLDataTypeRepresentation[] { this, this };
		}
		return new HTMLDataTypeRepresentation[] {
			new CompletelyDifferentHTMLDataTypeRepresentationWrapper(this),
			new CompletelyDifferentHTMLDataTypeRepresentationWrapper(otherRepresentation) };
	}

}
