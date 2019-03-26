/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package help.validator.model;

import help.validator.LinkDatabase;

import java.nio.file.Path;

public class TOCItemExternal extends TOCItem {

	public TOCItemExternal(TOCItem parentItem, Path tocFile, String ID, String text, String target,
			String sortPreference, int lineNumber) {
		super(parentItem, tocFile, ID, text, target, sortPreference, lineNumber);
	}

	@Override
	public boolean validate(LinkDatabase linkDatabase) {
		if (getTargetAttribute() == null) {
			return true; // no target path to validate
		}

		String ID = linkDatabase.getIDForLink(getTargetAttribute());
		if (ID != null) {
			return true; // valid help ID found
		}
		return false;
	}

	@Override
	public String generateTOCItemTag(LinkDatabase linkDatabase, boolean isInlineTag, int indentLevel) {
		return super.generateTOCItemTag(linkDatabase, isInlineTag, indentLevel);
	}

	@Override
	public String toString() {
		//@formatter:off
		return "<tocitem id=\"" + getIDAttribute() + "\"\n\t\t" +
			            "text=\"" + getTextAttribute() + "\"\n\t\t" +
			            "target=\"" + getTargetAttribute() + "\"" +
			    "/>\n\t" +
			   "\tTOC file=\"" + getSourceFile() +"\n";
		//@formatter:on
	}
}
