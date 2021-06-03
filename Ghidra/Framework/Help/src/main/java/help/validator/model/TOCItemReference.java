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
package help.validator.model;

import help.validator.LinkDatabase;

import java.nio.file.Path;

/**
 * A representation of the {@literal <tocref>} tag, which is a way to reference a TOC item entry in 
 * a TOC_Source.xml file other than the one in which the reference lives.
 */
public class TOCItemReference extends TOCItem implements Comparable<TOCItemReference> {

	public TOCItemReference(TOCItem parentItem, Path sourceTOCFile, String ID, int lineNumber) {
		super(parentItem, sourceTOCFile, ID, lineNumber);
	}

	@Override
	public boolean validate(LinkDatabase linkDatabase) {
		TOCItemDefinition definition = linkDatabase.getTOCDefinition(this);
		if (definition != null) {
			return true;
		}

		TOCItemExternal external = linkDatabase.getTOCExternal(this);
		if (external != null) {
			return true;
		}

		return false;
	}

	/** Overridden, as references cannot have targets, only their definitions */
	@Override
	public String getTargetAttribute() {
		throw new IllegalStateException("TOC reference item has not been validated!: " + this);
	}

	/** Overridden, as if we get called, then something is in an invalid state, so generate special output */
	@Override
	public String generateTOCItemTag(LinkDatabase linkDatabase, boolean isInlineTag, int indentLevel) {
		String indent = INDENTS[indentLevel];

		StringBuilder buildy = new StringBuilder();
		buildy.append(indent).append("<!-- WARNING: Unresolved reference ID\n");
		buildy.append(indent).append('\t').append(generateXMLString()).append("\n");
		buildy.append(indent).append("-->");
		return buildy.toString();
	}

	@Override
	public int compareTo(TOCItemReference other) {
		if (other == null) {
			return 1;
		}

		int fileComparison = getSourceFile().compareTo(other.getSourceFile());
		if (fileComparison != 0) {
			return fileComparison;
		}
		return getIDAttribute().compareTo(other.getIDAttribute());
	}

	@Override
	public String toString() {
		return generateXMLString() + "\n\t[source file=\"" + getSourceFile() + "\" (line:" +
			getLineNumber() + ")]";
	}

	private String generateXMLString() {
		return "<" + GhidraTOCFile.TOC_ITEM_REFERENCE + " id=\"" + getIDAttribute() + "\"/>";
	}
}
