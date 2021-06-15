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

import java.io.PrintWriter;
import java.nio.file.Path;
import java.util.*;

import help.validator.LinkDatabase;

/**
 * A Table of Contents entry, which is represented in the help output as an xml tag.
 */
public abstract class TOCItem {

	//@formatter:off
	protected static final String[] INDENTS = {
		"",
		"\t",
		"\t\t",
		"\t\t\t",
		"\t\t\t\t",
		"\t\t\t\t\t",
		"\t\t\t\t\t\t",
		"\t\t\t\t\t\t\t",
		"\t\t\t\t\t\t\t\t"
	};
	//@formatter:on

	private static final String TOC_TAG_NAME = "tocitem";
	private static final String TEXT = "text";
	private static final String TARGET = "target";
	private static final String MERGE_TYPE_ATTRIBUTE = "mergetype=\"javax.help.SortMerge\"";
	protected static final String TOC_ITEM_CLOSE_TAG = "</tocitem>";

	private String sortPreference;
	private final String IDAttribute;
	protected String textAttribute;
	protected String targetAttribute;
	private final Path sourceFile;
	protected TOCItem parentItem;
	private Set<TOCItem> children = new HashSet<TOCItem>();
	private int lineNumber;

	public TOCItem(TOCItem parentItem, Path sourceFile, String ID, int lineNumber) {
		this(parentItem, sourceFile, ID, null, null, null, lineNumber);
	}

	TOCItem(TOCItem parentItem, Path sourceFile, String ID, String text, String target,
			String sortPreference, int lineNumber) {
		this.parentItem = parentItem;
		this.sourceFile = sourceFile;
		this.IDAttribute = Objects.requireNonNull(ID,
			"TOC Tag missing 'id' attribute: " + sourceFile + ":" + lineNumber);
		this.textAttribute = text;

		this.targetAttribute = target;
		if (sortPreference != null) {
			this.sortPreference = sortPreference.toLowerCase();
		}
		else {
			this.sortPreference = (textAttribute == null) ? "" : textAttribute.toLowerCase();
		}
		this.lineNumber = lineNumber;

		if (parentItem != null) {
			parentItem.addChild(this);
		}
	}

	public abstract boolean validate(LinkDatabase linkDatabase);

	protected int childCount() {
		return children.size();
	}

	protected void addChild(TOCItem child) {
		if (this == child) {
			throw new IllegalArgumentException("TOCItem cannot be added to itself");
		}

		children.add(child);
	}

	protected void removeChild(TOCItem child) {
		children.remove(child);
	}

	protected Collection<TOCItem> getChildren() {
		return Collections.unmodifiableCollection(children);
	}

	public String getSortPreference() {
		return sortPreference;
	}

	public int getLineNumber() {
		return lineNumber;
	}

	public TOCItem getParent() {
		return parentItem;
	}

	public Path getSourceFile() {
		return sourceFile;
	}

	public String getIDAttribute() {
		return IDAttribute;
	}

	public String getTextAttribute() {
		return textAttribute;
	}

	public String getTargetAttribute() {
		return targetAttribute;
	}

	protected String printChildren() {
		return printChildren(1);
	}

	protected String printChildren(int tabCount) {
		StringBuilder buildy = new StringBuilder();
		for (TOCItem item : children) {
			buildy.append(INDENTS[tabCount]).append(item.toString());
			buildy.append('\n').append(item.printChildren(tabCount + 1));
		}
		return buildy.toString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((IDAttribute == null) ? 0 : IDAttribute.hashCode());
		result = prime * result + ((sortPreference == null) ? 0 : sortPreference.hashCode());
		result = prime * result + ((sourceFile == null) ? 0 : sourceFile.hashCode());
		result = prime * result + ((targetAttribute == null) ? 0 : targetAttribute.hashCode());
		result = prime * result + ((textAttribute == null) ? 0 : textAttribute.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		TOCItem other = (TOCItem) obj;
		if (IDAttribute == null) {
			if (other.IDAttribute != null) {
				return false;
			}
		}
		else if (!IDAttribute.equals(other.IDAttribute)) {
			return false;
		}
		if (sortPreference == null) {
			if (other.sortPreference != null) {
				return false;
			}
		}
		else if (!sortPreference.equals(other.sortPreference)) {
			return false;
		}
		if (sourceFile == null) {
			if (other.sourceFile != null) {
				return false;
			}
		}
		else if (!sourceFile.equals(other.sourceFile)) {
			return false;
		}
		if (targetAttribute == null) {
			if (other.targetAttribute != null) {
				return false;
			}
		}
		else if (!targetAttribute.equals(other.targetAttribute)) {
			return false;
		}
		if (textAttribute == null) {
			if (other.textAttribute != null) {
				return false;
			}
		}
		else if (!textAttribute.equals(other.textAttribute)) {
			return false;
		}
		return true;
	}

	/**
	 * True if the two items are the same, except that they come from a different source file.
	 * @param other the other item
	 * @return true if equivalent
	 */
	public boolean isEquivalent(TOCItem other) {
		if (this == other) {
			return true;
		}
		if (other == null) {
			return false;
		}
		if (getClass() != other.getClass()) {
			return false;
		}

		if (IDAttribute == null) {
			if (other.IDAttribute != null) {
				return false;
			}
		}
		else if (!IDAttribute.equals(other.IDAttribute)) {
			return false;
		}
		if (sortPreference == null) {
			if (other.sortPreference != null) {
				return false;
			}
		}
		else if (!sortPreference.equals(other.sortPreference)) {
			return false;
		}

		if (targetAttribute == null) {
			if (other.targetAttribute != null) {
				return false;
			}
		}
		else if (!targetAttribute.equals(other.targetAttribute)) {
			return false;
		}
		if (textAttribute == null) {
			if (other.textAttribute != null) {
				return false;
			}
		}
		else if (!textAttribute.equals(other.textAttribute)) {
			return false;
		}
		return true;
	}

	public void writeContents(LinkDatabase linkDatabase, PrintWriter writer, int indentLevel) {
		// if I have no children, then just write out a simple tag
		if (children.size() == 0) {
			writer.println(generateTOCItemTag(linkDatabase, true, indentLevel));
		}

		// otherwise, write out my opening tag, my children's data and then my closing tag
		else {
			writer.println(generateTOCItemTag(linkDatabase, false, indentLevel));
			int nextIndentLevel = indentLevel + 1;
			for (TOCItem item : children) {
				item.writeContents(linkDatabase, writer, nextIndentLevel);
			}
			writer.println(INDENTS[indentLevel] + TOC_ITEM_CLOSE_TAG);
		}
	}

	public String generateTOCItemTag(LinkDatabase linkDatabase, boolean isInlineTag,
			int indentLevel) {
		StringBuilder buildy = new StringBuilder();
		buildy.append(INDENTS[indentLevel]);
		buildy.append('<').append(TOC_TAG_NAME).append(' ');

		// text attribute
		// NOTE: we do not put our display text in this attribute.  This is because JavaHelp uses
		//       this attribute for sorting.  We want to separate sorting from display, so we
		//       manipulate the JavaHelp software by setting this attribute the desired sort value.
		//       We have overridden JavaHelp to use a custom renderer that will paint the display
		//       text with the attribute we set below.
		buildy.append(TEXT).append("=\"").append(sortPreference).append("\" ");

		// target attribute
		if (targetAttribute != null) {
			// this can be null if no html file is specified for a TOC item (like a parent folder)
			String ID = linkDatabase.getIDForLink(targetAttribute);
			if (ID == null) {
				ID = targetAttribute; // this can happen for things we do not map, like raw URLs
			}
			buildy.append(TARGET).append("=\"").append(ID).append("\" ");
		}

		// mergetype attribute
		buildy.append(MERGE_TYPE_ATTRIBUTE);

		// our custom display text attribute
		buildy.append(' ').append("display").append("=\"").append(textAttribute).append("\"");

		// our custom toc id attribute
		buildy.append(' ').append("toc_id").append("=\"").append(IDAttribute).append("\"");

		if (isInlineTag) {
			buildy.append(" />");
		}
		else {
			buildy.append(">");
		}

		return buildy.toString();
	}

	public String generateEndTag(int indentLevel) {
		return INDENTS[indentLevel] + TOC_ITEM_CLOSE_TAG;
	}

	public void writeContents(LinkDatabase linkDatabase, PrintWriter writer) {
		writeContents(linkDatabase, writer, 0);
	}
}
