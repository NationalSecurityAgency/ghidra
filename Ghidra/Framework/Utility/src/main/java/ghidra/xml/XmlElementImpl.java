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
package ghidra.xml;

import java.util.*;

public class XmlElementImpl implements XmlElement {
	private final String name;
	private final int level;
	private final LinkedHashMap<String, String> attributes;
	private final String text;
	private final boolean isStart;
	private final boolean isEnd;
	private final boolean isContent;
	private final int columnNumber;
	private final int lineNumber;

	public XmlElementImpl(boolean isStart, boolean isEnd, String name, int level,
			LinkedHashMap<String, String> attributes, String text, int columnNumber,
			int lineNumber) {
		if (isStart && isEnd) {
			throw new XmlException(
				"empty elements must be split into separate start and end elements (see splitEmptyElement)");
		}
		this.name = name;
		this.level = level;
		this.attributes = attributes;
		this.text = text;
		this.isStart = isStart;
		this.isEnd = isEnd;
		this.isContent = !isStart && !isEnd;
		this.columnNumber = columnNumber;
		this.lineNumber = lineNumber;
	}

	@Override
	public int getColumnNumber() {
		return columnNumber;
	}

	@Override
	public int getLineNumber() {
		return lineNumber;
	}

	@Override
	public boolean hasAttribute(String key) {
		if (attributes == null) {
			return false;
		}
		return attributes.containsKey(key);
	}

	@Override
	public String getAttribute(String key) {
		if (attributes == null) {
			return null;
		}
		return attributes.get(key);
	}

	@Override
	public LinkedHashMap<String, String> getAttributes() {
		return attributes == null ? null : new LinkedHashMap<String, String>(attributes);
	}

	@Override
	public Iterator<Map.Entry<String, String>> getAttributeIterator() {
		if (attributes == null) {
			return Collections.emptyIterator();
		}
		return attributes.entrySet().iterator();
	}

	@Override
	public void setAttribute(String key, String value) {
		attributes.put(key, value);
	}

	@Override
	public int getLevel() {
		return level;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getText() {
		return text;
	}

	@Override
	public boolean isContent() {
		return isContent;
	}

	@Override
	public boolean isEnd() {
		return isEnd;
	}

	@Override
	public boolean isStart() {
		return isStart;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();

		if (isContent) {
			if (text == null) {
				sb.append("(null)");
			}
			else {
				sb.append(text.replaceAll("\\\n", "\\\\n"));
			}
		}
		else if (isStart) {
			sb.append('<');
			sb.append(name);
			sb.append('(');
			sb.append(level);
			sb.append(')');
			String sep = " ";
			if (attributes != null) {
				for (Map.Entry<String, String> attribute : attributes.entrySet()) {
					sb.append(sep);
					sb.append(attribute.getKey());
					sb.append("=\"");
					sb.append(attribute.getValue());
					sb.append('"');
				}
			}
			sb.append('>');
		}
		else if (isEnd) {
			if (text == null) {
				sb.append("(null)");
			}
			else {
				sb.append(text.replaceAll("\\\n", "\\\\n"));
			}
			sb.append("</");
			sb.append(name);
			sb.append('(');
			sb.append(level);
			sb.append(')');
			sb.append('>');
		}

		sb.append(" @(");
		sb.append(lineNumber);
		sb.append(":");
		sb.append(columnNumber);
		sb.append(")");

		return sb.toString();
	}

	public static XmlElement[] splitEmptyElement(final XmlElementImpl element) {
		XmlElement[] result;
		if (element.isStart() && element.isEnd()) {
			result = new XmlElement[] {
				new XmlElementImpl(true, false, element.getName(), element.getLevel(),
					element.getAttributes(), null, element.getColumnNumber(),
					element.getLineNumber()),
				new XmlElementImpl(false, true, element.getName(), element.getLevel(), null, "",
					element.getColumnNumber(), element.getLineNumber()) };
		}
		else {
			result = new XmlElement[] { element };
		}
		return result;
	}

	@Override
	/**
	 * Checks that the element is a starting element and also that its name matches the passed 
	 * string.
	 * 
	 * @param string element name to check for a match.
	 * @return boolean 
	 */
	public boolean isStart(String string) {
		return this.isStart && this.name.equals(string);
	}
}
