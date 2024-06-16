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
package ghidra.util.html;

import java.util.*;

import ghidra.util.HTMLUtilities;

public class HTMLElement extends ArrayList<Object> {
	private String name;
	private Map<String, String> attributes = new HashMap<>();

	public HTMLElement(String name) {
		this.name = name;
	}

	public String getAttribute(String key) {
		return attributes.get(key);
	}

	public String putAttribute(String key, String value) {
		return attributes.put(key, value);
	}

	public String removeAttribute(String key) {
		return attributes.remove(key);
	}

	public HTMLElement addElement(String elementName) {
		HTMLElement newElement = new HTMLElement(elementName);
		add(newElement);
		return newElement;
	}

	public void addHTMLContent(String htmlContent) {
		HTMLContent html = new HTMLContent(htmlContent);
		add(html);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder("<" + name);
		for (Map.Entry<String, String> ent : attributes.entrySet()) {
			sb.append(" ");
			sb.append(ent.getKey());
			sb.append("=\"");
			sb.append(ent.getValue());
			sb.append("\"");
		}
		sb.append(">");
		for (Object obj : this) {
			if (obj == null) {
				sb.append("(null)");
			}
			else if (obj instanceof HTMLElement) {
				sb.append(obj.toString());
			}
			else if (obj instanceof HTMLContent) {
				sb.append(obj.toString());
			}
			else {
				sb.append(HTMLUtilities.friendlyEncodeHTML(obj.toString()));
			}
		}
		sb.append("</" + name + ">");
		return sb.toString();
	}

	private class HTMLContent {
		private String content;

		HTMLContent(String content) {
			this.content = content;
		}

		@Override
		public String toString() {
			return content;
		}
	}
}
