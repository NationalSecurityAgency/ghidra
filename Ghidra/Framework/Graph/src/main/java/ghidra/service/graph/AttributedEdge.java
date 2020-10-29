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
package ghidra.service.graph;

import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.apache.commons.text.StringEscapeUtils;

/**
 * Generic directed graph edge implementation
 */
public class AttributedEdge extends Attributed {
	private final String id;

	/**
	 * Cache of the edge label parsed as html
	 */
	private String htmlString;

	/**
	 * Constructs a new GhidraEdge
	 * @param id the unique id for the edge
	 */
	public AttributedEdge(String id) {
		this.id = id;
	}

	@Override
	public String toString() {
		return id;
	}

	/**
	 * The html representation of the key/values for this edge
	 * @return html formatted label for the edge
	 */
	public String getHtmlString() {
		if (htmlString != null) {
			return htmlString;
		}

		Set<Entry<String, String>> entries = entrySet();
		if (entries.isEmpty()) {
			return ""; // empty so tooltip clients can handle empty data
		}

		StringBuilder buf = new StringBuilder("<html>");
		for (Map.Entry<String, String> entry : entries) {
			buf.append(entry.getKey());
			buf.append(":");
			buf.append(StringEscapeUtils.escapeHtml4(entry.getValue()));
			buf.append("<br>");
		}
		htmlString = buf.toString();
		return htmlString;
	}

	/**
	 * Returns the id for this edge
	 * @return the id for this edge
	 */
	public String getId() {
		return id;
	}

	@Override
	public int hashCode() {
		return id.hashCode();
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
		AttributedEdge other = (AttributedEdge) obj;
		return id.equals(other.id);
	}
}
