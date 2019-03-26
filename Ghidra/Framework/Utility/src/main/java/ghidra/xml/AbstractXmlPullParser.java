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
package ghidra.xml;

public abstract class AbstractXmlPullParser implements XmlPullParser {

	public XmlElement end() {
		if (!hasNext()) {
			throw new XmlException("at EOF but expected end element");
		}
		XmlElement next = next();
		if (!next.isEnd()) {
			throw new XmlException("got " + (next.isStart() ? "start" : "content") +
				"element but expected end element");
		}
		return next;
	}

	public XmlElement end(XmlElement element) {
		String name = element.getName();
		if (!hasNext()) {
			throw new XmlException("at EOF but expected end element " + name);
		}
		XmlElement next = next();
		if (!name.equals(next.getName())) {
			throw new XmlException("got element " + next.getName() + " but expected end element " +
				name);
		}
		if (!next.isEnd()) {
			throw new XmlException("got " + (next.isStart() ? "start" : "content") +
				"element but expected end element " + name);
		}
		return next;
	}

	public int getColumnNumber() {
		if (hasNext()) {
			return peek().getColumnNumber();
		}
		return -1;
	}

	public int getCurrentLevel() {
		if (hasNext()) {
			return peek().getLevel();
		}
		return -1;
	}

	public int getLineNumber() {
		if (hasNext()) {
			return peek().getLineNumber();
		}
		return -1;
	}

	private static String collapse(String... s) {
		StringBuilder sb = new StringBuilder();
		if (s == null) {
			sb.append("(null)");
		}
		else {
			String sep = "";
			sb.append("[ ");
			for (String t : s) {
				sb.append(sep);
				sb.append(t);
				sep = ", ";
			}
			sb.append(" ]");
		}
		return sb.toString();
	}

	public XmlElement start(String... names) {
		if (!hasNext()) {
			throw new XmlException("at EOF but expected start element " + collapse(names));
		}
		XmlElement next = next();
		if (!next.isStart()) {
			throw new XmlException("got " + (next.isEnd() ? "end" : "content") +
				"element but expected start element " + collapse(names));
		}
		boolean found = names.length == 0;
		for (String name : names) {
			if (name.equals(next.getName())) {
				found = true;
				break;
			}
		}
		if (!found) {
			throw new XmlException("got element " + next.getName() +
				" but expected start element " + collapse(names));
		}
		return next;
	}

	public XmlElement softStart(String... names) {
		if (!hasNext()) {
			throw new XmlException("at EOF but expected soft start element " + collapse(names));
		}
		XmlElement peek = peek();
		if (!peek.isStart()) {
			return null;
		}
		boolean found = names.length == 0;
		for (String name : names) {
			if (name.equals(peek.getName())) {
				found = true;
				break;
			}
		}
		if (!found) {
			return null;
		}
		return next();
	}

	public int discardSubTree() {
		return discardSubTree(peek());
	}

	public int discardSubTree(XmlElement element) {
		if (element == peek()) {
			// we're being asked to skip the entire subtree starting from the front of the queue
			if (element.isStart()) {
				String elementName = element.getName();
				int elementLevel = element.getLevel();
				XmlElement next = next();
				int count = 1;
				while (!(next.isEnd() && next.getLevel() == elementLevel && next.getName().equals(
					elementName))) {
					next = next();
					++count;
				}
				return count;
			}
			// the front of the queue is a content element or an end element...so only
			// discard it
			next();
			return 1;
		}
		// we were provided with an arbitrary prior element which will be used as the "start"
		// element...now we try to skip until past the matching end element
		String elementName = element.getName();
		int elementLevel = element.getLevel();
		XmlElement peek = peek();
		int peekLevel = peek.getLevel();
		if (peekLevel < elementLevel) {
			// the "start" element was a child of a prior sibling of the front of the queue
			// so that ship has sailed (no skipping, just return)
			return 0;
		}
		else if (peekLevel == elementLevel) {
			// the "start" element is the same level as the front of the queue
			if (element.isStart() && peek.isEnd() && element.getName().equals(peek.getName())) {
				// hey, the "start" *is* the actual start, and the front of the queue
				// is the actual end (presumably).  So pop it and return...
				next();
				return 1;
			}
			// looks like the front of the queue is a sibling.  Don't skip anything,
			// just return
			return 0;
		}
		else {
			// the "start" is an ancestor of the front of the queue.  Pop stuff off until
			// we get past the end element.  Note that this could just fly off the end of the
			// XML file if you hand in a bogus element (although that can probably happen
			// all over the place)
			XmlElement next = next();
			int count = 1;
			while (!(next.isEnd() && next.getLevel() == elementLevel && next.getName().equals(
				elementName))) {
				next = next();
				++count;
			}
			return count;
		}
	}

	public int discardSubTree(String elementName) {
		XmlElement start = start(elementName);
		return discardSubTree(start) + 1;
	}
}
