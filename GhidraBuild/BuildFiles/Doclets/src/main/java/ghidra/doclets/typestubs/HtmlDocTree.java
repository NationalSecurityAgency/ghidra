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
package ghidra.doclets.typestubs;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.ListIterator;

import javax.lang.model.element.Element;

import com.sun.source.doctree.DocTree;
import com.sun.source.doctree.DocTreeVisitor;
import com.sun.source.doctree.EndElementTree;
import com.sun.source.doctree.StartElementTree;
import com.sun.source.doctree.TextTree;

/**
 * A {@link DocTree} for handling HTML<p/>
 *
 * This class allows for converting the HTML tags recursively in the same fashion
 * as the Javadoc tags.
 */
public final class HtmlDocTree implements DocTree {

	private final HtmlTagKind kind;
	private final StartElementTree start;
	private final EndElementTree end;
	private final List<? extends DocTree> body;

	/**
	 * Gets an {@link HtmlDocTree} for the provided {@link StartElementTree}
	 *
	 * @param converter the html converter
	 * @param start the html start
	 * @param el the element containing the documentation being processed
	 * @param it the iterator over the remaining tags
	 * @return the created {@link HtmlDocTree}
	 */
	public static HtmlDocTree getTree(HtmlConverter converter, StartElementTree start, Element el,
			ListIterator<? extends DocTree> it) {
		HtmlTagKind kind = HtmlTagKind.getKind(start);
		List<DocTree> body = new ArrayList<>();
		if (start.isSelfClosing() || HtmlTagKind.isVoidTag(kind)) {
			return new HtmlDocTree(kind, start, null, body);
		}
		while (it.hasNext()) {
			DocTree tag = it.next();
			switch (tag.getKind()) {
				case START_ELEMENT:
					if (kind.isTerminateBy((StartElementTree) tag)) {
						// hack for unclosed elements
						it.previous();
						converter.logUnterminatedHtml(el, start);
						return new HtmlDocTree(kind, start, null, body);
					}
					body.add(HtmlDocTree.getTree(converter, (StartElementTree) tag, el, it));
					break;
				case END_ELEMENT:
					if (kind.isTerminateBy((EndElementTree) tag)) {
						// hack for unclosed elements
						it.previous();
						converter.logUnterminatedHtml(el, start);
						return new HtmlDocTree(kind, start, null, body);
					}
					if (kind == HtmlTagKind.getKind((EndElementTree) tag)) {
						return new HtmlDocTree(kind, start, (EndElementTree) tag, body);
					}
					body.add(tag);
					break;
				case TEXT:
					String text = ((TextTree) tag).getBody();
					if (kind != HtmlTagKind.PRE && text.isBlank()) {
						continue;
					}
					body.add(tag);
					break;
				default:
					body.add(tag);
					break;
			}
		}
		converter.logUnterminatedHtml(el, start);
		return new HtmlDocTree(kind, start, null, body);
	}

	/**
	 * Creates a new {@link HtmlDocTree} with the provided fields
	 *
	 * @param kind the html tag kind
	 * @param start the start element
	 * @param end the optional end element
	 * @param body the html body
	 */
	private HtmlDocTree(HtmlTagKind kind, StartElementTree start, EndElementTree end,
			List<DocTree> body) {
		this.kind = kind;
		this.start = start;
		this.end = end;
		this.body = Collections.unmodifiableList(body);
	}

	@Override
	public Kind getKind() {
		// OTHER is implementation reserved
		// Since this is implementation specific, lets use it
		return Kind.OTHER;
	}

	@Override
	public <R, D> R accept(DocTreeVisitor<R, D> visitor, D data) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Gets the html body
	 *
	 * @return the html body
	 */
	public List<? extends DocTree> getBody() {
		return body;
	}

	/**
	 * Gets the html tag kind
	 *
	 * @return the html tag kind
	 */
	public HtmlTagKind getHtmlKind() {
		return kind;
	}

	/**
	 * Gets the html start element tree
	 *
	 * @return the html start element
	 */
	public StartElementTree getStartTag() {
		return start;
	}

	/**
	 * Gets the html end element tree<p/>
	 *
	 * This may be null if the html tag is a "void" tag or if the html is malformed
	 *
	 * @return the html end element or null
	 */
	public EndElementTree getEndTag() {
		return end;
	}
}
