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

import java.util.List;
import java.util.ListIterator;
import java.util.Map;

import javax.lang.model.element.Element;

import com.sun.source.doctree.DocTree;
import com.sun.source.doctree.EndElementTree;
import com.sun.source.doctree.LinkTree;
import com.sun.source.doctree.StartElementTree;
import com.sun.source.doctree.TextTree;

import jdk.javadoc.doclet.DocletEnvironment;
import jdk.javadoc.doclet.Reporter;

/**
 * Helper class for converting HTML to reStructuredText
 */
public final class HtmlConverter extends DocConverter {

	private final JavadocConverter docConverter;

	/**
	 * Creates a new {@link HtmlConverter}
	 *
	 * @param env the doclet environment
	 * @param log the log
	 */
	public HtmlConverter(DocletEnvironment env, Reporter log, JavadocConverter docConverter) {
		super(env, log);
		this.docConverter = docConverter;
	}

	@Override
	String convertTag(Element el, DocTree tag, ListIterator<? extends DocTree> it) {
		return docConverter.convertTag(el, tag, it);
	}

	/**
	 * Gets a map of the attributes in the html element
	 *
	 * @param start the start element
	 * @return the attributes map
	 */
	public Map<String, String> getAttributes(Element el, StartElementTree start) {
		return getAttributes(el, start.getAttributes());
	}

	/**
	 * Logs a warning about an unterminated html tag
	 *
	 * @param el the current element
	 * @param tag the current tag
	 */
	public void logUnterminatedHtml(Element el, StartElementTree tag) {
		try {
			logWarning(el, tag, "unterminated html tag");
		}
		catch (Throwable t) {
			t.printStackTrace();
		}
	}

	/**
	 * Converts the provided HTML to reStructuredText where possible
	 *
	 * @param tag the html
	 * @param el the element containing the html
	 * @param it the Javadoc tree iterator
	 * @return the converted string
	 */
	String convertHtml(HtmlDocTree tag, Element el, ListIterator<? extends DocTree> it) {
		StartElementTree start = tag.getStartTag();
		return switch (tag.getHtmlKind()) {
			case A -> convertAnchor(tag, el);
			case B -> "**" + convertTree(el, tag.getBody()) + "**";
			case BIG -> ""; // not in rst
			case BLOCKQUOTE -> convertBlockQuote(tag, el);
			case BR -> "\n";
			case CAPTION -> {
				logError(el, start, "<caption> outside of table");
				yield start.toString();
			}
			case CITE -> "*" + convertTree(el, tag.getBody()) + "*";
			case CODE -> "``" + convertTree(el, tag.getBody()) + "``";
			case DD -> {
				logError(el, start, "<dd> outside of list");
				yield start.toString();
			}
			case DEL -> "~~" + convertTree(el, tag.getBody()) + "~~";
			// rarely used, not bothering with id attribute
			case DFN -> "*" + convertTree(el, tag.getBody()) + "*";
			case DIV -> convertTree(el, tag.getBody()); // do nothing
			case DL -> convertDescriptionList(tag, el);
			case DT -> {
				logError(el, start, "<dt> outside of list");
				yield start.toString();
			}
			case EM -> "*" + convertTree(el, tag.getBody()) + "*";
			case H1 -> convertHeader(tag, el, '#');
			case H2 -> convertHeader(tag, el, '*');
			case H3 -> convertHeader(tag, el, '=');
			case H4 -> convertHeader(tag, el, '-');
			case H5 -> convertHeader(tag, el, '^');
			case H6 -> convertHeader(tag, el, '\'');
			case HR -> "---\n";
			case I -> "*" + convertTree(el, tag.getBody()) + "*";
			case IMG -> ""; // not supported because the images wouldn't be available
			case INS -> convertTree(el, tag.getBody()); // no underline in rst
			case LI -> {
				logError(el, start, "<li> outside of list");
				yield start.toString();
			}
			case OL -> convertOrderedList(tag, el);
			case P -> "\n";
			case PRE -> convertTree(el, tag.getBody()); // do nothing
			case SMALL -> ""; // not in rst
			case SPAN -> convertTree(el, tag.getBody()); // no colored text in rst
			case STRONG -> "**" + convertTree(el, tag.getBody()) + "**";
			case SUB -> ""; // no subscript in rst
			case SUP -> ""; // no superscript in rst
			case TABLE -> convertTable(tag, el);
			case TBODY -> {
				logError(el, start, "<tbody> outside of table");
				yield start.toString();
			}
			case TD -> {
				logError(el, start, "<td> outside of table");
				yield start.toString();
			}
			case TFOOT -> {
				logError(el, start, "<tfoot> outside of table");
				yield start.toString();
			}
			case TH -> {
				logError(el, start, "<th> outside of table");
				yield start.toString();
			}
			case THEAD -> {
				logError(el, start, "<thead> outside of table");
				yield start.toString();
			}
			case TR -> {
				logError(el, start, "<tr> outside of table");
				yield start.toString();
			}
			case TT -> "``" + convertTree(el, tag.getBody()) + "``";
			case U -> convertTree(el, tag.getBody()); // no underline in rst
			case UL -> convertUnorderedList(tag, el);
			case UNSUPPORTED -> {
				logWarning(el, start, "unsupported html tag");
				yield start.toString();
			}
			case VAR -> "*" + convertTree(el, tag.getBody()) + "*";
		};
	}

	String convertHtml(StartElementTree start, Element el, ListIterator<? extends DocTree> it) {
		HtmlDocTree tag = HtmlDocTree.getTree(this, start, el, it);
		return convertHtml(tag, el, it);
	}

	/**
	 * Converts a {@literal <blockquote>} tag
	 *
	 * @param html the html
	 * @param el the element
	 * @return the converted blockquote
	 */
	private String convertBlockQuote(HtmlDocTree html, Element el) {
		String body = convertTree(el, html.getBody());
		return body.indent(INDENT_WIDTH);
	}

	/**
	 * Converts the {@literal <H1>} ... {@literal <H6>} tags
	 *
	 * @param html the html
	 * @param el the element
	 * @param header the header character
	 * @return the converted header
	 */
	private String convertHeader(HtmlDocTree html, Element el, char header) {
		String body = convertTree(el, html.getBody());
		int length = body.length();
		StringBuilder builder = new StringBuilder();
		return builder.append('\n')
				.repeat(header, length)
				.append('\n')
				.append(body)
				.append('\n')
				.repeat(header, length)
				.append('\n')
				.toString();
	}

	/**
	 * Converts a {@literal <li>} tag
	 *
	 * @param tree the html
	 * @param el the element
	 * @return the converted list entry
	 */
	private String convertListEntry(HtmlDocTree tree, Element el) {
		StringBuilder builder = new StringBuilder();
		for (DocTree tag : tree.getBody()) {
			if (tag instanceof HtmlDocTree html) {
				switch (html.getHtmlKind()) {
					case OL: {
						String list = convertOrderedList(html, el);
						builder.append(list.indent(INDENT_WIDTH));
						break;
					}
					case UL: {
						String list = convertUnorderedList(html, el);
						builder.append(list.indent(INDENT_WIDTH));
						break;
					}
					default: {
						builder.append(convertTree(el, html.getBody()));
						break;
					}
				}
			}
			else {
				String entry = docConverter.convertTag(el, tag, null);
				builder.append(alignIndent(entry));
			}
		}
		return builder.toString();
	}

	/**
	 * Converts a description list {@literal <dl>}
	 *
	 * @param tree the html
	 * @param el the element
	 * @return the converted list
	 */
	private String convertDescriptionList(HtmlDocTree tree, Element el) {
		StringBuilder builder = new StringBuilder();
		builder.append('\n');
		for (DocTree tag : tree.getBody()) {
			if (tag instanceof HtmlDocTree html) {
				if (html.getHtmlKind() == HtmlTagKind.DT) {
					builder.append(convertTree(el, html.getBody()));
				}
				else if (html.getHtmlKind() == HtmlTagKind.DD) {
					String body = convertTree(el, html.getBody());
					builder.append(body.indent(INDENT_WIDTH))
							.append('\n');
				}
				else {
					builder.append(convertTree(el, html.getBody()));
				}
			}
			else {
				builder.append(docConverter.convertTag(el, tag, null));
			}
		}
		return builder.toString();
	}

	/**
	 * Converts an ordered list {@literal <ol>}
	 *
	 * @param tree the html
	 * @param el the element
	 * @return the converted list
	 */
	private String convertOrderedList(HtmlDocTree tree, Element el) {
		StringBuilder builder = new StringBuilder();
		int num = 1; // because #. doesn't always work like it should
		builder.append('\n');
		for (DocTree tag : tree.getBody()) {
			if (tag instanceof HtmlDocTree html) {
				if (html.getHtmlKind() == HtmlTagKind.LI) {
					builder.append(num++)
							.append(". ")
							.append(convertListEntry(html, el))
							.append('\n');
				}
				else {
					builder.append(convertTree(el, html.getBody()));
				}
			}
			else {
				builder.append(docConverter.convertTag(el, tag, null));
			}
		}
		return builder.toString();
	}

	/**
	 * Converts an unordered list {@literal <ul>}
	 *
	 * @param tree the html
	 * @param el the element
	 * @return the converted list
	 */
	private String convertUnorderedList(HtmlDocTree tree, Element el) {
		StringBuilder builder = new StringBuilder();
		builder.append('\n');
		for (DocTree tag : tree.getBody()) {
			if (tag instanceof HtmlDocTree html) {
				if (html.getHtmlKind() == HtmlTagKind.LI) {
					builder.append("* ")
							.append(convertListEntry(html, el))
							.append('\n');
				}
				else {
					builder.append(convertTree(el, html.getBody()));
				}
			}
			else {
				builder.append(docConverter.convertTag(el, tag, null));
			}
		}
		return builder.toString();
	}

	/**
	 * Converts an anchor {@literal <a id="#example">link text</a>}
	 *
	 * @param html the html
	 * @param el the element
	 * @return the converted html
	 */
	private String convertAnchor(HtmlDocTree html, Element el) {
		String label = convertTree(el, html.getBody()).stripLeading();
		Map<String, String> attrs = getAttributes(el, html.getStartTag());
		String id = attrs.get("id");
		if (id == null) {
			id = attrs.get("name");
		}
		if (id != null) {
			return "\n.. _" + id + ":\n\n" + label;
		}

		String href = attrs.get("href");
		if (href == null) {
			logWarning(el, html.getStartTag(), "skipping anchor without an id or href");
			return "";
		}
		if (href.startsWith("#")) {
			// internal
			if (label.isBlank()) {
				return href.substring(1) + '_';
			}
			return '`' + label + " <" + href.substring(1) + "_>`_";
		}

		// external
		if (label.isBlank()) {
			return '<' + href.substring(0) + '>';
		}
		return '`' + label + " <" + href + ">`_";
	}

	/**
	 * Converts the provided tree to a raw html string
	 *
	 * @param el the element
	 * @param tree the tree
	 * @return the html string
	 */
	private String getRawHtml(Element el, List<? extends DocTree> tree) {
		StringBuilder builder = new StringBuilder();
		for (DocTree tag : tree) {
			switch (tag.getKind()) {
				case START_ELEMENT:
				case END_ELEMENT:
					builder.append(tag.toString());
					break;
				case OTHER:
					if (!(tag instanceof HtmlDocTree)) {
						logError(el, tag, "Unexpected OTHER tag kind");
						return "";
					}
					HtmlDocTree html = (HtmlDocTree) tag;
					builder.append(html.getStartTag().toString())
						.append(getRawHtml(el, html.getBody()));
					EndElementTree end = html.getEndTag();
					if (end != null) {
						builder.append(end.toString());
					}
					break;
				case LINK:
				case LINK_PLAIN:
					builder.append(getRawHtml(el, ((LinkTree) tag).getLabel()));
					break;
				default:
					builder.append(docConverter.convertTag(el, tag, null));
					break;
			}
		}
		return builder.toString();
	}

	/**
	 * Converts the html tree to a raw html string
	 *
	 * @param html the html tree
	 * @param el the element
	 * @return the html
	 */
	private String getRawHtml(HtmlDocTree html, Element el) {
		StringBuilder builder = new StringBuilder();
		builder.append(html.getStartTag().toString())
			.append(getRawHtml(el, html.getBody()));
		EndElementTree end = html.getEndTag();
		if (end != null) {
			builder.append(end.toString());
		}
		return builder.toString();
	}

	/**
	 * Converts a table {@literal <table>} to reStructuredText if possible
	 *
	 * @param tree the html
	 * @param el the element
	 * @return the converted table or original html if not convertible
	 */
	private String convertTable(HtmlDocTree tree, Element el) {
		try {
			return tryConvertTable(tree, el);
		}
		catch (UnsupportedOperationException e) {
			// use raw html directive
			// this may not be supported by all IDEs but it is better then nothing
			// if your IDE doesn't support it, try tilting your head and squinting
			StringBuilder builder = new StringBuilder();
			return builder.append("\n\n.. raw:: html\n\n")
					.append(getRawHtml(tree, el).indent(INDENT_WIDTH))
					.append('\n')
					.toString();
		}
	}

	/**
	 * Converts a table {@literal <table>}
	 *
	 * @param tree the html
	 * @param el the element
	 * @return the converted table
	 * @throws UnsupportedOperationException if the table contains nested rows
	 */
	private String tryConvertTable(HtmlDocTree tree, Element el) {
		RstTableBuilder tbl = new RstTableBuilder(this, el);
		ListIterator<? extends DocTree> it = tree.getBody().listIterator();
		while (it.hasNext()) {
			DocTree tag = it.next();
			switch (tag.getKind()) {
				case OTHER:
					if (!(tag instanceof HtmlDocTree)) {
						logError(el, tag, "Unexpected OTHER tag kind");
						return "";
					}
					HtmlDocTree html = (HtmlDocTree) tag;
					switch (html.getHtmlKind()) {
						case TBODY:
						case TFOOT:
						case THEAD:
							tbl.addRowGroup(html);
							break;
						case TR:
							tbl.addRow(html);
							break;
						case CAPTION:
							tbl.addCaption(convertTree(el, html.getBody()));
							break;
						default:
							logError(el, tag,
								"unexpected html tag encountered while parsing table");
							break;
					}
					break;
				case TEXT:
					String body = ((TextTree) tag).getBody();
					if (!body.isBlank()) {
						logWarning(el, tag, "skipping unexpected text in table");
					}
					break;
				default:
					logError(el, tag, "unexpected tag encountered while parsing table");
					return "";
			}
		}
		return tbl.build();
	}
}
