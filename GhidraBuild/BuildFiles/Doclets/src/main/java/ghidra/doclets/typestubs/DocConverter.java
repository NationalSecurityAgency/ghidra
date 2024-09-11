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
import java.util.stream.Collectors;

import javax.lang.model.element.Element;
import javax.lang.model.util.Elements;
import javax.tools.Diagnostic;

import com.sun.source.doctree.AttributeTree;
import com.sun.source.doctree.DocCommentTree;
import com.sun.source.doctree.DocTree;
import com.sun.source.util.DocTreePath;
import com.sun.source.util.DocTrees;
import com.sun.source.util.TreePath;

import jdk.javadoc.doclet.DocletEnvironment;
import jdk.javadoc.doclet.Reporter;

/**
 * Base class for recursively converting documentation
 */
abstract class DocConverter {

	static final int INDENT_WIDTH = 4;

	private final DocletEnvironment env;
	private final Reporter log;

	/**
	 * Creates a new {@link DocConverter}
	 *
	 * @param env the doclet environment
	 * @param log the log
	 */
	DocConverter(DocletEnvironment env, Reporter log) {
		this.env = env;
		this.log = log;
	}

	/**
	 * Converts the provided Javadoc tag
	 *
	 * @param el the current element
	 * @param tag the Javadoc tag
	 * @return the converted tag
	 */
	abstract String convertTag(Element el, DocTree tag, ListIterator<? extends DocTree> it);

	/**
	 * Converts the provided doc tree
	 *
	 * @param el the current element
	 * @param tree the doc tree
	 * @return the converted doc tree
	 */
	public String convertTree(Element el, List<? extends DocTree> tree) {
		StringBuilder builder = new StringBuilder();
		ListIterator<? extends DocTree> it = tree.listIterator();
		while (it.hasNext()) {
			builder.append(convertTag(el, it.next(), it));
		}
		return builder.toString();
	}

	/**
	 * Logs a warning with the provided message
	 *
	 * @param el the current element
	 * @param tag the current tag
	 * @param message the message
	 */
	final void logWarning(Element el, DocTree tag, String message) {
		try {
			DocCommentTree tree = env.getDocTrees().getDocCommentTree(el);
			TreePath treePath = env.getDocTrees().getPath(el);
			DocTreePath path = DocTreePath.getPath(treePath, tree, tag);
			if (path != null) {
				log.print(Diagnostic.Kind.WARNING, path, message);
			}
			else {
				log.print(Diagnostic.Kind.WARNING, el, message);
			}
		}
		catch (Throwable t) {
			t.printStackTrace();
		}
	}

	/**
	 * Logs an error with the provided message
	 *
	 * @param el the current element
	 * @param tag the current tag
	 * @param message the message
	 */
	final void logError(Element el, DocTree tag, String message) {
		try {
			DocCommentTree tree = env.getDocTrees().getDocCommentTree(el);
			TreePath treePath = env.getDocTrees().getPath(el);
			DocTreePath path = DocTreePath.getPath(treePath, tree, tag);
			if (path != null) {
				log.print(Diagnostic.Kind.ERROR, path, message);
			}
			else {
				log.print(Diagnostic.Kind.ERROR, el, message);
			}
		}
		catch (Throwable t) {
			t.printStackTrace();
		}
	}

	final DocTrees getDocTrees() {
		return env.getDocTrees();
	}

	final Elements getElementUtils() {
		return env.getElementUtils();
	}

	/**
	 * Gets a mapping of the provided list of attributes
	 *
	 * @param attributes the attributes list
	 * @return the attributes mapping
	 */
	Map<String, String> getAttributes(Element el, List<? extends DocTree> attributes) {
		return attributes
				.stream()
				.filter(AttributeTree.class::isInstance)
				.map(AttributeTree.class::cast)
				.collect(Collectors.toMap(attr -> attr.getName().toString().toLowerCase(),
					attr -> attr.getValue() != null ? convertTree(el, attr.getValue()) : ""));
	}

	/**
	 * Aligns the lines in the provided text to the same indentation level
	 *
	 * @param text the text
	 * @return the new text all aligned to the same indentation level
	 */
	static String alignIndent(String text) {
		int index = text.indexOf('\n');
		if (index == -1) {
			return text;
		}

		StringBuilder builder = new StringBuilder();
		return builder.append(text.substring(0, index + 1))
				.append(text.substring(index + 1).stripIndent())
				.toString();
	}
}
