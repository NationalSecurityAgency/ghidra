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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.lang.model.element.Element;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.PackageElement;
import javax.lang.model.element.QualifiedNameable;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;

import com.sun.source.doctree.*;

import jdk.javadoc.doclet.DocletEnvironment;
import jdk.javadoc.doclet.Reporter;

/**
 * Helper class for converting Javadoc to Python docstring format
 */
public class JavadocConverter extends DocConverter {

	private static final Pattern LEADING_WHITESPACE = Pattern.compile("(\\s+)\\S.*");

	private static final Map<String, String> AUTO_CONVERSIONS = new HashMap<>(
		Map.ofEntries(
			Map.entry("java.lang.Boolean", "java.lang.Boolean or bool"),
			Map.entry("java.lang.Byte", "java.lang.Byte or int"),
			Map.entry("java.lang.Character", "java.lang.Character or int or str"),
			Map.entry("java.lang.Double", "java.lang.Double or float"),
			Map.entry("java.lang.Float", "java.lang.Float or float"),
			Map.entry("java.lang.Integer", "java.lang.Integer or int"),
			Map.entry("java.lang.Long", "java.lang.Long or int"),
			Map.entry("java.lang.Short", "java.lang.Short or int"),
			Map.entry("java.lang.String", "java.lang.String or str"),
			Map.entry("java.io.File", "jpype.protocol.SupportsPath"),
			Map.entry("java.nio.file.Path", "jpype.protocol.SupportsPath"),
			Map.entry("java.lang.Iterable", "collections.abc.Sequence"),
			Map.entry("java.util.Collection", "collections.abc.Sequence"),
			Map.entry("java.util.Map", "collections.abc.Mapping"),
			Map.entry("java.time.Instant", "datetime.datetime"),
			Map.entry("java.sql.Time", "datetime.time"),
			Map.entry("java.sql.Date", "datetime.date"),
			Map.entry("java.sql.Timestamp", "datetime.datetime"),
			Map.entry("java.math.BigDecimal", "decimal.Decimal")));

	// these tags are used in the jdk and shouldn't cause any warnings
	// it is not worth the effort to handle them to output any documentation
	private static final Set<String> JDK_TAGLETS = new HashSet<>(
		Set.of("jls", "jvms", "extLink", "Incubating", "moduleGraph", "sealedGraph", "toolGuide"));

	private static final Map<String, String> NOTE_TAGLETS = new HashMap<>(
		Map.of("apiNote", "API Note", "implNote", "Implementation Note", "implSpec",
			"Implementation Requirements"));

	private final HtmlConverter htmlConverter;

	/**
	 * Creates a new {@link DocConverter}
	 *
	 * @param env the doclet environment
	 * @param log the log
	 */
	public JavadocConverter(DocletEnvironment env, Reporter log) {
		super(env, log);
		this.htmlConverter = new HtmlConverter(env, log, this);
	}

	/**
	 * Gets the Javadoc for the provided element
	 *
	 * @param el the element
	 * @return the Javadoc
	 */
	String getJavadoc(Element el) {
		return getJavadoc(el, getDocTrees().getDocCommentTree(el));
	}

	/**
	 * Gets the Javadoc tree for the provided element
	 *
	 * @param el the element
	 * @return the Javadoc tree
	 */
	DocCommentTree getJavadocTree(Element el) {
		return getDocTrees().getDocCommentTree(el);
	}

	/**
	 * Gets the converted documentation for the provided element and doc tree
	 *
	 * @param el the element
	 * @param docCommentTree the doc tree
	 * @return the converted documentation
	 */
	private String getJavadoc(Element el, DocCommentTree docCommentTree) {
		if (docCommentTree != null) {
			StringBuilder builder = new StringBuilder();
			ListIterator<? extends DocTree> it = docCommentTree.getFullBody().listIterator();
			while (it.hasNext()) {
				DocTree next = it.next();
				builder.append(convertTag(el, next, it));
			}
			// A blank line is required before block tags
			builder.append("\n\n");
			List<SeeTree> seealso = new ArrayList<>();
			it = docCommentTree.getBlockTags().listIterator();
			while (it.hasNext()) {
				DocTree tag = it.next();
				if (tag.getKind() == DocTree.Kind.SEE) {
					seealso.add((SeeTree) tag);
					continue;
				}
				if (tag.getKind() == DocTree.Kind.HIDDEN) {
					// hidden blocktag means don't document
					return "";
				}
				builder.append(convertTag(el, tag, it));
			}
			if (!seealso.isEmpty()) {
				builder.append("\n.. seealso::\n\n");
				for (SeeTree tag : seealso) {
					String message = "| " + alignIndent(convertTree(el, tag.getReference()));
					builder.append(message.indent(INDENT_WIDTH))
							.append('\n');
				}

			}
			String tmp = builder.toString().replaceAll("\t", "    ");
			if (tmp.indexOf('\n') == -1) {
				return tmp;
			}
			builder = new StringBuilder(tmp.length());

			// we need to fix the indentation because it will mess with the reStructured text
			// NOTE: you cannot just use String.stripLeading or String.indent(-1) here
			Iterable<String> lines = () -> tmp.lines().iterator();
			for (String line : lines) {
				Matcher matcher = LEADING_WHITESPACE.matcher(line);
				if (matcher.matches()) {
					String whitespace = matcher.group(1);
					builder.append(line.substring(whitespace.length() % INDENT_WIDTH))
							.append('\n');
				}
				else {
					builder.append(line)
							.append('\n');
				}
			}
			return builder.toString();
		}
		return "";
	}

	@Override
	String convertTag(Element el, DocTree tag, ListIterator<? extends DocTree> it) {
		// NOTE: each tag is responsible for its own line endings
		return switch (tag.getKind()) {
			case DOC_ROOT -> tag.toString(); // not sure what would be an appropriate replacement
			case PARAM -> convertParamTag(el, (ParamTree) tag);
			case RETURN -> convertReturnTag((ExecutableElement) el, (ReturnTree) tag);
			case THROWS -> convertThrowsTag((ExecutableElement) el, (ThrowsTree) tag);
			case START_ELEMENT -> convertHTML(el, (StartElementTree) tag, it);
			case END_ELEMENT -> convertHTML((EndElementTree) tag);
			case LINK -> convertLinkTag(el, (LinkTree) tag);
			case LINK_PLAIN -> convertLinkTag(el, (LinkTree) tag);
			case EXCEPTION -> convertThrowsTag((ExecutableElement) el, (ThrowsTree) tag);
			case ENTITY -> convertEntity((EntityTree) tag);
			case CODE -> convertCodeTag((LiteralTree) tag);
			case LITERAL -> convertLiteralTag((LiteralTree) tag);
			case VALUE -> convertValueTag(el, (ValueTree) tag);
			case DEPRECATED -> convertDeprecatedTag(el, (DeprecatedTree) tag);
			case REFERENCE -> convertReferenceTag(el, (ReferenceTree) tag);
			case SINCE -> convertSinceTag(el, (SinceTree) tag);
			case AUTHOR -> convertAuthorTag(el, (AuthorTree) tag);
			case VERSION -> ""; // ignored
			case ERRONEOUS -> {
				logError(el, tag, "erroneous javadoc tag");
				yield tag.toString();
			}
			case UNKNOWN_BLOCK_TAG -> convertUnknownBlockTag(el, (UnknownBlockTagTree) tag);
			case UNKNOWN_INLINE_TAG -> {
				if (JDK_TAGLETS.contains(((UnknownInlineTagTree) tag).getTagName())) {
					yield "";
				}
				logError(el, tag, "unknown javadoc inline tag");
				yield tag.toString();
			}
			case TEXT -> ((TextTree) tag).getBody();
			case SNIPPET -> convertSnippet(el, (SnippetTree) tag);
			case INHERIT_DOC -> ""; // ignored, anything containing this is skipped
			case OTHER -> {
				if (tag instanceof HtmlDocTree html) {
					yield htmlConverter.convertHtml(html, el, it);
				}
				else {
					yield tag.toString();
				}
			}
			case SPEC -> "";
			case SERIAL -> "";
			case SERIAL_DATA -> "";
			case SYSTEM_PROPERTY -> "``" + ((SystemPropertyTree) tag).getPropertyName() + "``";
			case COMMENT -> "";
			case INDEX -> "";
			default -> {
				logWarning(el, tag, "unsupported javadoc tag");
				yield tag.toString();
			}
			case ESCAPE -> ((EscapeTree) tag).getBody();
			case SERIAL_FIELD -> "";
			case SUMMARY -> convertTree(el, ((SummaryTree) tag).getSummary());
			case USES -> "";
		};
	}

	private String convertUnknownBlockTag(Element el, UnknownBlockTagTree tag) {
		if (JDK_TAGLETS.contains(tag.getTagName())) {
			return "";
		}
		String title = NOTE_TAGLETS.get(tag.getTagName());
		if (title == null) {
			logError(el, tag, "unknown javadoc block tag");
			return tag.toString();
		}
		StringBuilder builder = new StringBuilder();
		String message = alignIndent(convertTree(el, tag.getContent()));
		return builder.append("\n.. admonition:: ")
				.append(title)
				.append("\n\n")
				.append(message.indent(INDENT_WIDTH))
				.append("\n\n")
				.toString();
	}

	/**
	 * Gets the attributes for the provided snippet
	 *
	 * @param snippet the snippet
	 * @return the snippet attributes
	 */
	private Map<String, String> getAttributes(Element el, SnippetTree snippet) {
		return getAttributes(el, snippet.getAttributes());
	}

	/**
	 * Indent the provided text
	 *
	 * @param text the text to indent
	 * @return the indented text
	 */
	private static String indent(String text) {
		return text.indent(INDENT_WIDTH);
	}

	/**
	 * Indent the provided text tree
	 *
	 * @param text the text tree
	 * @return the indented text
	 */
	private static String indent(TextTree text) {
		return indent(text.getBody());
	}

	/**
	 * Converts an author Javadoc tag
	 *
	 * @param el the current element
	 * @param author the author tag
	 * @return the converted tag
	 */
	private String convertAuthorTag(Element el, AuthorTree author) {
		String name = convertTree(el, author.getName());
		return "\n.. codeauthor:: " + name + '\n';
	}

	/**
	 * Converts a since Javadoc tag
	 *
	 * @param el the current element
	 * @param since the since tag
	 * @return the converted tag
	 */
	private String convertSinceTag(Element el, SinceTree since) {
		// NOTE: there must be a preceding new line
		String msg = convertTree(el, since.getBody());
		return "\n.. versionadded:: " + msg + '\n';
	}

	/**
	 * Converts a link Javadoc tag
	 *
	 * @param el the current element
	 * @param link the link tag
	 * @return the converted tag
	 */
	private String convertLinkTag(Element el, LinkTree link) {
		String sig = link.getReference().getSignature().replaceAll("#", ".");
		int index = sig.indexOf('(');
		String label = convertTree(el, link.getLabel());
		if (index != -1) {
			String name = sig;
			sig = sig.substring(0, index);
			if (label.isBlank()) {
				if (name.startsWith(".")) {
					label = name.substring(1);
				}
				else {
					label = name;
				}
			}
			return ":meth:`" + label + " <" + sig + ">`";
		}
		if (!label.isBlank()) {
			return ":obj:`" + label + " <" + sig + ">`";
		}
		return ":obj:`" + sig + '`';
	}

	/**
	 * Gets the constant value for a value tag
	 *
	 * @param el the current element
	 * @param tag the value tag
	 * @return the constant value
	 */
	private static String getConstantValue(VariableElement el, ValueTree tag) {
		Object value = el.getConstantValue();
		TextTree format = tag.getFormat();
		if (format != null) {
			try {
				return String.format(format.getBody(), value);
			}
			catch (IllegalArgumentException e) {
				// fallthrough
			}
		}
		return value.toString();
	}

	/**
	 * Converts a Javadoc reference
	 *
	 * @param el the current element
	 * @param ref the reference
	 * @return the converted reference
	 */
	private String convertReferenceTag(Element el, ReferenceTree ref) {
		String sig = ref.getSignature();
		if (sig == null || sig.isBlank()) {
			return "";
		}
		return ":obj:`" + sig.replace('#', '.') + '`';
	}

	/**
	 * Converts a value Javadoc tag
	 *
	 * @param el the current element
	 * @param value the value tag
	 * @return the converted tag
	 */
	private String convertValueTag(Element el, ValueTree value) {
		ReferenceTree ref = value.getReference();
		if (ref == null) {
			return "";
		}
		String sig = ref.getSignature();
		if (sig == null || sig.isBlank()) {
			if (el instanceof VariableElement var) {
				return getConstantValue(var, value);
			}
			return ":const:`" + sig.replaceAll("#", ".") + '`';
		}
		int index = sig.indexOf('#');
		TypeElement type;
		String field;
		if (index == 0) {
			if (el instanceof ExecutableElement method) {
				type = (TypeElement) method.getEnclosingElement();
			}
			else {
				type = (TypeElement) el;
			}
			field = sig.substring(1);
		}
		else {
			String name = sig.substring(0, index);
			type = getElementUtils().getTypeElement(name);
			if (type == null && el instanceof ExecutableElement method) {
				// check if the name of the current class was specified
				type = (TypeElement) method.getEnclosingElement();
				if (!type.getSimpleName().contentEquals(name)) {
					type = null;
				}
			}
			field = sig.substring(index + 1);
		}
		if (type != null) {
			for (Element child : getElementUtils().getAllMembers(type)) {
				if (child.getSimpleName().contentEquals(field)) {
					if (child instanceof VariableElement var) {
						return getConstantValue(var, value);
					}
				}
			}
		}
		return ":const:`" + sig.replaceAll("#", ".") + '`';
	}

	/**
	 * Converts a deprecated Javadoc tag
	 *
	 * @param tag the deprecated tag
	 * @return the converted tag
	 */
	private String convertDeprecatedTag(Element el, DeprecatedTree tag) {
		String body = convertTree(el, tag.getBody());
		return new StringBuilder("\n.. deprecated::\n\n")
				.append(body)
				.append('\n')
				.toString();
	}

	/**
	 * Converts a snippet Javadoc tag
	 *
	 * @param snippet the snippet tag
	 * @return the converted tag
	 */
	private String convertSnippet(Element el, SnippetTree snippet) {
		// let pygments guess the code type
		TextTree body = snippet.getBody();
		if (body == null) {
			// there are invalid snippet tags in the internal jdk packages
			return "";
		}

		Map<String, String> attributes = getAttributes(el, snippet);
		String lang = attributes.getOrDefault("lang", "guess");
		// any other attributes are not supported
		return new StringBuilder(".. code-block:: ")
				.append(lang)
				.append("\n    :dedent: 4\n\n")
				.append(indent(body))
				.append('\n')
				.toString();
	}

	/**
	 * Converts a code Javadoc tag
	 *
	 * @param code the code tag
	 * @return the converted tag
	 */
	private static String convertCodeTag(LiteralTree code) {
		String body = convertLiteralTag(code);
		if (body.isBlank()) {
			return "";
		}
		return "``" + body + "``";
	}

	/**
	 * Converts a literal Javadoc tag
	 *
	 * @param literal the literal tag
	 * @return the converted tag
	 */
	private static String convertLiteralTag(LiteralTree literal) {
		// NOTE: the literal tag DOES NOT preserve line endings or whitespace
		// it is still present in the body so remove it
		TextTree text = literal.getBody();
		if (text == null) {
			return "";
		}

		String body = text.getBody();
		if (body == null) {
			return "";
		}

		return body.stripIndent().replaceAll("\n", "");
	}

	/**
	 * Converts a html entity (ie. {@literal &amp;lt;})
	 *
	 * @param entity the entity
	 * @return the converted entity
	 */
	private String convertEntity(EntityTree entity) {
		return getDocTrees().getCharacters(entity);
	}

	/**
	 * Converts a html tag
	 *
	 * @param tag the html start tag
	 * @return the converted html
	 */
	private String convertHTML(Element el, StartElementTree tag,
			ListIterator<? extends DocTree> it) {
		return htmlConverter.convertHtml(tag, el, it);
	}

	/**
	 * Converts a html tag
	 *
	 * @param tag the html end tag
	 * @return the converted html
	 */
	private static String convertHTML(EndElementTree tag) {
		if (tag.getName().contentEquals("p")) {
			return "\n";
		}
		return tag.toString();
	}

	/**
	 * Sanitizes the provided type with respect to the provided method element
	 *
	 * @param el the method element
	 * @param type the type
	 * @return the sanitized type name
	 */
	private static String sanitizeQualifiedName(ExecutableElement el, TypeMirror type) {
		Element self = el.getEnclosingElement();
		PackageElement pkg = PythonTypeStubElement.getPackage(self);
		return PythonTypeStubElement.sanitizeQualifiedName(type, pkg);
	}

	/**
	 * Converts a param Javadoc tag for a method parameter
	 *
	 * @param el the current element
	 * @param param the param tag
	 * @return the converted tag
	 */
	private String convertParamTag(Element el, ParamTree param) {
		if (el instanceof ExecutableElement executableElement) {
			return convertParamTag(executableElement, param);
		}
		return convertParamTag((TypeElement) el, param);
	}

	/**
	 * Converts a param Javadoc tag
	 *
	 * @param el the current element
	 * @param param the param tag
	 * @return the converted tag
	 */
	private static String convertParamTag(TypeElement el, ParamTree param) {
		// I'm not sure python does this?
		return "";
	}

	/**
	 * Converts the parameter type type to show all possible values
	 *
	 * @param type the type to convert
	 * @return the type or null if not applicable
	 */
	private static String convertParamType(TypeMirror type) {
		if (type.getKind().isPrimitive()) {
			return switch (type.getKind()) {
				case BOOLEAN -> "jpype.JBoolean or bool";
				case BYTE -> "jpype.JByte or int";
				case CHAR -> "jpype.JChar or int or str";
				case DOUBLE -> "jpype.JDouble or float";
				case FLOAT -> "jpype.JFloat or float";
				case INT -> "jpype.JInt or int";
				case LONG -> "jpype.JLong or int";
				case SHORT -> "jpype.JShort or int";
				default -> throw new RuntimeException("unexpected TypeKind " + type.getKind());
			};
		}
		if (type instanceof DeclaredType dt) {
			Element element = dt.asElement();
			if (element instanceof QualifiedNameable nameable) {
				return AUTO_CONVERSIONS.get(nameable.getQualifiedName().toString());
			}
		}
		return null;
	}

	/**
	 * Converts a param Javadoc tag for a method parameter
	 *
	 * @param el the current element
	 * @param param the param tag
	 * @return the converted tag
	 */
	private String convertParamTag(ExecutableElement el, ParamTree param) {
		TypeMirror type = null;
		for (VariableElement child : el.getParameters()) {
			if (child.getSimpleName().equals(param.getName().getName())) {
				type = child.asType();
				break;
			}
		}
		String description = convertTree(el, param.getDescription());
		if (type == null) {
			return ":param " + param.getName() + ": " + description;
		}
		String typename = convertParamType(type);
		if (typename == null) {
			typename = sanitizeQualifiedName(el, type);
		}
		return ":param " + typename + " " + param.getName() + ": " + description + '\n';
	}

	/**
	 * Converts a return Javadoc tag
	 *
	 * @param el the current element
	 * @param tag the return tag
	 * @return the converted tag
	 */
	private String convertReturnTag(ExecutableElement el, ReturnTree tag) {
		String description = convertTree(el, tag.getDescription());
		if (el.getReturnType().getKind() == TypeKind.VOID) {
			return ":return: " + description + '\n';
		}

		String typename = PythonTypeStubMethod.convertResultType(el.getReturnType());
		if (typename == null) {
			typename = sanitizeQualifiedName(el, el.getReturnType());
		}
		String res = ":return: " + description + '\n';
		return res + ":rtype: " + typename + '\n';
	}

	/**
	 * Converts a throws Javadoc tag
	 *
	 * @param el the current element
	 * @param tag the throws tag
	 * @return the converted tag
	 */
	private String convertThrowsTag(ExecutableElement el, ThrowsTree tag) {
		String typename = tag.getExceptionName().getSignature();
		TypeMirror type = null;
		for (TypeMirror thrownType : el.getThrownTypes()) {
			if (thrownType.getKind() == TypeKind.TYPEVAR) {
				if (thrownType.toString().equals(typename)) {
					break;
				}
				continue;
			}
			TypeElement typeElement = (TypeElement) (((DeclaredType) thrownType).asElement());
			if (typeElement.getQualifiedName().contentEquals(typename)) {
				type = thrownType;
				break;
			}
			if (typeElement.getQualifiedName().toString().startsWith("java.lang.")) {
				if (typeElement.getSimpleName().contentEquals(typename)) {
					type = thrownType;
					break;
				}
			}
		}
		if (type != null) {
			typename = sanitizeQualifiedName(el, type);
		}
		String description = convertTree(el, tag.getDescription());
		return ":raises " + typename + ": " + description + '\n';
	}
}
