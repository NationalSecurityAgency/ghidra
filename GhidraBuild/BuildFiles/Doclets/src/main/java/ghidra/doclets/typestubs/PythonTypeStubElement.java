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

import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.lang.model.element.Element;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.Name;
import javax.lang.model.element.PackageElement;
import javax.lang.model.element.QualifiedNameable;
import javax.lang.model.element.TypeElement;
import javax.lang.model.type.ArrayType;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.type.WildcardType;

/**
 * Base class providing access to sanitized names (Python safe).
 */
abstract class PythonTypeStubElement<T extends Element> {

	private static final Set<String> PY_KEYWORDS = new HashSet<>(
		Set.of("False", "None", "True", "and", "as", "assert", "async", "await", "break",
			"class", "continue", "def", "del", "elif", "else", "except", "exec", "finally", "for",
			"from", "global", "if", "import", "in", "is", "lambda",
			"nonlocal", "not", "or", "pass", "raise", "return", "try", "while", "with",
			"yield"));

	static final String DOC_QUOTES = "\"\"\"";
	static final String ALT_DOC_QUOTES = "'''";
	static final String PY_INDENT = "    ";

	final PythonTypeStubDoclet doclet;
	final T el;
	private final PackageElement pkg;

	private String name;

	PythonTypeStubElement(PythonTypeStubDoclet doclet, T el) {
		this(doclet, getPackage(el), el);
	}

	PythonTypeStubElement(PythonTypeStubDoclet doclet, PackageElement pkg, T el) {
		this.doclet = doclet;
		this.pkg = pkg;
		this.el = el;
	}

	/**
	 * Gets the package for the provided element
	 *
	 * @param el the element
	 * @return the package
	 */
	static PackageElement getPackage(Element el) {
		while (!(el instanceof PackageElement)) {
			el = el.getEnclosingElement();
		}
		return (PackageElement) el;
	}

	static int compareQualifiedNameable(QualifiedNameable a, QualifiedNameable b) {
		return a.getQualifiedName().toString().compareTo(b.getQualifiedName().toString());
	}

	/**
	 * Checks if the provided element is in the same package as this element
	 *
	 * @param el the other element
	 * @return true if the other element is declared in the same package
	 */
	boolean isSamePackage(Element el) {
		return pkg.equals(getPackage(el));
	}

	/**
	 * Checks if the provided type is in the same package as this element
	 *
	 * @param type the type
	 * @return true if the type is declared in the same package
	 */
	boolean isSamePackage(TypeMirror type) {
		if (type instanceof DeclaredType dt) {
			return pkg.equals(getPackage(dt.asElement()));
		}
		return false;
	}

	/**
	 * Gets the Python safe name for this element
	 *
	 * @return the python safe name
	 */
	final String getName() {
		if (name == null) {
			name = sanitize(el.getSimpleName());
		}
		return name;
	}

	/**
	 * Writes the Javadoc for the provided element to the provided printer
	 *
	 * @param element the element to write the javadoc for
	 * @param printer the printer to write to
	 * @param indent the indentation
	 * @param emptyValue the value to use when there is no documentation
	 * @return true if a Javadoc was written else false
	 */
	final boolean writeJavaDoc(Element element, PrintWriter printer, String indent,
			String emptyValue) {
		String doc = doclet.getJavadoc(element);
		if (doc.isBlank()) {
			if (!emptyValue.isBlank()) {
				printer.print(indent);
				printer.print(emptyValue);
			}
			return false;
		}
		String quotes = doc.contains(DOC_QUOTES) ? ALT_DOC_QUOTES : DOC_QUOTES;
		if (quotes == ALT_DOC_QUOTES) {
			// ensure there are no problems
			doc = doc.replaceAll(ALT_DOC_QUOTES, '\\' + ALT_DOC_QUOTES);
		}
		printer.print(indent);
		printer.println(quotes);
		writeLines(printer, doc.stripTrailing(), indent);
		printer.print(indent);
		printer.println(quotes);
		return true;
	}

	/**
	 * Writes the Javadoc for this element to the provided printer
	 *
	 * @param printer the printer to write to
	 * @param indent the indentation
	 * @param emptyValue the value to use when there is no documentation
	 */
	final void writeJavaDoc(PrintWriter printer, String indent, String emptyValue) {
		writeJavaDoc(el, printer, indent, emptyValue);
	}

	/**
	 * Writes the Javadoc for this element to the provided printer
	 *
	 * @param printer the printer to write to
	 * @param indent the indentation
	 */
	final void writeJavaDoc(PrintWriter printer, String indent) {
		writeJavaDoc(el, printer, indent, "");
	}

	/**
	 * Makes the provided String Python safe if necessary
	 *
	 * @param value the value to make Python safe
	 * @return the Python safe value
	 */
	static String sanitize(String value) {
		if (PY_KEYWORDS.contains(value)) {
			return value + "_";
		}
		return value;
	}

	/**
	 * Makes the provided element name Python safe if necessary
	 *
	 * @param name the name to make Python safe
	 * @return the Python safe name
	 */
	static String sanitize(Name name) {
		return sanitize(name.toString());
	}

	/**
	 * Makes the provided qualified name Python safe if necessary
	 *
	 * @param name the qualified name to make Python safe
	 * @return the Python safe qualified name
	 */
	static String sanitizeQualifiedName(String name) {
		Iterator<String> it = Arrays.stream(name.split("\\."))
				.map(PythonTypeStubElement::sanitize)
				.iterator();
		return String.join(".", (Iterable<String>) () -> it);
	}

	/**
	 * Makes the provided qualified name Python safe if necessary
	 *
	 * @param name the qualified name to make Python safe
	 * @return the Python safe qualified name
	 */
	static String sanitizeQualifiedName(QualifiedNameable name) {
		return sanitizeQualifiedName(name.getQualifiedName().toString());
	}

	/**
	 * Makes the provided package name Python safe if necessary
	 *
	 * @param pkg the package to make Python safe
	 * @return the Python safe package name
	 */
	static String sanitizeQualifiedName(PackageElement pkg) {
		return sanitizeQualifiedName(pkg.getQualifiedName().toString());
	}

	/**
	 * Makes the provided type Python safe if necessary
	 *
	 * @param type the type to make Python safe
	 * @param pkg the current package
	 * @return the Python safe type name
	 */
	static String sanitize(TypeMirror type, PackageElement pkg) {
		return switch (type.getKind()) {
			case DECLARED -> throw new RuntimeException(
				"declared types should use the qualified name");
			case ARRAY -> {
				TypeMirror component = ((ArrayType) type).getComponentType();
				yield "jpype.JArray[" + sanitizeQualifiedName(component, pkg) + "]";
			}
			case BOOLEAN -> "jpype.JBoolean";
			case BYTE -> "jpype.JByte";
			case CHAR -> "jpype.JChar";
			case DOUBLE -> "jpype.JDouble";
			case FLOAT -> "jpype.JFloat";
			case INT -> "jpype.JInt";
			case LONG -> "jpype.JLong";
			case SHORT -> "jpype.JShort";
			case TYPEVAR -> type.toString();
			case WILDCARD -> getWildcardVarName((WildcardType) type, pkg);
			default -> throw new RuntimeException("unexpected TypeKind " + type.getKind());
		};
	}

	/**
	 * Makes the qualified name for the provided type Python safe if necessary
	 *
	 * @param type the type to make Python safe
	 * @return the Python safe qualified type name
	 */
	final String sanitizeQualifiedName(TypeMirror type) {
		return sanitizeQualifiedName(type, pkg);
	}

	/**
	 * Makes the qualified name for the provided type Python safe if necessary<p/>
	 *
	 * The provided package is used to check each type and generic components.
	 *
	 * @param type the type to make Python safe
	 * @param pkg the current package
	 * @return the Python safe qualified type name
	 */
	static final String sanitizeQualifiedName(TypeMirror type, PackageElement pkg) {
		if (type instanceof DeclaredType dt) {
			TypeElement el = (TypeElement) dt.asElement();
			PackageElement typePkg = getPackage(el);

			String name;
			if (pkg.equals(typePkg)) {
				name = sanitize(el.getSimpleName());
				Element parent = el.getEnclosingElement();
				while (parent instanceof TypeElement parentType) {
					parent = parent.getEnclosingElement();
					name = sanitize(parentType.getSimpleName()) + "." + name;
				}
			}
			else {
				name = sanitizeQualifiedName(el);
			}

			List<? extends TypeMirror> args = dt.getTypeArguments();
			if (args.isEmpty()) {
				return name;
			}
			Iterable<String> it = () -> args.stream()
					.map(paramType -> sanitizeQualifiedName(paramType, pkg))
					.iterator();
			return name + "[" + String.join(", ", it) + "]";
		}
		return sanitize(type, pkg);
	}

	/**
	 * Recursively adds the type and it's generic parameters to the provided imports set.
	 *
	 * @param imports the set of imported types
	 * @param type the type to add to the imports
	 */
	static void addNeededTypes(Set<TypeElement> imports, TypeMirror type) {
		switch (type.getKind()) {
			case DECLARED:
				DeclaredType dt = (DeclaredType) type;;
				imports.add((TypeElement) dt.asElement());
				for (TypeMirror genericType : dt.getTypeArguments()) {
					addNeededTypes(imports, genericType);
				}
				break;
			case WILDCARD:
				WildcardType wt = (WildcardType) type;
				TypeMirror base = wt.getExtendsBound();
				if (base == null) {
					base = wt.getSuperBound();
				}
				if (base != null) {
					addNeededTypes(imports, base);
				}
				break;
			default:
				break;
		}
	}

	/**
	 * Checks if the provided element is static
	 *
	 * @param el the element to check
	 * @return true if the element is static
	 */
	static boolean isStatic(Element el) {
		return el.getModifiers().contains(Modifier.STATIC);
	}

	/**
	 * Checks if the provided element is final
	 *
	 * @param el the element to check
	 * @return true if the element is final
	 */
	static boolean isFinal(Element el) {
		return el.getModifiers().contains(Modifier.FINAL);
	}

	/**
	 * Checks if the provided element is public
	 *
	 * @param el the element to check
	 * @return true if the element is public
	 */
	static boolean isPublic(Element el) {
		return el.getModifiers().contains(Modifier.PUBLIC);
	}

	/**
	 * Checks if the provided element is protected
	 *
	 * @param el the element to check
	 * @return true if the element is protected
	 */
	static boolean isProtected(Element el) {
		return el.getModifiers().contains(Modifier.PROTECTED);
	}

	/**
	 * Increases the provided indentation by one level
	 *
	 * @param indent the indentation
	 * @return the new indentation
	 */
	static String indent(String indent) {
		return indent + PY_INDENT;
	}

	/**
	 * Decreases the provided indentation by one level
	 *
	 * @param indent the indentation
	 * @return the new indentation
	 */
	static String deindent(String indent) {
		return indent.substring(0, indent.length() - PY_INDENT.length());
	}

	/**
	 * Gets the name for a wildcard type if possible
	 *
	 * @param type the wildcard type
	 * @param pkg the current package
	 * @return the determined type name if possible otherwise typing.Any
	 */
	private static String getWildcardVarName(WildcardType type, PackageElement pkg) {
		TypeMirror base = type.getExtendsBound();
		if (base == null) {
			base = type.getSuperBound();
		}
		if (base != null) {
			return sanitizeQualifiedName(base, pkg);
		}
		return "typing.Any";
	}

	/**
	 * Writes the lines to the printer with the provided intentation
	 *
	 * @param printer the printer
	 * @param lines the lines to write
	 * @param indent the indentation to use
	 */
	private static void writeLines(PrintWriter printer, String lines, String indent) {
		lines.lines().forEach((line) -> {
			printer.print(indent);
			printer.println(line);
		});
	}
}
