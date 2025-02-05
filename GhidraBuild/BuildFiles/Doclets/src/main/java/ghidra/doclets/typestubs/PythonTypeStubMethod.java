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
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.lang.model.element.Element;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.QualifiedNameable;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.TypeParameterElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.ArrayType;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.ExecutableType;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;

/**
 * {@link PythonTypeStubElement} for a method
 */
final class PythonTypeStubMethod extends PythonTypeStubElement<ExecutableElement>
		implements Comparable<PythonTypeStubMethod> {

	private static final String EMPTY_DOCS = "..." + System.lineSeparator();

	private static final Map<String, String> AUTO_CONVERSIONS = new HashMap<>(
		Map.ofEntries(
			Map.entry("java.lang.Boolean", "typing.Union[java.lang.Boolean, bool]"),
			Map.entry("java.lang.Byte", "typing.Union[java.lang.Byte, int]"),
			Map.entry("java.lang.Character", "typing.Union[java.lang.Character, int, str]"),
			Map.entry("java.lang.Double", "typing.Union[java.lang.Double, float]"),
			Map.entry("java.lang.Float", "typing.Union[java.lang.Float, float]"),
			Map.entry("java.lang.Integer", "typing.Union[java.lang.Integer, int]"),
			Map.entry("java.lang.Long", "typing.Union[java.lang.Long, int]"),
			Map.entry("java.lang.Short", "typing.Union[java.lang.Short, int]"),
			Map.entry("java.lang.String", "typing.Union[java.lang.String, str]"),
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

	// FIXME: list and set aren't automatically converted to java.util.List and java.util.Set :(
	// if wanted they could be setup to be converted automatically by PyGhidra
	// however, when passed as a parameter and modified, the original underlying python container
	// wouldn't be modified. To make it work as expected, a python implementation for
	// java.util.List and java.util.Set would need to be created using jpype.JImplements,
	// that would wrap the list/set before passing it to Java instead of copying the contents
	// into a Java List/Set.

	private static final Map<String, String> RESULT_CONVERSIONS = new HashMap<>(
		Map.of(
			"java.lang.Boolean", "bool",
			"java.lang.Byte", "int",
			"java.lang.Character", "str",
			"java.lang.Double", "float",
			"java.lang.Float", "float",
			"java.lang.Integer", "int",
			"java.lang.Long", "int",
			"java.lang.Short", "int",
			"java.lang.String", "str"));

	private final boolean filterSelf;
	List<String> typevars;
	Set<TypeElement> imports;

	/**
	 * Creates a new {@link PythonTypeStubMethod}
	 *
	 * @param parent the type containing this method
	 * @param el the element for this method
	 */
	PythonTypeStubMethod(PythonTypeStubType parent, ExecutableElement el) {
		this(parent, el, false);
	}

	/**
	 * Creates a new {@link PythonTypeStubMethod}
	 *
	 * @param parent the type containing this method
	 * @param el the element for this method
	 * @param filterSelf true if the self parameter should be filtered
	 */
	PythonTypeStubMethod(PythonTypeStubType parent, ExecutableElement el, boolean filterSelf) {
		super(parent.doclet, el);
		this.filterSelf = filterSelf;
	}

	/**
	 * Processes the method and prints it to the provided printer
	 *
	 * @param printer the printer
	 * @param indent the indentation
	 * @param overload true if the overload annotation should be applied
	 */
	void process(PrintWriter printer, String indent, boolean overload) {
		String name = sanitize(getName());
		Set<Modifier> modifiers = el.getModifiers();
		boolean isStatic = modifiers.contains(Modifier.STATIC);

		if (name.equals("<init>")) {
			name = "__init__";
		}

		printer.print(indent);
		if (isStatic) {
			printer.println("@staticmethod");
			printer.print(indent);
		}

		if (overload) {
			printer.println("@typing.overload");
			printer.print(indent);
		}

		if (doclet.isDeprecated(el)) {
			String msg = doclet.getDeprecatedMessage(el);
			if (msg != null) {
				// a message is required
				// if one is not present, don't apply it
				printer.print("@deprecated(");
				printer.print(msg);
				printer.println(')');
				printer.print(indent);
			}
		}

		printer.print("def ");
		printer.print(name);

		printSignature(printer, filterSelf || isStatic);

		printer.println(":");
		indent += PY_INDENT;
		writeJavaDoc(el, printer, indent, EMPTY_DOCS);
		printer.println();
	}

	/**
	 * Gets a collection of all TypeVars needed by this method
	 *
	 * @return a collection of all needed TypeVars
	 */
	Collection<String> getTypeVars() {
		if (typevars != null) {
			return typevars;
		}

		List<? extends TypeParameterElement> params = el.getTypeParameters();
		typevars = new ArrayList<>(params.size());
		for (TypeParameterElement param : params) {
			typevars.add(param.getSimpleName().toString());
		}
		return typevars;
	}

	/**
	 * Gets a collection of all type that need to be imported for this method
	 *
	 * @return a collection of types to import
	 */
	Collection<TypeElement> getImportedTypes() {
		if (imports != null) {
			return imports;
		}

		List<? extends TypeMirror> parameters = getParameterTypes();

		// make the set big enough for all paramters and the return type
		imports = new HashSet<>(parameters.size() + 1);

		addNeededTypes(imports, getReturnType());
		for (TypeMirror param : parameters) {
			addNeededTypes(imports, param);
		}

		return imports;
	}

	/**
	 * Converts the result type to the Python equivalent type if applicable
	 *
	 * @param type the result type
	 * @return the Python equivalent type or null if there is no equivalent type
	 */
	static String convertResultType(TypeMirror type) {
		if (type.getKind().isPrimitive()) {
			return switch (type.getKind()) {
				case BOOLEAN -> "bool";
				case BYTE -> "int";
				case CHAR -> "str";
				case DOUBLE -> "float";
				case FLOAT -> "float";
				case INT -> "int";
				case LONG -> "int";
				case SHORT -> "int";
				default -> throw new RuntimeException("unexpected TypeKind " + type.getKind());
			};
		}

		if (type instanceof DeclaredType dt) {
			Element element = dt.asElement();
			if (element instanceof QualifiedNameable nameable) {
				return RESULT_CONVERSIONS.get(nameable.getQualifiedName().toString());
			}
		}
		return null;
	}

	/**
	 * Checks if this method is a candidate for a Python property
	 *
	 * @return true if this method may be a Python property
	 */
	boolean isProperty() {
		if (isStatic(el)) {
			return false;
		}

		List<? extends VariableElement> params = el.getParameters();
		if (params.size() > 1) {
			return false;
		}

		String name = getName();
		TypeKind resultKind = getReturnType().getKind();
		try {
			if (name.startsWith("get")) {
				return Character.isUpperCase(name.charAt(3)) && resultKind != TypeKind.VOID;
			}
			if (name.startsWith("is")) {
				return Character.isUpperCase(name.charAt(2)) && resultKind != TypeKind.VOID;
			}
			if (name.startsWith("set")) {
				if (params.size() != 1) {
					return false;
				}
				return Character.isUpperCase(name.charAt(3)) && resultKind == TypeKind.VOID;
			}
		}
		catch (IndexOutOfBoundsException e) {
			// name check failed
		}
		return false;
	}

	/**
	 * Converts this method to its Python property form
	 *
	 * @return this method as a Python property
	 */
	PropertyMethod asProperty() {
		return new PropertyMethod();
	}

	/**
	 * Prints the Python equivalent method signature to the provided printer
	 *
	 * @param printer the printer
	 * @param isStatic true if this method is a static method
	 */
	private void printSignature(PrintWriter printer, boolean isStatic) {
		List<String> names = getParameterNames();
		List<? extends TypeMirror> types = getParameterTypes();
		StringBuilder args = new StringBuilder();

		if (!isStatic) {
			args.append("self");
		}

		for (int i = 0; i < names.size(); i++) {
			if (i != 0 || !isStatic) {
				args.append(", ");
			}
			if (el.isVarArgs() && i == names.size() - 1) {
				ArrayType type = (ArrayType) types.get(i);
				String arg = convertParam(names.get(i), type.getComponentType());
				args.append('*' + arg);
			}
			else {
				args.append(convertParam(names.get(i), types.get(i)));
			}
		}

		printer.print("(");
		printer.print(args);
		printer.print(")");

		TypeMirror res = el.getReturnType();
		if (res.getKind() != TypeKind.VOID) {
			printer.print(" -> ");
			String convertedType = convertResultType(res);
			if (convertedType != null) {
				printer.print(convertedType);
			}
			else {
				printer.print(sanitizeQualifiedName(res));
			}
		}
	}

	/**
	 * Gets the property name for this method if applicable
	 *
	 * @return the property name or null
	 */
	private String getPropertyName() {
		String name = getName();
		if (name.startsWith("get") || name.startsWith("set")) {
			return Character.toLowerCase(name.charAt(3)) + name.substring(4);
		}
		if (name.startsWith("is")) {
			return Character.toLowerCase(name.charAt(2)) + name.substring(3);
		}
		return null;
	}

	/**
	 * Gets a list of all the parameter types
	 *
	 * @return the list of parameter types
	 */
	private List<? extends TypeMirror> getParameterTypes() {
		return ((ExecutableType) el.asType()).getParameterTypes();
	}

	/**
	 * Gets a list of all the Python safe parameter names
	 *
	 * @return the list of parameter names
	 */
	private List<String> getParameterNames() {
		List<? extends VariableElement> params = el.getParameters();
		List<String> names = new ArrayList<>(params.size());
		for (VariableElement param : params) {
			String name = sanitize(param.getSimpleName());
			if (name.equals("self")) {
				name = "self_";
			}
			names.add(name);
		}
		return names;
	}

	/**
	 * Gets the return type
	 *
	 * @return the return type
	 */
	private TypeMirror getReturnType() {
		return el.getReturnType();
	}

	/**
	 * Converts the provided parameter type to a typing.Union of all the allowed types
	 *
	 * @param name the parameter name
	 * @param type the parameter type
	 * @return the parameter and its type
	 */
	private String convertParam(String name, TypeMirror type) {
		String convertedType = convertParamType(type);
		if (convertedType != null) {
			return name + ": " + convertedType;
		}
		return name + ": " + sanitizeQualifiedName(type);
	}

	/**
	 * Converts the provided parameter type to a typing.Union of all the allowed types
	 *
	 * @param type the parameter type
	 * @return the converted type
	 */
	private static String convertParamType(TypeMirror type) {
		if (type.getKind().isPrimitive()) {
			return switch (type.getKind()) {
				case BOOLEAN -> "typing.Union[jpype.JBoolean, bool]";
				case BYTE -> "typing.Union[jpype.JByte, int]";
				case CHAR -> "typing.Union[jpype.JChar, int, str]";
				case DOUBLE -> "typing.Union[jpype.JDouble, float]";
				case FLOAT -> "typing.Union[jpype.JFloat, float]";
				case INT -> "typing.Union[jpype.JInt, int]";
				case LONG -> "typing.Union[jpype.JLong, int]";
				case SHORT -> "typing.Union[jpype.JShort, int]";
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
	 * Helper for creating a Python property.<p/>
	 *
	 * This class only represents one part of a complete Python property.
	 */
	class PropertyMethod {

		/**
		 * Gets the name for this property
		 *
		 * @return the property name
		 */
		String getName() {
			return sanitize(getPropertyName());
		}

		/**
		 * Checks if this property is a getter
		 *
		 * @return true if this property is a getter
		 */
		boolean isGetter() {
			return el.getReturnType().getKind() != TypeKind.VOID;
		}

		/**
		 * Checks if this property is a setter
		 *
		 * @return true if this property is a setter
		 */
		boolean isSetter() {
			return el.getReturnType().getKind() == TypeKind.VOID;
		}

		/**
		 * Gets the type for this property
		 *
		 * @return the property type
		 */
		TypeMirror getType() {
			TypeMirror type;
			if (isGetter()) {
				type = el.getReturnType();
			}
			else {
				type = getParameterTypes().get(0);
			}
			try {
				return doclet.getTypeUtils().unboxedType(type);
			}
			catch (IllegalArgumentException e) {
				// not boxed
				return type;
			}
		}

		/**
		 * Checks if this property and the other provided property form a pair
		 *
		 * @param other the other property
		 * @return true if the two properties form a pair
		 */
		boolean isPair(PropertyMethod other) {
			if (isGetter() && other.isGetter()) {
				return false;
			}
			if (isSetter() && other.isSetter()) {
				return false;
			}
			if (!getName().equals(other.getName())) {
				return false;
			}
			return doclet.getTypeUtils().isSameType(getType(), other.getType());
		}
	}

	@Override
	public int compareTo(PythonTypeStubMethod other) {
		return getName().compareTo(other.getName());
	}
}
