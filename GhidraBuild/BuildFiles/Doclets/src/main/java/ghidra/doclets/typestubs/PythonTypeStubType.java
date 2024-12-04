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
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.lang.model.element.*;
import javax.lang.model.type.*;

import com.sun.source.doctree.DocTree;

/**
 * {@link PythonTypeStubElement} for a declared type
 */
class PythonTypeStubType extends PythonTypeStubElement<TypeElement> {

	private static final String OBJECT_NAME = Object.class.getName();
	private static final Map<String, String> GENERIC_CUSTOMIZERS = new HashMap<>(Map.ofEntries(
		Map.entry("java.lang.Iterable", "collections.abc.Iterable"),
		Map.entry("java.util.Collection", "collections.abc.Collection"),
		Map.entry("java.util.List", "list"),
		Map.entry("java.util.Map", "dict"),
		Map.entry("java.util.Set", "set"),
		Map.entry("java.util.Map.Entry", "tuple"),
		Map.entry("java.util.Iterator", "collections.abc.Iterator"),
		Map.entry("java.util.Enumeration", "collections.abc.Iterator")));

	private final PythonTypeStubPackage pkg;
	private Set<TypeElement> imports;
	private Set<String> typevars;
	private List<PythonTypeStubNestedType> nestedTypes;
	private List<VariableElement> fields;
	private List<PythonTypeStubMethod> methods;
	private List<Property> properties;
	private Set<String> fieldNames;
	private Set<String> methodNames;

	/**
	 * Creates a new {@link PythonTypeStubType}
	 *
	 * @param pkg the package containing this type
	 * @param el the element for this type
	 */
	PythonTypeStubType(PythonTypeStubPackage pkg, TypeElement el) {
		super(pkg.doclet, pkg.el, el);
		this.pkg = pkg;
	}

	/**
	 * Process the current type and write it to the provided printer
	 *
	 * @param printer the printer
	 * @param indent the indentation
	 */
	void process(PrintWriter printer, String indent) {
		printClass(printer, indent);
	}

	/**
	 * Gets a set of all the TypeVars used by this type
	 *
	 * @return a set of all used TypeVars
	 */
	Set<String> getTypeVars() {
		if (typevars != null) {
			return typevars;
		}
		List<? extends TypeParameterElement> params = el.getTypeParameters();
		typevars = new HashSet<>();
		for (TypeParameterElement param : params) {
			typevars.add(param.getSimpleName().toString());
		}
		for (PythonTypeStubNestedType nested : getNestedTypes()) {
			typevars.addAll(nested.getTypeVars());
		}
		for (PythonTypeStubMethod method : getMethods()) {
			typevars.addAll(method.getTypeVars());
		}
		return typevars;
	}

	/**
	 * Gets a collection of all the imported types used by this type
	 *
	 * @return a collection of all imported types
	 */
	final Collection<TypeElement> getImportedTypes() {
		if (imports != null) {
			return imports;
		}
		imports = new HashSet<>();
		TypeMirror base = el.getSuperclass();
		if (base instanceof DeclaredType dt) {
			imports.add((TypeElement) dt.asElement());
		}
		for (TypeMirror iface : el.getInterfaces()) {
			addNeededTypes(imports, iface);
		}
		for (PythonTypeStubNestedType nested : getNestedTypes()) {
			imports.addAll(nested.getImportedTypes());
		}
		for (VariableElement field : getFields()) {
			addNeededTypes(imports, field.asType());
		}
		for (PythonTypeStubMethod method : getMethods()) {
			imports.addAll(method.getImportedTypes());
		}
		return imports;
	}

	/**
	 * Gets a list of all the nested types declared in this type
	 *
	 * @return a list of all nested types
	 */
	final List<PythonTypeStubNestedType> getNestedTypes() {
		if (nestedTypes != null) {
			return nestedTypes;
		}
		nestedTypes = new ArrayList<>();
		for (Element child : el.getEnclosedElements()) {
			if (child instanceof TypeElement type) {
				nestedTypes.add(new PythonTypeStubNestedType(pkg, type));
			}
		}
		return nestedTypes;
	}

	/**
	 * Gets a list of all the public fields in this type
	 *
	 * @return a list of all public fields
	 */
	final List<VariableElement> getFields() {
		return getFields(false);
	}

	/**
	 * Gets a list of all the visible fields in this type
	 *
	 * @param protectedScope true to include protected fields
	 * @return a list of all visible fields
	 */
	final List<VariableElement> getFields(boolean protectedScope) {
		if (fields != null) {
			return fields;
		}
		fields = new ArrayList<>();
		for (Element child : el.getEnclosedElements()) {
			switch (child.getKind()) {
				case ENUM_CONSTANT:
				case FIELD:
					break;
				default:
					continue;
			}
			if (!isVisible(child, protectedScope)) {
				continue;
			}
			fields.add((VariableElement) child);
		}
		return fields;
	}

	/**
	 * Gets a list of all public methods and constructors in this type
	 *
	 * @return a list of all public methods
	 */
	final List<PythonTypeStubMethod> getMethods() {
		return getMethods(false, false);
	}

	/**
	 * Gets a list of all visible methods in this type
	 *
	 * @param protectedScope true to include protected methods
	 * @param filterConstructor true to filter constructors
	 * @return a list of visible methods
	 */
	final List<PythonTypeStubMethod> getMethods(boolean protectedScope, boolean filterConstructor) {
		if (methods != null) {
			return methods;
		}
		methods = new ArrayList<>();
		for (Element child : el.getEnclosedElements()) {
			switch (child.getKind()) {
				case CONSTRUCTOR:
					if (filterConstructor) {
						continue;
					}
				case METHOD:
					if (!isVisible(child, protectedScope)) {
						continue;
					}
					if (isUndocumentedOverride(child)) {
						continue;
					}
					methods.add(new PythonTypeStubMethod(this, (ExecutableElement) child,
						filterConstructor));
					break;
				default:
					break;
			}

		}
		// apparently overloads must come one after another
		// therefore this must be sorted
		methods.sort(null);
		return methods;
	}

	/**
	 * Checks if the provided method needs the typing.overload decorator
	 *
	 * @param methods the list of methods
	 * @param it the current iterator
	 * @param method the method to check
	 * @return true if typing.overload should be applied
	 */
	static boolean isOverload(List<PythonTypeStubMethod> methods,
			ListIterator<PythonTypeStubMethod> it, PythonTypeStubMethod method) {
		if (it.hasNext()) {
			if (methods.get(it.nextIndex()).getName().equals(method.getName())) {
				return true;
			}
		}
		int index = it.previousIndex();
		if (index >= 1) {
			// the previous index is actually the index of the method parameter
			if (methods.get(index - 1).getName().equals(method.getName())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Prints the Python class definition for this type to the provided printer
	 *
	 * @param printer the printer
	 * @param indent the current indentation
	 */
	final void printClass(PrintWriter printer, String indent) {
		printClassDefinition(printer, indent);
		indent = indent(indent);
		for (PythonTypeStubNestedType nested : getNestedTypes()) {
			nested.process(printer, indent);
		}
		printClassLiteralField(printer, indent);
		for (VariableElement field : getFields()) {
			printField(field, printer, indent, isStatic(field));
		}
		printer.println();
		ListIterator<PythonTypeStubMethod> methodIterator = getMethods().listIterator();
		while (methodIterator.hasNext()) {
			PythonTypeStubMethod method = methodIterator.next();
			boolean overload = isOverload(getMethods(), methodIterator, method);
			method.process(printer, indent, overload);
		}
		if (!doclet.isUsingPythonProperties()) {
			printer.println();
			return;
		}
		for (Property property : getProperties()) {
			property.process(printer, indent);
		}
		printer.println();
	}

	/**
	 * Prints the provided field to the provided printer
	 *
	 * @param field the field to print
	 * @param printer the printer
	 * @param indent the indentation
	 * @param isStatic true if the field is static
	 */
	void printField(VariableElement field, PrintWriter printer, String indent, boolean isStatic) {
		String name = sanitize(field.getSimpleName());
		printer.print(indent);
		printer.print(name);

		String value = getConstantValue(field);
		if (value != null) {
			// constants are always static final
			printer.print(": typing.Final = ");
			printer.println(value);
		}
		else {
			TypeMirror type = field.asType();
			printer.print(": ");
			String sanitizedType = sanitizeQualifiedName(type);

			// only one of these may be applied
			// prefer Final over ClassVar
			if (isFinal(field)) {
				sanitizedType = applyFinal(sanitizedType);
			}
			else if (isStatic) {
				sanitizedType = applyClassVar(sanitizedType);
			}

			printer.print(sanitizedType);
			printer.println();
		}

		if (writeJavaDoc(field, printer, indent, "")) {
			printer.println();
		}
	}

	/**
	 * Prints the class literal field to the provided printer
	 *
	 * @param printer the printer
	 * @param indent the indentation
	 */
	void printClassLiteralField(PrintWriter printer, String indent) {
		printer.print(indent);
		printer.println("class_: " + applyClassVar(Class.class.getName()));
	}

	/**
	 * Wraps the provided type in typing.ClassVar
	 *
	 * @param type the type to wrap
	 * @return the wrapped type
	 */
	private static String applyClassVar(String type) {
		if (!type.isEmpty()) {
			return "typing.ClassVar[" + type + ']';
		}
		return type;
	}

	/**
	 * Wraps the provided type in typing.Final
	 *
	 * @param type the type to wrap
	 * @return the wrapped type
	 */
	private static String applyFinal(String type) {
		if (!type.isEmpty()) {
			return "typing.Final[" + type + ']';
		}
		return type;
	}

	/**
	 * Gets a list of TypeVars for only this type
	 *
	 * @return the list of TypeVars for this type
	 */
	private List<String> getClassTypeVars() {
		List<? extends TypeParameterElement> params = el.getTypeParameters();
		List<String> res = new ArrayList<>(params.size());
		for (TypeParameterElement param : params) {
			res.add(param.getSimpleName().toString());
		}
		return res;
	}

	/**
	 * Gets a list of the Python properties to be created for this type
	 *
	 * @return the list of Python properties
	 */
	private List<Property> getProperties() {
		if (properties != null) {
			return properties;
		}
		properties = getMethods()
				.stream()
				.filter(PythonTypeStubMethod::isProperty)
				.map(PythonTypeStubMethod::asProperty)
				.collect(Collectors.groupingBy(PythonTypeStubMethod.PropertyMethod::getName))
				.values()
				.stream()
				.map(this::mergeProperties)
				.flatMap(Optional::stream)
				.collect(Collectors.toList());
		return properties;
	}

	/**
	 * Merges the provided pairs into one Python property
	 *
	 * @param pairs the property pairs
	 * @return an optional Python property
	 */
	private Optional<Property> mergeProperties(List<PythonTypeStubMethod.PropertyMethod> pairs) {
		Property res = new Property();
		if (pairs.size() == 1) {
			PythonTypeStubMethod.PropertyMethod p = pairs.get(0);
			if (p.isGetter()) {
				res.getter = p;
			}
			else {
				res.setter = p;
			}
			return Optional.of(res);
		}
		PythonTypeStubMethod.PropertyMethod getter = pairs.stream()
				.filter(PythonTypeStubMethod.PropertyMethod::isGetter)
				.findFirst()
				.orElse(null);
		if (getter != null) {
			// go through all remaining methods and take the first matching pair
			// it does not matter if one is a boxed primitive and the other is
			// unboxed because the JavaProperty will use the primitive type anyway
			PythonTypeStubMethod.PropertyMethod setter = pairs.stream()
					.filter(PythonTypeStubMethod.PropertyMethod::isSetter)
					.filter(getter::isPair)
					.findFirst()
					.orElse(null);
			res.getter = getter;
			res.setter = setter;
			return Optional.of(res);
		}
		return Optional.empty();
	}

	/**
	 * Gets a set of the public method names for this type
	 *
	 * @return the set of public method names
	 */
	private Set<String> getMethodNames() {
		if (methodNames != null) {
			return methodNames;
		}
		methodNames = getMethods().stream()
				.map(PythonTypeStubMethod::getName)
				.collect(Collectors.toCollection(() -> new HashSet<>(getMethods().size())));
		return methodNames;
	}

	/**
	 * Gets a set of the public field names for this type
	 *
	 * @return the set of public field names
	 */
	private Set<String> getFieldNames() {
		if (fieldNames != null) {
			return fieldNames;
		}
		fieldNames = getFields().stream()
				.map(VariableElement::getSimpleName)
				.map(Object::toString)
				.map(PythonTypeStubElement::sanitize)
				.collect(Collectors.toCollection(() -> new HashSet<>(getFields().size())));
		return fieldNames;
	}

	/**
	 * Gets an appropriate Python generic base for the provided type
	 *
	 * @param type the generic type
	 * @param params the type parameters
	 * @return the parameterized generic base type
	 */
	private static String getGenericBase(String type, Iterable<String> params) {
		String generic = GENERIC_CUSTOMIZERS.getOrDefault(type, "typing.Generic");
		return generic + "[" + String.join(", ", params) + "]";
	}

	/**
	 * Prints the first part of the Python class definition
	 *
	 * @param printer the printer
	 * @param indent the indentation
	 */
	private void printClassDefinition(PrintWriter printer, String indent) {
		if (!isPublic(el)) {
			printer.print(indent);
			printer.println("@typing.type_check_only");
		}
		if (doclet.isDeprecated(el)) {
			String msg = doclet.getDeprecatedMessage(el);
			if (msg != null) {
				// a message is required
				// if one is not present, don't apply it
				printer.print(indent);
				printer.print("@deprecated(");
				printer.print(msg);
				printer.println(')');
			}
		}
		printer.print(indent);
		printer.print("class ");
		printer.print(getName());

		String base = getSuperClass();
		if (base == null) {
			// edge case, this is java.lang.Object
			printer.println(":");
			indent = indent(indent);
			writeJavaDoc(printer, indent);
			printer.println();
			return;
		}

		Stream<String> bases;
		if (el.getInterfaces().isEmpty()) {
			bases = Stream.of(base);
		}
		else if (base.equals(OBJECT_NAME)) {
			// Object base isn't needed
			bases = getInterfaces();
		}
		else {
			bases = Stream.concat(Stream.of(base), getInterfaces());
		}

		List<String> typeParams = getClassTypeVars();
		if (!typeParams.isEmpty()) {
			String type = el.getQualifiedName().toString();
			String genericBase = getGenericBase(type, typeParams);
			bases = Stream.concat(bases, Stream.of(genericBase));
		}

		Iterator<String> it = bases.iterator();
		String baseList = String.join(", ", (Iterable<String>) () -> it);
		if (!baseList.isEmpty()) {
			printer.print("(");
			printer.print(baseList);
			printer.print(")");
		}
		printer.println(":");
		indent = indent(indent);
		if (getNestedTypes().isEmpty() && getFields().isEmpty() && getMethods().isEmpty()) {
			writeJavaDoc(printer, indent, "...");
		}
		else {
			writeJavaDoc(printer, indent);
		}
		printer.println();
	}

	/**
	 * Converts the provided float constant to a Python constant
	 *
	 * @param value the value
	 * @return the Python float constant
	 */
	private static String convertFloatConstant(double value) {
		if (Double.isInfinite(value)) {
			if (value < 0.0f) {
				return "float(\"-inf\")";
			}
			return "float(\"inf\")";
		}
		if (Double.isNaN(value)) {
			return "float(\"nan\")";
		}
		return Double.toString(value);
	}

	/**
	 * Converts the provided field to a Python constant if applicable
	 *
	 * @param field the field
	 * @return the constant value or null
	 */
	private String getConstantValue(VariableElement field) {
		Object value = field.getConstantValue();
		return switch (value) {
			case String str -> doclet.getStringLiteral(str);
			case Character str -> doclet.getStringLiteral(str);
			case Boolean flag -> flag ? "True" : "False";
			case Float dec -> convertFloatConstant(dec);
			case Double dec -> convertFloatConstant(dec);
			case null -> null;
			default -> value.toString();
		};
	}

	/**
	 * Checks if this element is an undocumented override
	 *
	 * @param child the element to check
	 * @return true if this override has no additional documentation
	 */
	private boolean isUndocumentedOverride(Element child) {
		if (!doclet.hasJavadoc(child)) {
			return child.getAnnotation(Override.class) != null;
		}
		if (doclet.hasJavadocTag(child, DocTree.Kind.INHERIT_DOC)) {
			return true;
		}
		return false;
	}

	/**
	 * Checks if this element is visible
	 *
	 * @param child the element to check
	 * @param protectedScope true to include protected scope
	 * @return true if this element is visible
	 */
	private boolean isVisible(Element child, boolean protectedScope) {
		if (isPublic(child)) {
			return true;
		}
		if (protectedScope) {
			return isProtected(child);
		}
		return false;
	}

	/**
	 * Gets the base class to use for this type
	 *
	 * @return the base class
	 */
	private String getSuperClass() {
		TypeMirror base = el.getSuperclass();
		if (base.getKind() == TypeKind.NONE) {
			if (el.getQualifiedName().toString().equals(OBJECT_NAME)) {
				return null;
			}
			return OBJECT_NAME;
		}
		return sanitizeQualifiedName(base);
	}

	/**
	 * Gets the interfaces for this type
	 *
	 * @return the interfaces
	 */
	private Stream<String> getInterfaces() {
		return el.getInterfaces()
				.stream()
				.map(this::sanitizeQualifiedName);
	}

	/**
	 * Helper for creating a Python property
	 */
	class Property {
		PythonTypeStubMethod.PropertyMethod getter;
		PythonTypeStubMethod.PropertyMethod setter;

		/**
		 * Prints this property to the provided printer
		 *
		 * @param printer the printer
		 * @param indent the indentation
		 */
		void process(PrintWriter printer, String indent) {
			if (getter == null) {
				// only possible at runtime
				return;
			}
			String name = getter.getName();
			if (name.equals("property")) {
				// it's not a keyword but it makes the type checker go haywire
				// just blacklist it
				return;
			}
			if (getMethodNames().contains(name) || getFieldNames().contains(name)) {
				// do not redefine a method or field
				return;
			}
			String type = sanitizeQualifiedName(getter.getType());
			printer.print(indent);
			printer.println("@property");
			printer.print(indent);
			printer.print("def ");
			printer.print(name);
			printer.print("(self) -> ");
			printer.print(type);
			printer.println(":");
			indent = indent(indent);
			printer.print(indent);
			printer.println("...");
			printer.println();

			if (setter != null) {
				indent = deindent(indent);
				printer.print(indent);
				printer.print("@");
				printer.print(name);
				printer.println(".setter");
				printer.print(indent);
				printer.print("def ");
				printer.print(name);
				printer.print("(self, value: ");
				printer.print(type);
				printer.println("):");
				indent = indent(indent);
				printer.print(indent);
				printer.println("...");
				printer.println();
			}
		}
	}
}
