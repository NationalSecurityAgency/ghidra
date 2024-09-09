package ghidra.doclets.typestubs;

import java.io.PrintWriter;

import javax.lang.model.element.TypeElement;

/**
 * {@link PythonTypeStubElement} for a nested type
 */
final class PythonTypeStubNestedType extends PythonTypeStubType {

	// while it is possible to create a pseudo sub module to
	// make static nested classes and enum values individually
	// importable during type checking, it's not worth the effort

	/**
	 * Creates a new {@link PythonTypeStubNestedType}
	 *
	 * @param pkg the package containing this type
	 * @param el the element for this type
	 */
	PythonTypeStubNestedType(PythonTypeStubPackage pkg, TypeElement el) {
		super(pkg, el);
	}

	@Override
	void process(PrintWriter printer, String indent) {
		printClass(printer, indent);
	}
}
