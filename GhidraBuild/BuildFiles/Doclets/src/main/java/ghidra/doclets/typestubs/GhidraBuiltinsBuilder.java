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

import java.io.*;
import java.util.*;

import javax.lang.model.element.*;
import javax.lang.model.util.Elements;

/**
 * A builder class for the pseudo ghidra.ghidra_builtins package
 */
class GhidraBuiltinsBuilder {

	private static final String INDENT = "";

	private final PythonTypeStubDoclet doclet;
	private final PythonTypeStubType api;
	private final PythonTypeStubType script;

	/**
	 * Creates a new {@link GhidraBuiltinsBuilder}
	 *
	 * @param doclet the current doclet
	 */
	GhidraBuiltinsBuilder(PythonTypeStubDoclet doclet) {
		this.doclet = doclet;
		this.api = getType(doclet, "ghidra.program.flatapi.FlatProgramAPI");
		this.script = getType(doclet, "ghidra.app.script.GhidraScript");
	}

	/**
	 * Processes the pseudo ghidra.ghidra_builtins package
	 */
	void process() {
		File root = new File(doclet.getDestDir(), "ghidra-stubs/ghidra_builtins");
		root.mkdirs();
		File stub = new File(root, "__init__.pyi");
		try (PrintWriter printer = new PrintWriter(new FileWriter(stub))) {
			process(printer);
		}
		catch (IOException e) {
			e.printStackTrace();
		}

		File pypredefDir = new File(doclet.getDestDir().getParentFile(), "pypredef");
		File pypredefFile = new File(pypredefDir, "ghidra.ghidra_builtins.pypredef");
		pypredefDir.mkdirs();
		try (PrintWriter printer = new PrintWriter(new FileWriter(pypredefFile))) {
			process(printer);
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Processes the pseudo ghidra.ghidra_builtins package using the provided printer
	 *
	 * @param printer the printer
	 */
	private void process(PrintWriter printer) {
		// collect methods and fields early to ensure protected visibility
		api.getMethods(true, true);
		script.getMethods(true, true);
		api.getFields(true);
		script.getFields(true);

		script.writeJavaDoc(printer, INDENT);
		printer.println();

		printScriptImports(printer);
		printTypeVars(printer);

		// we need to keep track of things to export for __all__
		Set<String> exports = new LinkedHashSet<>();

		printFields(printer, exports);

		printer.println();
		printer.println();

		printMethods(printer, exports);

		printer.print("__all__ = [");
		printer.print(String.join(", ", exports));
		printer.println("]");
	}

	/**
	 * Prints all necessary TypeVars
	 *
	 * @param printer the printer
	 */
	private void printTypeVars(PrintWriter printer) {
		for (String typevar : getScriptTypeVars()) {
			printer.print(typevar);
			printer.print(" = typing.TypeVar(\"");
			printer.print(typevar);
			printer.println("\")");
		}
		printer.println();
		printer.println();
	}

	/**
	 * Prints all the script fields
	 *
	 * @param printer the printer
	 * @param exports the set of fields to export
	 */
	private void printFields(PrintWriter printer, Set<String> exports) {
		// always use false for static so typing.ClassVar is not emitted
		for (VariableElement field : api.getFields(true)) {
			api.printField(field, printer, INDENT, false);
			exports.add('"' + field.getSimpleName().toString() + '"');
		}
		for (VariableElement field : script.getFields(true)) {
			script.printField(field, printer, INDENT, false);
			exports.add('"' + field.getSimpleName().toString() + '"');
		}
	}

	/**
	 * Prints all the script methods
	 *
	 * @param printer the printer
	 * @param exports the set of methods to export
	 */
	private void printMethods(PrintWriter printer, Set<String> exports) {
		// methods must be sorted by name for typing.overload
		List<PythonTypeStubMethod> apiMethods = filter(api.getMethods(true, true));
		List<PythonTypeStubMethod> scriptMethods = filter(script.getMethods(true, true));

		int length = apiMethods.size() + scriptMethods.size();
		List<PythonTypeStubMethod> methods = new ArrayList<>(length);

		methods.addAll(apiMethods);
		methods.addAll(scriptMethods);
		methods.sort(null);

		ListIterator<PythonTypeStubMethod> methodIterator = methods.listIterator();

		while (methodIterator.hasNext()) {
			PythonTypeStubMethod method = methodIterator.next();
			boolean overload = PythonTypeStubType.isOverload(methods, methodIterator, method);
			method.process(printer, INDENT, overload);
			exports.add('"' + method.getName() + '"');
			printer.println();
		}
	}

	/**
	 * Gets a list of all imported packages
	 *
	 * @return the list of packages
	 */
	private List<PackageElement> getScriptPackages() {
		Set<PackageElement> packages = new HashSet<>();
		for (TypeElement type : api.getImportedTypes()) {
			packages.add(PythonTypeStubElement.getPackage(type));
		}
		for (TypeElement type : script.getImportedTypes()) {
			packages.add(PythonTypeStubElement.getPackage(type));
		}
		List<PackageElement> res = new ArrayList<>(packages);
		res.sort(PythonTypeStubElement::compareQualifiedNameable);
		return res;
	}

	/**
	 * Prints the imports needed by this package
	 *
	 * @param printer the printer
	 */
	private void printScriptImports(PrintWriter printer) {
		printer.println("from __future__ import annotations");
		printer.println("import collections.abc");
		printer.println("import typing");
		printer.println("from warnings import deprecated # type: ignore");
		printer.println();
		printer.println("import jpype # type: ignore");
		printer.println("import jpype.protocol # type: ignore");
		printer.println();
		doclet.printImports(printer, getScriptPackages());
		printer.println();
		printer.println();
		printer.println("from ghidra.app.script import *");
		printer.println();
		printer.println();
	}

	/**
	 * Gets a list of TypeVars needed by this package
	 *
	 * @return the list of TypeVars
	 */
	private List<String> getScriptTypeVars() {
		// all this for only two typing.TypeVar
		// at least this is future proof
		Set<String> vars = new HashSet<>(api.getTypeVars());
		vars.addAll(script.getTypeVars());

		List<String> res = new ArrayList<>(vars);
		res.sort(null);
		return res;
	}

	/**
	 * Gets the PythonTypeStubType for the provided type name
	 *
	 * @param doclet the current doclet
	 * @param name the type name
	 * @return the requested type
	 */
	private static PythonTypeStubType getType(PythonTypeStubDoclet doclet, String name) {
		Elements elements = doclet.getElementUtils();
		TypeElement type = elements.getTypeElement(name);
		PackageElement pkg = (PackageElement) type.getEnclosingElement();
		return new PythonTypeStubType(new PythonTypeStubPackage(doclet, pkg), type);
	}

	/**
	 * Filters out methods that should not be considered for type generation.
	 * <p>
	 * One use case of this is to prevent Ghidra methods from overriding built-in Python methods
	 * that have a higher precedence.
	 * 
	 * @param methods The methods to filter
	 * @return A new {@link List} of filtered methods
	 */
	private List<PythonTypeStubMethod> filter(List<PythonTypeStubMethod> methods) {
		final Set<String> EXCLUDES = Set.of("set");
		return methods.stream().filter(m -> !EXCLUDES.contains(m.getName())).toList();
	}
}
