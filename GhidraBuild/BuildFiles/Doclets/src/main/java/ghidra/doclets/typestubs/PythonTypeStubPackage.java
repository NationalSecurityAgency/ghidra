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

/**
 * {@link PythonTypeStubElement} for a package<p/>
 *
 * This will process all visible classes, interfaces, handle necessary imports
 * and create the __init__.pyi file.
 */
final class PythonTypeStubPackage extends PythonTypeStubElement<PackageElement> {

	private String packageName;
	private File path;
	private List<PythonTypeStubType> types;

	/**
	 * Creates a new {@link PythonTypeStubPackage}
	 *
	 * @param doclet the current doclet
	 * @param el the element for this package
	 */
	PythonTypeStubPackage(PythonTypeStubDoclet doclet, PackageElement el) {
		super(doclet, el);
	}

	/**
	 * Gets a list of all the TypeVars needed by the types in this package
	 *
	 * @return a list of all the needed TypeVars
	 */
	List<String> getTypeVars() {
		Set<String> typevars = new HashSet<>();
		for (PythonTypeStubType type : getTypes()) {
			typevars.addAll(type.getTypeVars());
		}
		List<String> res = new ArrayList<>(typevars);
		res.sort(null);
		return res;
	}

	/**
	 * Gets a collection of all the imported types needed by the types in this package
	 *
	 * @return a collection of all the imported types
	 */
	Collection<TypeElement> getImportedTypes() {
		Set<TypeElement> imported = new HashSet<>();
		for (PythonTypeStubType type : getTypes()) {
			imported.addAll(type.getImportedTypes());
		}
		return imported;
	}

	/**
	 * Gets the Python safe, fully qualified name for this package
	 *
	 * @return the qualified package name
	 */
	String getPackageName() {
		if (packageName == null) {
			packageName = sanitizeQualifiedName(el.getQualifiedName().toString());
		}
		return packageName;
	}

	/**
	 * Processes this package and its contents to create a __init__.pyi file
	 */
	void process() {
		doclet.addProcessedPackage(el);
		getPath().mkdirs();
		File stub = new File(path, "__init__.pyi");
		try (PrintWriter printer = new PrintWriter(new FileWriter(stub))) {
			process(printer, "");
		}
		catch (IOException e) {
			e.printStackTrace();
		}

		File pypredefDir = new File(doclet.getDestDir().getParentFile(), "pypredef");
		File pypredefFile = new File(pypredefDir, packageName + ".pypredef");
		pypredefDir.mkdirs();
		try (PrintWriter printer = new PrintWriter(new FileWriter(pypredefFile))) {
			process(printer, "");
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Gets a list of all the types declared in this package
	 *
	 * @return a list of all specified types
	 */
	List<PythonTypeStubType> getTypes() {
		// NOTE: do ALL SPECIFIED TYPES
		// if it is not public, it will be decorated with @typing.type_check_only
		// this prevents errors during typechecking from having a class with a base
		// class that doesn't have public visibility
		if (types != null) {
			return types;
		}
		types = new ArrayList<>();
		for (Element child : el.getEnclosedElements()) {
			switch (child.getKind()) {
				case CLASS:
				case INTERFACE:
				case ENUM:
				case RECORD:
					if (!doclet.isSpecified(child)) {
						continue;
					}
					types.add(new PythonTypeStubType(this, (TypeElement) child));
					break;
				default:
					break;
			}
		}
		return types;
	}

	/**
	 * Process the contents of this package and write the results to the provided printer
	 *
	 * @param printer the printer to write to
	 * @param indent the current indentation
	 */
	private void process(PrintWriter printer, String indent) {
		writeJavaDoc(printer, indent, "");
		printer.println("from __future__ import annotations");
		printer.println("import collections.abc");
		printer.println("import datetime");
		printer.println("import typing");
		printer.println("from warnings import deprecated # type: ignore");
		printer.println();
		printer.println("import jpype # type: ignore");
		printer.println("import jpype.protocol # type: ignore");
		printer.println();
		doclet.printImports(printer, getImportedPackages());
		printer.println();
		printer.println();
		printTypeVars(printer);
		Set<String> exports = new LinkedHashSet<>();
		for (PythonTypeStubType type : getTypes()) {
			processType(printer, indent, type);
			exports.add('"' + type.getName() + '"');
		}
		printer.println();

		// create the __all__ variable to prevent our imports and TypeVars from being
		// imported when "from {getPackageName()} import *" is used
		printer.print("__all__ = [");
		printer.print(String.join(", ", exports));
		printer.println("]");
	}

	/**
	 * Gets the output directory for this package
	 *
	 * @return the output directory
	 */
	private File getPath() {
		if (path == null) {
			String name = getPackageName();
			int index = name.indexOf('.');
			if (index != -1) {
				name = name.substring(0, index) + "-stubs" + name.substring(index);
			}
			else {
				name += "-stubs";
			}
			path = new File(doclet.getDestDir(), name.replace('.', '/'));
		}
		return path;
	}

	/**
	 * Gets a collection of all imported packages
	 *
	 * @return a collection of all imported packages
	 */
	private Collection<PackageElement> getImportedPackages() {
		Set<PackageElement> packages = new HashSet<>();
		for (TypeElement element : getImportedTypes()) {
			if (isNestedType(element)) {
				// don't import types declared in this file
				continue;
			}

			PackageElement importedPkg = getPackage(element);
			if (importedPkg == null || el.equals(importedPkg)) {
				continue;
			}
			packages.add(importedPkg);
		}

		List<PackageElement> res = new ArrayList<>(packages);
		res.sort(PythonTypeStubElement::compareQualifiedNameable);
		return res;
	}

	/**
	 * Processes the provided type and write it to the provided printer
	 *
	 * @param printer the printer
	 * @param indent the current indentation
	 * @param type the type
	 */
	private void processType(PrintWriter printer, String indent, PythonTypeStubType type) {
		type.process(printer, indent);
	}

	/**
	 * Checks if the provided type is a nested type
	 *
	 * @param element the type element to check
	 * @return true if the type is declared within another class
	 */
	private static boolean isNestedType(TypeElement element) {
		return element.getEnclosingElement() instanceof TypeElement;
	}

	/**
	 * Prints all the typevars to the provided printer
	 *
	 * @param printer the printer
	 */
	private void printTypeVars(PrintWriter printer) {
		List<String> allTypeVars = getTypeVars();
		for (String generic : allTypeVars) {
			printer.println(generic + " = typing.TypeVar(\"" + generic + "\")");
		}
		if (!allTypeVars.isEmpty()) {
			printer.println();
			printer.println();
		}
	}
}
