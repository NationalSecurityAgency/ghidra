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
package ghidra.app.util;

import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;

/**
 * A class to hold utility methods for working with namespaces.
 * <p>
 * <a id="examples"></a>
 * Example string format:
 * <ul>
 *     <li>global{@link Namespace#DELIMITER ::}child1{@link Namespace#DELIMITER ::}child2
 *     <li>child1
 * </ul>
 * <a id="assumptions"></a>
 * <b>Assumptions for creating namespaces from a path string: </b>
 * <ul>
 *     <li>All elements of a namespace path should be namespace symbols and not other
 *         symbol types.         
 *     <li>Absolute paths can optionally start with the global namespace.
 *     <li>You can provide a relative path that will start at the given
 *         parent namespace (or global if there is no parent provided).
 *     <li>You can provide a path that has as its first entry the name of the
 *         given parent.  In this case, the first entry will not be created,
 *         but rather the provided parent will be used.
 *     <li>If you provide a path and a parent, but the first element of the
 *         path is the global namespace, then the global namespace will be
 *         used as the parent namespace and not the one that was provided.
 *     <li>You cannot embed the global namespace in a path, but it can be at
 *         the root.
 * </ul>
 *
 *
 */
public class NamespaceUtils {

	private NamespaceUtils() {
		// singleton utils class--no public construction
	}

	/**
	 * Get the normal namespace path excluding any library name.  Global namespace will be
	 * returned as empty string, while other namespace paths will be returned with trailing ::
	 * suffix.
	 * @param namespace namespace
	 * @return namespace path excluding any library name
	 */
	public static String getNamespacePathWithoutLibrary(Namespace namespace) {
		String str = new String();
		while (namespace != null && !(namespace instanceof GlobalNamespace) &&
			!(namespace instanceof Library)) {
			str = namespace.getName() + Namespace.DELIMITER + str;
			namespace = namespace.getParentNamespace();
		}
		return str;
	}

	/**
	 * Get namespace qualified symbol name
	 * @param namespace namespace object
	 * @param symbolName name of symbol
	 * @param excludeLibraryName if true any library name will be excluded from path returned,
	 * otherwise it will be included
	 * @return namespace qualified symbol name
	 */
	public static String getNamespaceQualifiedName(Namespace namespace, String symbolName,
			boolean excludeLibraryName) {
		String str = "";
		if (excludeLibraryName && namespace.isExternal()) {
			str = getNamespacePathWithoutLibrary(namespace);
		}
		else if (namespace != null && !(namespace instanceof GlobalNamespace)) {
			str = namespace.getName(true) + Namespace.DELIMITER;
		}
		str += symbolName;
		return str;
	}

	/**
	 * Provide a standard method for splitting a symbol path into its
	 * various namespace and symbol name elements.  While the current implementation
	 * uses a very simplistic approach, this may be improved upon in the future
	 * to handle various grouping concepts.
	 * @param path symbol namespace path (path will be trimmed before parse)
	 * @return order list of namespace names
	 * @deprecated use SymbolPath instead
	 */
	@Deprecated
	public static List<String> splitNamespacePath(String path) {
		return Arrays.asList(path.trim().split(Namespace.DELIMITER));
	}

	/**
	 * Get the library associated with the specified namespace
	 * @param namespace namespace
	 * @return associated library or null if not associated with a library
	 */
	public static Library getLibrary(Namespace namespace) {
		Namespace ns = namespace;
		while (ns.isExternal()) {
			if (ns instanceof Library) {
				return (Library) ns;
			}
			ns = ns.getParentNamespace();
		}
		return null;
	}

	/**
	 * Returns a list of all namespaces with the given name in the parent namespace
	 * 
	 * @param program the program to search
	 * @param parent the parent namespace from which to find all namespaces with the given name;
	 *        if null, the global namespace will be used
	 * @param namespaceName the name of the namespaces to retrieve
	 * @return a list of all namespaces that match the given name in the given parent namespace.
	 */
	public static List<Namespace> getNamespacesByName(Program program, Namespace parent,
			String namespaceName) {
		validate(program, parent);
		List<Namespace> namespaceList = new ArrayList<>();
		List<Symbol> symbols = program.getSymbolTable().getSymbols(namespaceName, parent);
		for (Symbol symbol : symbols) {
			if (symbol.getSymbolType().isNamespace()) {
				namespaceList.add((Namespace) symbol.getObject());
			}
		}
		return namespaceList;
	}

	/**
	 * Returns a list of namespaces that match the given path.  The path can be
	 * relative to the given root namespace or absolute if the path begins with
	 * the global namespace name.
	 *
	 * <P>Note: this path must only contain Namespace names and no other symbol types.
	 * 
	 * @param program the program to search
	 * @param parent the namespace to use as the root for relative paths. If null, the
	 * 		  global namespace will be used
	 * @param pathString the path to the desired namespace
	 * @return a list of namespaces that match the given path
	 */
	public static List<Namespace> getNamespaceByPath(Program program, Namespace parent,
			String pathString) {

		validate(program, parent);

		parent = adjustForNullRootNamespace(parent, pathString, program);

		SymbolPath path = new SymbolPath(parent.getSymbol());
		if (pathString != null) {
			path = path.append(new SymbolPath(pathString));
		}

		List<String> namespaceNames = path.asList();
		List<Namespace> namespaces = doGetNamespaces(namespaceNames, parent, program);
		return namespaces;
	}

	private static List<Namespace> doGetNamespaces(List<String> namespaceNames,
			Namespace root, Program program) {

		if (root == null) {
			root = program.getGlobalNamespace();
		}

		List<Namespace> parents = Arrays.asList(root);
		for (String name : namespaceNames) {
			List<Namespace> matches = getMatchingNamespaces(name, parents, program);
			parents = matches;
		}
		return parents;
	}

	/**
	 * Returns a list all namespaces that have the given name in any of the given namespaces
	 *
	 * @param childName the name of the namespaces to retrieve
	 * @param parents a list of all namespaces to search for child namespaces with the given name
	 * @param program the program to search
	 * @return a list all namespaces that have the given name in any of the given namespaces
	 */
	public static List<Namespace> getMatchingNamespaces(String childName, List<Namespace> parents,
			Program program) {
		validate(program, parents);
		List<Namespace> list = new ArrayList<>();
		for (Namespace parent : parents) {
			list.addAll(getNamespacesByName(program, parent, childName));
		}

		return list;
	}

	/**
	 * Returns a list all symbols that have the given name in any of the given
	 * parent namespaces.
	 *
	 * @param parents a list of all namespaces to search for symbols with the given name.
	 * @param symbolName the name of the symbols to retrieve.
	 * @param program the program to search.
	 * @return a list all symbols that have the given name in any of the given namespaces.
	 */
	private static List<Symbol> searchForAllSymbolsInAnyOfTheseNamespaces(List<Namespace> parents,
			String symbolName, Program program) {

		List<Symbol> list = new ArrayList<>();
		for (Namespace parent : parents) {
			list.addAll(program.getSymbolTable().getSymbols(symbolName, parent));
		}

		return list;

	}

	/**
	 * Returns a list of all symbols that match the given path. The path consists of a series
	 * of namespaces names separated by "::" followed by a label or function name.
	 *
	 * @param symbolPath the names of namespaces and symbol separated by "::".
	 * @param program the program to search
	 * @return the list of symbols that match the given
	 */
	public static List<Symbol> getSymbols(String symbolPath, Program program) {

		List<String> namespaceNames = new SymbolPath(symbolPath).asList();
		if (namespaceNames.isEmpty()) {
			return Collections.emptyList();
		}

		String symbolName = namespaceNames.remove(namespaceNames.size() - 1);
		List<Namespace> parents =
			doGetNamespaces(namespaceNames, program.getGlobalNamespace(), program);
		return searchForAllSymbolsInAnyOfTheseNamespaces(parents, symbolName, program);
	}

	/**
	 * Returns a list of Symbol that match the given symbolPath.
	 *
	 * @param symbolPath the symbol path that specifies a series of namespace and symbol names.
	 * @param program the program to search for symbols with the given path.
	 * @return  a list of Symbol that match the given symbolPath.
	 */
	public static List<Symbol> getSymbols(SymbolPath symbolPath, Program program) {
		SymbolPath parentPath = symbolPath.getParent();
		if (parentPath == null) {
			return program.getSymbolTable().getGlobalSymbols(symbolPath.getName());
		}
		List<Namespace> parents = doGetNamespaces(parentPath.asList(), null, program);
		return searchForAllSymbolsInAnyOfTheseNamespaces(parents, symbolPath.getName(), program);
	}

	/**
	 * Returns the first namespace with the given name and that is NOT a function that
	 * is within the parent namespace. (ie. the first namespace that is not tied to a program
	 * address)
	 *
	 * @param parent the parent namespace to search
	 * @param namespaceName the name of the namespace to find
	 * @param program the program to search.
	 * @return the first namespace that matches, or null if no match.
	 */
	public static Namespace getFirstNonFunctionNamespace(Namespace parent, String namespaceName,
			Program program) {
		validate(program, parent);
		List<Symbol> symbols = program.getSymbolTable().getSymbols(namespaceName, parent);
		for (Symbol symbol : symbols) {
			if (symbol.getSymbolType().isNamespace() &&
				symbol.getSymbolType() != SymbolType.FUNCTION) {
				return (Namespace) symbol.getObject();
			}
		}
		return null;
	}

	/**
	 * Takes a namespace path string and creates a namespace hierarchy to
	 * match that string.  This method ignores function namespaces so the path
	 * should not contain any function names.  If you want traverse down through
	 * functions, then use the version that also takes an address that is used to distinguish
	 * between multiple functions with the same name.
	 * <P>
	 * The root namespace can be a function.
	 *
	 *
	 * @param  namespacePath The namespace name or path string to be parsed.
	 *         This value should not include a trailing symbol name, only namespace names.
	 * @param  rootNamespace The parent namespace under which the desired
	 *         namespace or path resides.  If this value is null, then the
	 *         global namespace will be used. This namespace can be a function name;
	 * @param  program The current program in which the desired namespace
	 *         resides.
	 * @param  source the source type of the namespace
	 * @return The namespace that matches the given path.  This can be either an existing
	 *         namespace or a newly created one.
	 * @throws InvalidInputException If a given namespace name is in an
	 *         invalid format and this method attempts to create that
	 *         namespace, or if the namespace string contains the global
	 *         namespace name in a position other than the root.
	 * @see    <a href="#assumptions">assumptions</a>
	 */
	public static Namespace createNamespaceHierarchy(String namespacePath, Namespace rootNamespace,
			Program program, SourceType source) throws InvalidInputException {
		return createNamespaceHierarchy(namespacePath, rootNamespace, program, null, source);
	}

	/**
	 * Takes a namespace path string and creates a namespace hierarchy to
	 * match that string.  This method allows function namespaces in the path
	 * and uses the given address to resolve functions with duplicate names.  When
	 * resolving down the namespace path, a function that matches a name will only
	 * be used if the given address is contained in the body of that function.
	 * 
	 * <p>The root namespace can be a function.
	 * 
	 * <p>If an address is passed, then the path can contain a function name provided the 
	 * address is in the body of the function; otherwise the names must all be namespaces other 
	 * than functions.
	 *
	 * @param  namespacePath The namespace name or path string to be parsed
	 *         This value should not include a trailing symbol name, only namespace names
	 * @param  rootNamespace The parent namespace under which the desired
	 *         namespace or path resides.  If this value is null, then the
	 *         global namespace will be used.
	 * @param  program The current program in which the desired namespace
	 *         resides
	 * @param  address the address used to resolve possible functions with duplicate names; may
	 *         be null
	 * @param  source the source of the namespace
	 * @return The namespace that matches the given path.  This can be either an existing
	 *         namespace or a newly created one.
	 * @throws InvalidInputException If a given namespace name is in an
	 *         invalid format and this method attempts to create that
	 *         namespace, or if the namespace string contains the global
	 *         namespace name in a position other than the root.
	 * @see    <a href="#assumptions">assumptions</a>
	 */
	public static Namespace createNamespaceHierarchy(String namespacePath, Namespace rootNamespace,
			Program program, Address address, SourceType source) throws InvalidInputException {
		validate(program, rootNamespace);
		rootNamespace = adjustForNullRootNamespace(rootNamespace, namespacePath, program);
		if (namespacePath == null) {
			return rootNamespace;
		}

		SymbolPath path = new SymbolPath(namespacePath);
		List<String> namespacesList = path.asList();

		SymbolTable symbolTable = program.getSymbolTable();
		Namespace namespace = rootNamespace;
		for (String namespaceName : namespacesList) {
			Namespace ns = getNamespace(program, namespace, namespaceName, address);
			if (ns == null) {
				try {
					ns = symbolTable.createNameSpace(namespace, namespaceName, source);
				}
				catch (DuplicateNameException e) {
					throw new AssertException(
						"Duplicate name exception should not be possible here since we checked first!");
				}
			}
			namespace = ns;
		}

		return namespace;
	}

	/**
	 * Returns the existing Function at the given address if its {@link SymbolPath} matches the
	 * given path  
	 *
	 * @param program the program
	 * @param symbolPath the path of namespace
	 * @param address the address 
	 * @return the namespace represented by the given path, or null if no such namespace exists
	 */
	public static Namespace getFunctionNamespaceAt(Program program, SymbolPath symbolPath,
			Address address) {

		if (symbolPath == null || address == null) {
			return null;
		}

		Symbol[] symbols = program.getSymbolTable().getSymbols(address);
		for (Symbol symbol : symbols) {
			if (symbol.getSymbolType() == SymbolType.FUNCTION &&
				symbolPath.matchesPathOf(symbol)) {
				return (Function) symbol.getObject();
			}
		}
		return null;
	}

	/**
	 * Returns the existing Function containing the given address if its 
	 * {@link SymbolPath} matches the given path  
	 *
	 * @param program the program
	 * @param symbolPath the path of namespace
	 * @param address the address 
	 * @return the namespace represented by the given path, or null if no such namespace exists
	 */
	public static Namespace getFunctionNamespaceContaining(Program program, SymbolPath symbolPath,
			Address address) {

		if (symbolPath == null || address == null) {
			return null;
		}

		FunctionManager fm = program.getFunctionManager();
		Function f = fm.getFunctionContaining(address);
		if (f != null) {
			if (symbolPath.matchesPathOf(f.getSymbol())) {
				return f;
			}
		}
		return null;
	}

	/**
	 * Finds the namespace for the given symbol path <b>that is not a function</b>
	 *
	 * @param program the program from which to get the namespace
	 * @param symbolPath the path of namespace names including the name of the desired namespace
	 * @return the namespace represented by the given path, or null if no such namespace exists or
	 *         the namespace is a function
	 */
	public static Namespace getNonFunctionNamespace(Program program, SymbolPath symbolPath) {

		if (symbolPath == null) {
			return program.getGlobalNamespace();
		}

		List<Symbol> symbols = getSymbols(symbolPath, program);
		for (Symbol symbol : symbols) {
			if (symbol.getSymbolType() != SymbolType.FUNCTION &&
				symbol.getSymbolType().isNamespace()) {
				return (Namespace) symbol.getObject();
			}
		}
		return null;
	}

	private static Namespace getNamespace(Program program, Namespace parent, String name,
			Address address) {

		if (parent == null) {
			return null;
		}

		List<Symbol> symbols = program.getSymbolTable().getSymbols(name, parent);

		// first see if there are any functions and if they contain the given address
		if (address != null) {
			for (Symbol symbol : symbols) {
				if (symbol.getSymbolType() == SymbolType.FUNCTION) {
					Function function = (Function) symbol.getObject();
					if (function.getBody().contains(address)) {
						return function;
					}
				}
			}
		}
		// otherwise just see if there is a non-function namespace
		for (Symbol symbol : symbols) {
			SymbolType type = symbol.getSymbolType();
			if (type != SymbolType.FUNCTION && type.isNamespace()) {
				return (Namespace) symbol.getObject();
			}
		}

		return null;
	}

	private static Namespace adjustForNullRootNamespace(Namespace parentNamespace,
			String namespacePath, Program program) {
		Namespace globalNamespace = program.getGlobalNamespace();
		if (namespacePath != null && namespacePath.startsWith(globalNamespace.getName())) {
			return globalNamespace;
		}

		if (parentNamespace != null) {
			return parentNamespace;
		}

		return globalNamespace;
	}

	private static void validate(Program program, Namespace namespace) {
		if (namespace != null && !namespace.isGlobal()) {
			if (program != namespace.getSymbol().getProgram()) {
				throw new IllegalArgumentException(
					"Given namespace does not belong to the given program");
			}
		}
	}

	private static void validate(Program program, List<Namespace> parents) {
		for (Namespace namespace : parents) {
			validate(program, namespace);
		}
	}

	/**
	 * Convert a namespace to a class by copying all namespace children into a newly created class
	 * and then removing the old namespace
	 * 
	 * @param namespace namespace to be converted
	 * @return new class namespace
	 * @throws InvalidInputException if namespace was contained within a function and can not be
	 * 			converted to a class
	 */
	public static GhidraClass convertNamespaceToClass(Namespace namespace)
			throws InvalidInputException {

		Symbol namespaceSymbol = namespace.getSymbol();
		SymbolTable symbolTable = namespaceSymbol.getProgram().getSymbolTable();
		return symbolTable.convertNamespaceToClass(namespace);
	}
}
