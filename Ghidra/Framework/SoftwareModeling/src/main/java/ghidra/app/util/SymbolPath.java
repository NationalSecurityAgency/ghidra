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

import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.Library;
import ghidra.program.model.symbol.*;

/**
 * A convenience object for parsing a namespace path to a symbol.
 * <P>
 * For example, if a SymbolPath is constructed with "foo::bar::baz", then "baz" is the
 * name of a symbol in the "bar" namespace, which is in the "foo" namespace.
 * <P>
 * <UL>
 * <LI>{@link #getName()} will return "baz".
 * <LI>{@link #getParentPath()} will return "foo:bar".
 * <LI>{@link #getPath()} will return "foo::bar::baz".
 * </UL>
 *
 */
public class SymbolPath implements Comparable<SymbolPath> {

	private final SymbolPath parentPath;
	private final String symbolName;

	/**
	 * Construct a SymbolPath from a string containing NAMESPACE_DELIMITER ("::") sequences to
	 * separate the namespace names.  This is the only constructor that employs special
	 * string-based namespace parsing.
	 * @param symbolPathString the string to parse as a sequence of namespace names separated by
	 * "::".
	 */
	public SymbolPath(String symbolPathString) {
		this(SymbolPathParser.parse(symbolPathString));
	}

	/**
	 * Construct a SymbolPath from an array of strings where each string is the name of a namespace
	 * in the symbol path.
	 *
	 * @param symbolPath the array of names of namespaces.
	 */
	public SymbolPath(String[] symbolPath) {
		this(Arrays.asList(symbolPath));
	}

	/**
	 * Construct a SymbolPath from a list of strings where each string is the name of a namespace
	 * in the symbol path.
	 *
	 * @param symbolList the array of names of namespaces.
	 * @throws IllegalArgumentException if the given list is null or empty.
	 */
	public SymbolPath(List<String> symbolList) {
		if (symbolList == null || symbolList.isEmpty()) {
			throw new IllegalArgumentException(
				"Symbol list must contain at least one symbol name!");
		}
		symbolName = symbolList.get(symbolList.size() - 1);
		if (symbolList.size() == 1) {
			parentPath = null;
		}
		else {
			parentPath = checkGlobal(new SymbolPath(symbolList.subList(0, symbolList.size() - 1)));
		}
	}

	/**
	 * Constructs a new SymbolPath for the given symbol.
	 *
	 * @param symbol the symbol to get a SymbolPath for.
	 */
	public SymbolPath(Symbol symbol) {
		this(symbol, false);
	}

	/**
	 * Constructs a new SymbolPath for the given symbol with the option to exclude a beginning
	 * library name.
	 *
	 * @param symbol the symbol to get a SymbolPath for.
	 * @param excludeLibrary if true, any library name at the front of the path will be removed.
	 */
	public SymbolPath(Symbol symbol, boolean excludeLibrary) {
		symbolName = symbol.getName();
		Namespace parentNamespace = symbol.getParentNamespace();
		if (parentNamespace == null || parentNamespace.isGlobal()) {
			parentPath = null;
		}
		else if (excludeLibrary && (parentNamespace instanceof Library)) {
			parentPath = null;
		}
		else {
			parentPath = new SymbolPath(parentNamespace.getSymbol());
		}
	}

	/**
	 * Creates a Symbol from a parent SymbolPath and a symbol name.
	 * @param parent the parent SymbolPath. Can be null if the name is in the global space.
	 * @param name the name of the symbol. This can't be null;
	 */
	public SymbolPath(SymbolPath parent, String name) {
		this.symbolName = Objects.requireNonNull(name);
		this.parentPath = checkGlobal(parent);
	}

	/**
	 * Returns a new SymbolPath in which invalid characters are replaced
	 * with underscores.
	 * @return the new SymbolPath with replaced characters.
	 */
	public SymbolPath replaceInvalidChars() {
		List<String> modList = new ArrayList<>();
		for (String str : asList()) {
			modList.add(SymbolUtilities.replaceInvalidChars(str, true));
		}
		return new SymbolPath(modList);
	}

	/**
	 * Returns the name of the symbol;
	 * 
	 * @return the symbol name as string without any path information.
	 */
	public String getName() {
		return symbolName;
	}

	/**
	 * Returns the SymbolPath for the parent namespace or null if the parent is the global space.
	 *
	 * @return  the SymbolPath for the parent namespace or null if the parent is the global space.
	 */
	public SymbolPath getParent() {
		return parentPath;
	}

	/**
	 * Returns null if the parent is null or global; otherwise returns the path as a string of the
	 * parent namespace path.
	 *
	 * @return the path of the parent namespace as string. Returns null if the parent is null or global.
	 */
	public String getParentPath() {
		if (parentPath == null) {
			return null;
		}
		return parentPath.getPath();
	}

	/**
	 * Returns the full symbol path as a string.
	 * 
	 * @return the SymbolPath for the complete name as string, including namespace.
	 */
	public String getPath() {
		if (parentPath != null) {
			return parentPath.getPath() + Namespace.DELIMITER + symbolName;
		}
		return symbolName;
	}

	/**
	 * Creates a new SymbolPath composed of the list of names in this path followed by the
	 * list of names in the given path.
	 * @param path the path of names to append to this path.
	 * @return a new SymbolPath that appends the given path to this path.
	 */
	public SymbolPath append(SymbolPath path) {
		List<String> list = asList();
		list.addAll(path.asList());
		return new SymbolPath(list);
	}

	/**
	 * Returns true if this path contains any path entry matching the given text
	 * 
	 * @param text the text for which to search
	 * @return true if any path entry matches the given text
	 */
	public boolean containsPathEntry(String text) {
		return asList().contains(text);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((parentPath == null) ? 0 : parentPath.hashCode());
		result = prime * result + ((symbolName == null) ? 0 : symbolName.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		SymbolPath other = (SymbolPath) obj;
		if (!Objects.equals(parentPath, other.parentPath)) {
			return false;
		}
		if (!Objects.equals(symbolName, other.symbolName)) {
			return false;
		}
		return true;
	}

	/**
	 * A convenience method to check if the given symbol's symbol path matches this path
	 * 
	 * @param s the symbol to check
	 * @return true if the symbol paths match
	 */
	public boolean matchesPathOf(Symbol s) {
		return equals(new SymbolPath(s));
	}

	/**
	 * Returns a list of names of the symbols in the symbol path, starting with the name just
	 * below the global namespace.
	 *
	 * @return  a list of names of the symbols in the symbol path.
	 */
	public List<String> asList() {
		List<String> list = new ArrayList<>();
		addToList(list);
		return list;
	}

	/**
	 * Returns an array of names of the symbols in the symbol path, starting with the name just
	 * below the global namespace.
	 *
	 * @return  an array of names of the symbols in the symbol path.
	 */
	public String[] asArray() {
		List<String> list = new ArrayList<>();
		addToList(list);
		return list.toArray(new String[list.size()]);
	}

	@Override
	public String toString() {
		return getPath();
	}

	private void addToList(List<String> list) {
		if (parentPath != null) {
			parentPath.addToList(list);
		}
		list.add(symbolName);
	}

	/**
	 * Some existing code might include "Global" at the beginning of their path.  This
	 * method will eliminate any "Global" at the beginning of the path.
	 *
	 * @param path the path to check for "Global"
	 * @return the given path if it is not global; otherwise returns null.
	 */
	private SymbolPath checkGlobal(SymbolPath path) {
		if (path == null) {
			return null;
		}
		if (path.parentPath == null &&
			path.getName().equalsIgnoreCase(GlobalNamespace.GLOBAL_NAMESPACE_NAME)) {
			return null;
		}
		return path;
	}

	@Override
	public int compareTo(SymbolPath o) {
		SymbolPath otherParentPath = o.getParent();
		int result = 0;
		if (parentPath == null) {
			if (otherParentPath != null) {
				return -1;
			}
		}
		else if (otherParentPath == null) {
			return 1;
		}
		else {
			result = parentPath.compareTo(otherParentPath);
		}
		if (result == 0) {
			result = symbolName.compareTo(o.getName());
		}
		return result;
	}
}
