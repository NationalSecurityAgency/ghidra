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
package ghidra.app.util.bin.format.dwarf4.next;

import java.util.function.Consumer;

import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Represents a hierarchical path of containers that hold names of objects.
 * <p>
 * Each container of names (lets call them a namespace for short) can have a type that
 * distinguishes it from other containers: classes, functions, c++ namespaces, etc.
 * <p>
 * A NamespacePath does not correlate directly to a Ghidra {@link Namespace}, as a Ghidra Namespace
 * is tied to a Program and has rules about what can be placed inside of it.
 * <p>
 * NamespacePath instances can be created without referring to a Ghidra Program and without
 * concern as to what will be valid or have collisions.
 * <p>
 * Use a NamespacePath to represent and hold forward-engineering namespace nesting information (ie.
 * namespace info recovered from debug info), and when a Ghidra Namespace is needed,
 * convert to or lookup the live/'real' Ghidra Namespace.
 *
 */
public class NamespacePath implements Comparable<NamespacePath> {

	public static final NamespacePath ROOT = new NamespacePath(null, null, SymbolType.NAMESPACE);

	/**
	 * Creates a new {@link NamespacePath} instance.
	 *
	 * @param parent optional - parent {@link NamespacePath} instance, default to {@link #ROOT} if null.
	 * @param name string name of the new namespace.
	 * @param type {@link SymbolType} of the named space - ie. a "namespace", a class,
	 * @return new {@link NamespacePath}
	 */
	public static NamespacePath create(NamespacePath parent, String name, SymbolType type) {
		return new NamespacePath(parent == null ? ROOT : parent, preMangleName(name), type);
	}

	private static final String FWDSLASH_MANGLE = "-fwdslash-";
	private static final String COLON_MANGLE = "-";

	private static String preMangleName(String name) {
		return name == null ? null
				: name.replaceAll(":", COLON_MANGLE).replaceAll(" ", "").replaceAll("/",
					FWDSLASH_MANGLE);
	}

	private final NamespacePath parent;
	private final String name;
	private final SymbolType type;

	private NamespacePath(NamespacePath parent, String name, SymbolType type) {
		this.parent = parent;
		this.name = name;
		this.type = type;
	}

	/**
	 * Returns true if this namespace path points to the root of the namespace space.
	 *
	 * @return boolean true if ROOT
	 */
	public boolean isRoot() {
		return parent == null;
	}

	/**
	 * Returns the name of this namespace element, ie. the last thing on the path.
	 *
	 * @return string name.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns a reference to the parent NamespacePath.
	 *
	 * @return parent NamespacePath
	 */
	public NamespacePath getParent() {
		return parent;
	}

	/**
	 * Returns the {@link SymbolType} of this namespace element (ie. the symbol type of the last
	 * thing on the path).
	 *
	 * @return {@link SymbolType}
	 */
	public SymbolType getType() {
		return type;
	}

	private static SymbolType flattenSymbolTypeForDNI(SymbolType type) {
		if (type == SymbolType.CLASS) {
			return SymbolType.CLASS;
		}
		return SymbolType.NAMESPACE;
	}

	/**
	 * Converts this NamespacePath into a Ghidra {@link Namespace} in the specified {@link Program},
	 * creating missing elements on the path as necessary.
	 *
	 * @param program Ghidra {@link Program} where the namespace should be retrieved from or created in.
	 * @return {@link Namespace} or fallback to the progam's Global root namespace if problem.
	 */
	public Namespace getNamespace(Program program) {
		if (isRoot()) {
			return program.getGlobalNamespace();
		}
		try {
			Namespace result = parent.getNamespace(program);
			Namespace existingNamespace =
				NamespaceUtils.getFirstNonFunctionNamespace(result, name, program);
			SymbolType targetSymbolType = flattenSymbolTypeForDNI(type);
			SymbolType existingSymbolType =
				(existingNamespace != null) ? existingNamespace.getSymbol().getSymbolType() : null;

			if (existingNamespace == null) {
				result = (targetSymbolType == SymbolType.NAMESPACE)
						? program.getSymbolTable().createNameSpace(result, name,
							SourceType.IMPORTED)
						: program.getSymbolTable().createClass(result, name, SourceType.IMPORTED);

			}
			else if (existingSymbolType == targetSymbolType) {
				result = existingNamespace;
			}
			else {
				// conflict type
				if (existingSymbolType == SymbolType.NAMESPACE &&
					targetSymbolType == SymbolType.CLASS) {
					result = NamespaceUtils.convertNamespaceToClass(existingNamespace);
				}
				else if (existingSymbolType == SymbolType.CLASS &&
					targetSymbolType == SymbolType.NAMESPACE) {
					// silently allow this
					result = existingNamespace;
				}
				else {
					Msg.error(this, "Error getting Ghidra namespace for " + asNamespaceString());
					result = program.getGlobalNamespace();
				}
			}
			return result;
		}
		catch (DuplicateNameException | InvalidInputException e) {
			Msg.error(this, "Failed to create Ghidra namespace for " + asNamespaceString());
			return program.getGlobalNamespace();
		}
	}

	/**
	 * Converts this namespace path into a {@link CategoryPath} style string.
	 * @return string path "/namespace1/namespace2"
	 */
	public String asCategoryPathString() {
		StringBuilder sb = new StringBuilder();
		doInOrderTraversal(
			nsp -> sb.append(sb.length() != 1 ? "/" : "").append(nsp.isRoot() ? "" : nsp.name));
		return sb.toString();
	}

	/**
	 * Converts this namespace path into a {@link Namespace} style string.
	 * @return string path "ROOT::namespace1::namespace2"
	 */
	public String asNamespaceString() {
		StringBuilder sb = new StringBuilder();
		doInOrderTraversal(
			nsp -> sb.append(sb.length() != 0 ? Namespace.DELIMITER : "").append(
				nsp.isRoot() ? "ROOT" : nsp.name));
		return sb.toString();
	}

	/**
	 * Converts this namespace path into a {@link Namespace} style string without the ROOT namespace
	 * included.
	 * @return string path "namespace1::namespace2"
	 */
	public String asFormattedString() {
		StringBuilder sb = new StringBuilder();

		doInOrderTraversal(nsp -> {
			if (!nsp.isRoot()) {
				sb.append(sb.length() != 0 ? Namespace.DELIMITER : "").append(nsp.name);
			}

		});

		return sb.toString();
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		doInOrderTraversal(
			nsp -> sb.append(sb.length() != 0 ? Namespace.DELIMITER : "").append(
				nsp.isRoot() ? "ROOT" : nsp.name).append(
					"(" + (nsp.getType() != null ? nsp.getType() : "unknown type") + ")"));
		return sb.toString();

	}

	private void doInOrderTraversal(Consumer<NamespacePath> consumer) {
		if (parent != null) {
			parent.doInOrderTraversal(consumer);
		}
		consumer.accept(this);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		result = prime * result + ((parent == null) ? 0 : parent.hashCode());
		result = prime * result + ((type == null) ? 0 : type.hashCode());
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
		if (!(obj instanceof NamespacePath)) {
			return false;
		}
		NamespacePath other = (NamespacePath) obj;
		if (name == null) {
			if (other.name != null) {
				return false;
			}
		}
		else if (!name.equals(other.name)) {
			return false;
		}
		if (parent == null) {
			if (other.parent != null) {
				return false;
			}
		}
		else if (!parent.equals(other.parent)) {
			return false;
		}
		if (type == null) {
			if (other.type != null) {
				return false;
			}
		}
		else if (!type.equals(other.type)) {
			return false;
		}
		return true;
	}

	@Override
	public int compareTo(NamespacePath otherPath) {
		if (parent == null) {
			return (otherPath.parent == null) ? 0 : 1;
		}
		return (parent == otherPath.parent) ? name.compareTo(otherPath.name)
				: parent.compareTo(otherPath.parent);
	}
}
