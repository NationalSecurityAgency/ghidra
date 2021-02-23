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
package ghidra.dbg.util;

import java.nio.CharBuffer;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.dbg.target.TargetObject;

/**
 * A collection of utilities for examining and manipulating debug object paths
 * 
 * <p>
 * Paths are merely lists of strings where each part indicates an attribute name or element index.
 * Element indices are enclosed in brackets {@code []}, may be multidimensional, and may be any type
 * encoded as a string. Method invocations contain {@code (...)}. The root object has the empty
 * path.
 */
public enum PathUtils {
	;

	/**
	 * Comparators for keys, i.e., strings in a path
	 */
	public enum TargetObjectKeyComparator implements Comparator<String> {
		/**
		 * Sort keys by attribute name, lexicographically.
		 */
		ATTRIBUTE {
			@Override
			public int compare(String o1, String o2) {
				return o1.compareTo(o2);
			}
		},
		/**
		 * Sort keys by element index.
		 * 
		 * <p>
		 * Element indices may be multidimensional, in which case the dimensions are separated by
		 * commas, and sorting prioritizes the left-most dimensions. Where indices (or dimensions
		 * thereof) appear to be numeric, they are sorted as such. Otherwise, they are sorted
		 * lexicographically. Numeric types can be encoded in hexadecimal. While decimal is typical
		 * you may run into difficulties if those numbers are too large, as the implementation must
		 * assume numeric types are hexadecimal.
		 * 
		 * @implNote The only way I can think to resolve the numeric encoding issue is to examine
		 *           all keys before even selecting a comparator. As is, a comparator can only see
		 *           two keys at a time, and has no context to what it's actually sorting.
		 */
		ELEMENT {
			@Override
			public int compare(String o1, String o2) {
				String[] p1 = o1.split(",");
				String[] p2 = o2.split(",");
				int min = Math.min(p1.length, p2.length);
				for (int i = 0; i < min; i++) {
					int c = ELEMENT_DIM.compare(p1[i], p2[i]);
					if (c != 0) {
						return c;
					}
				}
				return Integer.compare(p1.length, p2.length);
			}
		},
		/**
		 * Sort keys by element index, allowing only one dimension.
		 * 
		 * <p>
		 * Please use {@link #ELEMENT}, unless you really know you need this instead.
		 */
		ELEMENT_DIM {
			@Override
			public int compare(String o1, String o2) {
				Long l1 = null;
				Long l2 = null;
				try {
					l1 = Long.parseLong(o1, 16);
				}
				catch (NumberFormatException e) {
				}
				try {
					l2 = Long.parseLong(o2, 16);
				}
				catch (NumberFormatException e) {
				}
				if (l1 != null && l2 != null) {
					return l1.compareTo(l2);
				}
				if (l1 != null) { // Want numbers first, so l1 < l2
					return -1;
				}
				if (l2 != null) {
					return 1;
				}
				return o1.compareTo(o2);
			}
		},
		/**
		 * Sort keys by element or index as appropriate, placing elements first.
		 */
		CHILD {
			@Override
			public int compare(String o1, String o2) {
				boolean ii1 = o1.startsWith("[") && o1.endsWith("]");
				boolean ii2 = o2.startsWith("[") && o2.endsWith("]");
				if (ii1 && ii2) {
					return ELEMENT.compare(o1.substring(1, o1.length() - 1),
						o2.substring(1, o2.length() - 1));
				}
				if (ii1) {
					return -1;
				}
				if (ii2) {
					return 1;
				}
				return ATTRIBUTE.compare(o1, o2);
			}
		}
	}

	/**
	 * Comparators for paths
	 */
	public enum PathComparator implements Comparator<List<String>> {
		/**
		 * Sort paths by key, prioritizing the left-most, i.e., top-most, keys.
		 * 
		 * <p>
		 * If one path is a prefix to the other, the prefix is "less than" the other.
		 */
		KEYED {
			@Override
			public int compare(List<String> o1, List<String> o2) {
				int min = Math.min(o1.size(), o2.size());
				for (int i = 0; i < min; i++) {
					String e1 = o1.get(i);
					String e2 = o2.get(i);
					int c = e1.compareTo(e2);
					if (c != 0) {
						return c;
					}
				}
				return Integer.compare(o1.size(), o2.size());
			}
		},
		/**
		 * Sort paths by length, longest first, then as in {@link #KEYED}.
		 */
		LONGEST_FIRST {
			@Override
			public int compare(List<String> o1, List<String> o2) {
				int c;
				c = Integer.compare(o2.size(), o1.size());
				if (c != 0) {
					return c;
				}
				return KEYED.compare(o1, o2);
			}
		}
	}

	protected static class PathParser {
		protected final static Pattern LBRACKET = Pattern.compile("\\[");
		protected final static Pattern RBRACKET = Pattern.compile("\\]");
		protected final static Pattern BRACKETED = Pattern.compile("\\[.*?\\]");
		protected final static Pattern LPAREN = Pattern.compile("\\(");
		protected final static Pattern RPAREN = Pattern.compile("\\)");

		protected final CharBuffer buf;
		protected final Pattern sep;

		protected final List<String> result = new ArrayList<>();

		protected PathParser(CharSequence path, String sepRE) {
			buf = CharBuffer.wrap(path);
			sep = Pattern.compile(sepRE);
		}

		protected String match(Pattern pat) {
			Matcher mat = pat.matcher(buf);
			if (!mat.lookingAt()) {
				throw new IllegalArgumentException("Expecting " + pat + ", but had " + buf);
			}
			String tok = mat.group();
			int length = mat.end() - mat.start();
			buf.position(buf.position() + length);
			return tok;
		}

		protected void advanceParenthesized() {
			while (buf.hasRemaining()) {
				if (RPAREN.matcher(buf).lookingAt()) {
					buf.get();
					break;
				}
				else if (LPAREN.matcher(buf).lookingAt()) {
					buf.get();
					advanceParenthesized();
				}
				else {
					buf.get();
				}
			}
		}

		protected String parseName() {
			int p = buf.position();
			while (buf.hasRemaining()) {
				if (sep.matcher(buf).lookingAt()) {
					break;
				}
				else if (LBRACKET.matcher(buf).lookingAt()) {
					break;
				}
				else if (LPAREN.matcher(buf).lookingAt()) {
					buf.get();
					advanceParenthesized();
				}
				else {
					buf.get();
				}
			}
			int e = buf.position();
			buf.position(p);
			String tok = buf.subSequence(0, e - p).toString();
			buf.position(e);
			return tok;
		}

		protected String parseNext() {
			if (sep.matcher(buf).lookingAt()) {
				match(sep);
				return parseName();
			}
			if (LBRACKET.matcher(buf).lookingAt()) {
				return match(BRACKETED);
			}
			throw new IllegalArgumentException(
				"Expected " + sep + " or " + LBRACKET + ", but had " + buf);
		}

		protected List<String> parse() {
			String first = parseName();
			if (first.length() != 0) {
				result.add(first);
			}
			while (buf.hasRemaining()) {
				result.add(parseNext());
			}
			return result;
		}
	}

	public static List<String> parse(String path, String sepRE) {
		return new PathParser(path, sepRE).parse();
	}

	public static List<String> parse(String path) {
		return parse(path, "\\.");
	}

	public static String toString(List<String> path, String sep) {
		StringBuilder sb = new StringBuilder();
		boolean first = true;
		for (String e : path) {
			if (!isIndex(e) && !first) {
				sb.append(sep);
			}
			first = false;
			sb.append(e);
		}
		return sb.toString();
	}

	public static String toString(List<String> path) {
		return toString(path, ".");
	}

	/**
	 * Extend a path with a given key, usually attribute name
	 * 
	 * @param path the parent path
	 * @param key the key to append
	 * @return the resulting extended path
	 */
	public static List<String> extend(List<String> path, String key) {
		List<String> result = new ArrayList<>(path.size() + 1);
		result.addAll(path);
		result.add(key);
		return List.copyOf(result);
	}

	/**
	 * Extend a path with another sub-path
	 * 
	 * @param path the parent path
	 * @param sub the sub-path to the successor
	 * @return the resulting extended path
	 */
	public static List<String> extend(List<String> path, List<String> sub) {
		List<String> result = new ArrayList<>(path.size() + sub.size());
		result.addAll(path);
		result.addAll(sub);
		return List.copyOf(result);
	}

	/**
	 * Encode the given index in decimal, without brackets
	 * 
	 * @param i the numeric index
	 * @return the encoded index
	 */
	public static String makeIndex(long i) {
		return Long.toString(i);
	}

	/**
	 * Encode the given index in decimal, without brackets
	 * 
	 * @param i the numeric index
	 * @return the encoded index
	 */
	public static String makeIndex(int i) {
		return Integer.toString(i);
	}

	/**
	 * Encode the given index as a key
	 * 
	 * <p>
	 * When indexing elements, no brackets are needed. The brackets become necessary when used as a
	 * key, e.g., when specifying an index within a path, or as keys in a map of all children.
	 * 
	 * @param index the index
	 * @return the key, specifying an element.
	 */
	public static String makeKey(String index) {
		return "[" + index + "]";
	}

	/**
	 * Extend a path with a given index
	 * 
	 * <p>
	 * This is equivalent to calling {@code extend(path, makeKey(index))}.
	 * 
	 * @param path the parent path
	 * @param index the index to append
	 * @return the resulting extended path
	 */
	public static List<String> index(List<String> path, String index) {
		return extend(path, makeKey(index));
	}

	/**
	 * Obtain the parent path of this path
	 * 
	 * <p>
	 * This merely removes the last element of the path. If the given path refers to the root,
	 * {@code null} is returned.
	 * 
	 * @param path the child path
	 * @return the parent path or {@code null}
	 */
	public static List<String> parent(List<String> path) {
		if (path.isEmpty()) {
			return null;
		}
		return path.subList(0, path.size() - 1);
	}

	/**
	 * Obtain the key of the object to which the given path refers
	 * 
	 * <p>
	 * This is merely the final right-most key in the path. If the given path refers to the root,
	 * {@code null} is returned.
	 * 
	 * @param path the object's path
	 * @return the key of the object
	 */
	public static String getKey(List<String> path) {
		if (path.isEmpty()) {
			return null;
		}
		return path.get(path.size() - 1);
	}

	/**
	 * Parse an index value from a key
	 * 
	 * <p>
	 * Where key is the form {@code [index]}, this merely returns {@code index}.
	 * 
	 * @param key the key
	 * @return the index
	 * @throws IllegalArgumentException if key is not of the required form
	 */
	public static String parseIndex(String key) {
		if (isIndex(key)) {
			return key.substring(1, key.length() - 1);
		}
		throw new IllegalArgumentException("Index keys must be of the form '[index]'. Got " + key);
	}

	/**
	 * Obtain the index of the object to which the given path refers
	 * 
	 * <p>
	 * This merely parses the index from the final right-most key in the path. It is roughly
	 * equivalent to calling {@code parseIndex(getKey(path))}.
	 * 
	 * @see #getKey(List)
	 * @see #parseIndex(String)
	 * @see #index(List, String)
	 * @param path the object's path
	 * @return the index of the object
	 * @throws IllegalArgumentException if key is not of the required form
	 */
	public static String getIndex(List<String> path) {
		String key = getKey(path);
		return key == null ? null : parseIndex(key);
	}

	/**
	 * Check if the given key is a bracketed index
	 * 
	 * @param key the key to check
	 * @return true if it is an index
	 */
	public static boolean isIndex(String key) {
		return key == null ? false : key.startsWith("[") && key.endsWith("]");
	}

	/**
	 * Check if the final right-most key of the given path is a bracketed index
	 * 
	 * @param path the path to check
	 * @return true if the final key is an index
	 */
	public static boolean isIndex(List<String> path) {
		return isIndex(getKey(path));
	}

	/**
	 * Check if the given key is an attribute name, i.e., not an index
	 * 
	 * @param key the key to check
	 * @return true if it is an attribute name
	 */
	public static boolean isName(String key) {
		return key == null ? false : !isIndex(key);
	}

	/**
	 * Check if the final right-most key of the given path is an attribute name
	 * 
	 * @param path the path to check
	 * @return true if the final key is an attribute name
	 */
	public static boolean isName(List<String> path) {
		return isName(getKey(path));
	}

	/**
	 * Check if the first path refers to an ancestor of the second path
	 * 
	 * <p>
	 * Equivalently, check if the second path refers to a successor of the second path
	 * 
	 * <p>
	 * This effectively checks that ancestor is a prefix of successor. By this definition, every
	 * path is technically an ancestor and successor of itself. If you do not desire that behavior,
	 * check that the two paths are not equal first.
	 * 
	 * @param ancestor the first path
	 * @param successor the second path
	 * @return true if ancestor is, in fact, an ancestor of successor
	 */
	public static boolean isAncestor(List<String> ancestor, List<String> successor) {
		if (ancestor.size() > successor.size()) {
			return false;
		}
		return Objects.equals(ancestor, successor.subList(0, ancestor.size()));
	}

	/**
	 * Check whether a given object-valued attribute is a link.
	 * 
	 * <p>
	 * Consider an object {@code O} with an object-valued attribute {@code a}. {@code a}'s value is
	 * a link, iff its path does <em>not</em> match that generated by extending {@code O}'s path
	 * with {@code a}'s name.
	 * 
	 * @param parentPath the path of the parent object of the given attribute
	 * @param name the name of the given attribute
	 * @param attributePath the canonical path of the attribute's object value
	 * @return true if the value is a link (i.e., it's object has a different path)
	 */
	public static boolean isLink(List<String> parentPath, String name, List<String> attributePath) {
		return !Objects.equals(extend(parentPath, name), attributePath);
	}

	/**
	 * Check whether a given element is a link.
	 * 
	 * <p>
	 * Consider an object {@code O} with an element {@code [1]}. {@code [1]}'s value is a link, iff
	 * its path does <em>not</em> match that generated by extending {@code O}'s path with
	 * {@code [1]}'s key.
	 * 
	 * @param parentPath the path of the parent object of the given element
	 * @param index the index of the given element
	 * @param elementPath the canonical path of the element
	 * @return true if the value is a link (i.e., it's object has a different path)
	 */
	public static boolean isElementLink(List<String> parentPath, String index,
			List<String> elementPath) {
		return !Objects.equals(index(parentPath, index), elementPath);
	}

	/**
	 * Check whether a given attribute should be displayed.
	 * 
	 * @param key the key of the given attribute
	 */
	public static boolean isHidden(String key) {
		return key.startsWith(TargetObject.PREFIX_INVISIBLE);
	}

	/**
	 * Check whether a given path key represents a method invocation.
	 * 
	 * <p>
	 * This really just checks if the key ends in {@code )}.
	 * 
	 * @param key the key
	 * @return true if an invocation, false if not
	 */
	public static boolean isInvocation(String key) {
		return key.endsWith(")");
	}

	/**
	 * Get the name and parameters expression of the method from an invocation.
	 * 
	 * <p>
	 * TODO: We need a more formal model for method invocation in paths. Probably shouldn't return a
	 * map entry once we have that specified, either.
	 * 
	 * @param name the name, which must be in the form {@code method(params)}
	 * @return the method name
	 */
	public static Map.Entry<String, String> parseInvocation(String name) {
		if (!isInvocation(name)) {
			throw new IllegalArgumentException(
				"Invocation keys must be of the form 'method(params)'. Got " + name);
		}
		int i = name.indexOf('(');
		if (i == -1) {
			throw new IllegalArgumentException(
				"Invocation keys must be of the form 'method(params)'. Got " + name);
		}
		return Map.entry(name.substring(0, i), name.substring(i + 1, name.length() - 1));
	}
}
