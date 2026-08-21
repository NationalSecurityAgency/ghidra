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
package ghidra.trace.model.target.path;

import java.nio.CharBuffer;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * An immutable path of keys leading from one object (usually the root) object to another
 * 
 * <p>
 * Often, the source is the root. These are often taken as a parameter when searching for values. In
 * essence, they simply wrap a list of string keys, but it provides convenience methods, sensible
 * comparison, and better typing.
 */
public final class KeyPath implements Comparable<KeyPath>, Iterable<String> {
	public static final KeyPath ROOT = new KeyPath();

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
	 * Check if the given key is a bracketed index
	 * 
	 * @param key the key to check
	 * @return true if it is an index
	 */
	public static boolean isIndex(String key) {
		return key == null ? false : key.startsWith("[") && key.endsWith("]");
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
	 * If an index, parse it, otherwise just return the key
	 * 
	 * @param key the key
	 * @return the index or key
	 */
	public static String parseIfIndex(String key) {
		if (isIndex(key)) {
			return key.substring(1, key.length() - 1);
		}
		return key;
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
	 * Comparators for keys, i.e., strings in a path
	 */
	public enum KeyComparator implements Comparator<String> {
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
	public enum PathComparator implements Comparator<KeyPath> {
		/**
		 * Sort paths by key, prioritizing the left-most, i.e., top-most, keys.
		 * 
		 * <p>
		 * If one path is a prefix to the other, the prefix is "less than" the other.
		 */
		KEYED {
			@Override
			public int compare(KeyPath o1, KeyPath o2) {
				int min = Math.min(o1.size(), o2.size());
				for (int i = 0; i < min; i++) {
					String e1 = o1.key(i);
					String e2 = o2.key(i);
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
			public int compare(KeyPath o1, KeyPath o2) {
				int c;
				c = Integer.compare(o2.size(), o1.size());
				if (c != 0) {
					return c;
				}
				return KEYED.compare(o1, o2);
			}
		}
	}

	public static class PathParser {
		protected final static Pattern LBRACKET = Pattern.compile("\\[");
		protected final static Pattern RBRACKET = Pattern.compile("\\]");
		protected final static Pattern BRACKETED = Pattern.compile("\\[.*?\\]");
		protected final static Pattern LPAREN = Pattern.compile("\\(");
		protected final static Pattern RPAREN = Pattern.compile("\\)");

		protected final CharBuffer buf;
		protected final Pattern sep;

		protected final List<String> result = new ArrayList<>();

		public PathParser(CharSequence path, String sepRE) {
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

		public KeyPath parse() {
			String first = parseName();
			if (first.length() != 0) {
				result.add(first);
			}
			while (buf.hasRemaining()) {
				result.add(parseNext());
			}
			return KeyPath.of(result);
		}
	}

	/**
	 * Create a path from the given list of keys
	 * 
	 * @param keyList the list of keys from source to destination
	 * @return the path
	 */
	public static KeyPath of(List<String> keyList) {
		return new KeyPath(keyList.toArray(String[]::new));
	}

	public static KeyPath of(Stream<String> keyStream) {
		return new KeyPath(keyStream.toArray(String[]::new));
	}

	/**
	 * Create a path from the given keys
	 * 
	 * @param keys the keys from source to destination
	 * @return the path
	 */
	public static KeyPath of(String... keys) {
		return new KeyPath(Arrays.copyOf(keys, keys.length));
	}

	/**
	 * Parse a path from the given string
	 * 
	 * @param path the dot-separated keys from source to destination
	 * @return the path
	 */
	public static KeyPath parse(String path) {
		return new PathParser(path, "\\.").parse();
	}

	final String[] keys;
	private final int hash;

	KeyPath(String... keys) {
		this.keys = keys;
		this.hash = Objects.hash((Object[]) keys);
	}

	@Override
	public int hashCode() {
		return hash;
	}

	@Override
	public int compareTo(KeyPath that) {
		if (this == that) {
			return 0;
		}
		return PathComparator.KEYED.compare(this, that);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof KeyPath that)) {
			return false;
		}
		return Arrays.equals(this.keys, that.keys);
	}

	public int size() {
		return keys.length;
	}

	@Override
	public Iterator<String> iterator() {
		return new Iterator<>() {
			int i = 0;

			@Override
			public boolean hasNext() {
				return i < keys.length;
			}

			@Override
			public String next() {
				return keys[i++];
			}
		};
	}

	public String key(int i) {
		return keys[i];
	}

	/**
	 * Get the (immutable) list of keys from source to destination
	 * 
	 * @return the key list
	 */
	public List<String> toList() {
		return List.of(keys);
	}

	public boolean containsWildcard() {
		for (String k : keys) {
			if (PathPattern.isWildcard(k)) {
				return true;
			}
		}
		return false;
	}

	public int countWildcards() {
		int count = 0;
		for (String k : keys) {
			if (PathPattern.isWildcard(k)) {
				count++;
			}
		}
		return count;
	}

	/**
	 * Assuming the source is the root, check if this path refers to that root
	 * 
	 * @return true if the path is empty, false otherwise
	 */
	public boolean isRoot() {
		return keys.length == 0;
	}

	/**
	 * Create a new path by appending the given key
	 * 
	 * <p>
	 * For example, if this path is "{@code Processes[2]}" and {@code name} takes the value
	 * "{@code Threads}", the result will be "{@code Processes[2].Threads}".
	 * 
	 * @param name the new final key
	 * @return the resulting path
	 */
	public KeyPath key(String name) {
		String[] keys = Arrays.copyOf(this.keys, this.keys.length + 1);
		keys[this.keys.length] = name;
		return new KeyPath(keys);
	}

	/**
	 * Get the final key of this path
	 * 
	 * @return the final key
	 */
	public String key() {
		if (keys.length == 0) {
			return null;
		}
		return keys[keys.length - 1];
	}

	/**
	 * Create a new path by appending the given element index
	 * 
	 * <p>
	 * For example, if this path is "{@code Processes}" and {@code index} takes the value 2, the
	 * result will be "{@code Processes[2]}".
	 * 
	 * @param index the new final index
	 * @return the resulting path
	 */
	public KeyPath index(long index) {
		return index(makeIndex(index));
	}

	/**
	 * Create a new path by appending the given element index
	 * 
	 * <p>
	 * This does the same as {@link #key(String)} but uses brackets instead. For example, if this
	 * path is "{@code Processes[2].Threads[0].Registers}" and {@code index} takes the value
	 * "{@code RAX}", the result will be "{@code Processes[2].Threads[0].Registers[RAX]"}.
	 * 
	 * @param index the new final index
	 * @return the resulting path
	 */
	public KeyPath index(String index) {
		return extend(makeKey(index));
	}

	/**
	 * Get the final index of this path
	 * 
	 * @return the final index
	 * @throws IllegalArgumentException if the final key is not an index, i.e., in brackets
	 */
	public String index() {
		String key = key();
		return key == null ? null : parseIndex(key);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Gives the dot-joined path
	 */
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		boolean first = true;
		for (String k : keys) {
			if (!isIndex(k) && !first) {
				sb.append(".");
			}
			first = false;
			sb.append(k);
		}
		return sb.toString();
	}

	/**
	 * Create a new path by removing the final key
	 * 
	 * @return the resulting path, or null if this path is empty
	 */
	public KeyPath parent() {
		return parent(1);
	}

	/**
	 * Create a new path by removing the final {@code n} keys
	 * 
	 * @param n the number of keys to remove
	 * @return the resulting path, or null if fewer than 0 keys would remain
	 */
	public KeyPath parent(int n) {
		if (n < 0) {
			throw new IllegalArgumentException("n<0");
		}
		if (keys.length < n) {
			return null;
		}
		return new KeyPath(Arrays.copyOf(keys, keys.length - n));
	}

	/**
	 * Create a new path by appending the given list of keys
	 * 
	 * <p>
	 * For example, if this path is "{@code Processes[2]}" and {@code sub} takes the value
	 * "{@code Threads[0]}", the result will be "{@code Processes[2].Threads[0]}".
	 * 
	 * @param sub the path to append
	 * @return the resulting path
	 */
	public KeyPath extend(KeyPath sub) {
		return extend(sub.keys);
	}

	/**
	 * Create a new path by appending the given keys
	 * 
	 * @see #extend(KeyPath)
	 * @param subKeys the keys to append
	 * @return the resulting path
	 */
	public KeyPath extend(String... subKeys) {
		String[] keys = Arrays.copyOf(this.keys, this.keys.length + subKeys.length);
		System.arraycopy(subKeys, 0, keys, this.keys.length, subKeys.length);
		return new KeyPath(keys);
	}

	/**
	 * Stream, starting with the longer paths, paths that match the given predicates
	 * 
	 * @param filter the predicates to filter the ancestor paths
	 * @return the stream of matching paths, longest to shortest
	 */
	public Stream<KeyPath> streamMatchingAncestry(PathFilter filter) {
		if (!filter.ancestorMatches(this, false)) {
			return Stream.of();
		}
		Stream<KeyPath> ancestry =
			isRoot() ? Stream.of() : parent().streamMatchingAncestry(filter);
		if (filter.matches(this)) {
			return Stream.concat(Stream.of(this), ancestry);
		}
		return ancestry;
	}

	/**
	 * Check if this path is an ancestor of the given path
	 * 
	 * <p>
	 * Equivalently, check if the given path is a successor of this path. A path is considered an
	 * ancestor of itself. To check for a strict ancestor, use
	 * {@code this.isAncestor(that) && !this.equals(that)}.
	 * 
	 * @param successor the supposed successor to this path
	 * @return true if the given path is in fact a successor
	 */
	public boolean isAncestor(KeyPath successor) {
		if (this.keys.length > successor.keys.length) {
			return false;
		}
		int len = this.keys.length;
		return Arrays.equals(this.keys, 0, len, successor.keys, 0, len);
	}

	/**
	 * Assuming this is an ancestor of the given successor, compute the relative path from here to
	 * there
	 * 
	 * @param successor the successor
	 * @return the relative path
	 */
	public KeyPath relativize(KeyPath successor) {
		if (!isAncestor(successor)) {
			throw new IllegalArgumentException("this is not an ancestor to successor");
		}
		return new KeyPath(
			Arrays.copyOfRange(successor.keys, this.keys.length, successor.keys.length));
	}
}
