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
package ghidra.taint.model;

import java.util.*;
import java.util.stream.Collectors;

/**
 * A taint mark
 * 
 * <p>
 * This is essentially a symbol or variable, but we also include an immutable set of tags. A mark is
 * the bottom-most component in a {@link TaintVec}.
 */
public class TaintMark {
	private static final String SEP = ":";
	private static final String TAG_SEP = ",";

	/**
	 * Parse a mark from the given string
	 * 
	 * <p>
	 * A mark has the form "{@code name:tag1,tag2,...,tagN}". The tags are optional, so it may also
	 * take the form "{@code name}".
	 * 
	 * @param string the string to parse
	 * @return the resulting mark
	 */
	public static TaintMark parse(String string) {
		String[] parts = string.split(SEP);
		if (parts.length == 1) {
			return new TaintMark(parts[0], Set.of());
		}
		return new TaintMark(parts[0], Set.of(parts[1].split(TAG_SEP)));
	}

	private final String name;
	private final Set<String> tags;
	private final int hashCode;

	/**
	 * Construct a new taint mark
	 * 
	 * <p>
	 * TODO: Validation that the name and tags do not contain any separators, so that
	 * {@link #parse(String)} and {@link #toString()} are proper inverses.
	 * 
	 * @param name the name
	 * @param tags the tags
	 */
	public TaintMark(String name, Set<String> tags) {
		this.name = name;
		this.tags = Set.copyOf(tags); // TODO: Optimize
		this.hashCode = Objects.hash(name, tags);
	}

	/**
	 * Render the mark as a string
	 * 
	 * @see #parse(String)
	 */
	@Override
	public String toString() {
		if (tags.isEmpty()) {
			return getName();
		}
		return getName() + SEP + tags.stream().collect(Collectors.joining(TAG_SEP));
	}

	/**
	 * Check if two marks are equal
	 * 
	 * <p>
	 * Note that we distinguish between a mark without tags and another mark with the same name but
	 * having tags. Because we use tags to indicate, e.g., indirection, we want to allow a variable
	 * to be marked as tainted both directly and indirectly. Furthermore, if indirect taints are
	 * filtered, we would want to ensure such a variable is not removed, since it's also tainted
	 * directly.
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof TaintMark)) {
			return false;
		}
		TaintMark that = (TaintMark) obj;
		if (!Objects.equals(this.name, that.name)) {
			return false;
		}
		if (!Objects.equals(this.tags, that.tags)) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		return hashCode;
	}

	/**
	 * Get the name of the mark
	 * 
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Get the mark's tags
	 * 
	 * @return the tags
	 */
	public Set<String> getTags() {
		return tags;
	}

	/**
	 * Create a new mark with the given tag added
	 * 
	 * <p>
	 * Tags are a set, so this may return the same mark
	 * 
	 * @param tag
	 * @return
	 */
	public TaintMark tagged(String tag) {
		if (this.tags.contains(tag)) {
			return this;
		}
		HashSet<String> tags = new HashSet<>(this.tags);
		tags.add(tag);
		return new TaintMark(name, tags);
	}
}
