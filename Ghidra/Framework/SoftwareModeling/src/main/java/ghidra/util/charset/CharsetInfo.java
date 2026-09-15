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
package ghidra.util.charset;

import java.lang.Character.UnicodeScript;
import java.nio.charset.Charset;
import java.util.*;

import generic.json.Json;

/**
 * Additional information about {@link Charset java.nio.charset.Charset's} that
 * Ghidra needs to be able to create Ghidra string datatype instances.
 * <p>
 * See charset_info.json to specify info about a custom charset.
 */
public class CharsetInfo {
	static final Set<String> FIELDS_TO_EXCLUDE_FROM_JSON = Set.of("standardCharset");
	static final int UNICODESCRIPT_COUNT = UnicodeScript.UNKNOWN.ordinal() + 1;
	static final EnumSet<UnicodeScript> ALL_SCRIPTS = EnumSet.allOf(UnicodeScript.class);
	static final EnumSet<UnicodeScript> NO_SCRIPTS = EnumSet.noneOf(UnicodeScript.class);

	private final String name;
	private final String comment;
	private final int minBytesPerChar;
	private final int maxBytesPerChar;
	private final int alignment;
	private final int codePointCount;
	private final EnumSet<UnicodeScript> scripts;
	private final Set<String> contains;
	private final boolean canProduceError;
	private final boolean standardCharset; // not serialized, see FIELDS_TO_EXCLUDE_FROM_JSON

	public CharsetInfo(Charset cs) {
		this(cs.name(), null, 1, -1, 1, -1, false, true, NO_SCRIPTS, Set.of());
	}

	public CharsetInfo(String name, String comment, int minBytesPerChar, int maxBytesPerChar,
			int alignment, int codePointCount, boolean standardCharset, boolean canProduceError,
			EnumSet<UnicodeScript> scripts, Set<String> contains) {
		this.name = name;
		this.comment = comment;
		this.minBytesPerChar = minBytesPerChar;
		this.maxBytesPerChar = maxBytesPerChar;
		this.alignment = alignment;
		this.codePointCount = codePointCount;
		this.standardCharset = standardCharset;
		this.canProduceError = canProduceError;
		this.scripts = scripts;
		this.contains = contains;
	}

	/**
	 * {@return a copy of this instance, with a new comment value}
	 * @param newComment string
	 */
	public CharsetInfo withComment(String newComment) {
		return new CharsetInfo(name, newComment, minBytesPerChar, maxBytesPerChar, alignment,
			codePointCount, standardCharset, canProduceError, scripts, contains);
	}

	/**
	 * @return {@link Charset}
	 */
	public Charset getCharset() {
		return Charset.forName(name, null);
	}

	/**
	 * {@return name of the charset}
	 */
	public String getName() {
		return name;
	}

	/**
	 * {@return boolean flag, true if this is a standard charset that is guaranteed to be present
	 * in the jvm, otherwise false}
	 */
	public boolean isStandardCharset() {
		return standardCharset;
	}

	/**
	 * {@return true if this charset can produce Unicode REPLACEMENT codepoints for
	 * bad byte sequences, otherwise false if there are no byte sequences that result in REPLACEMENT
	 * codepoints.  This is typically single-byte charsets that map all byte values to a codepoint}
	 */
	public boolean isCanProduceError() {
		return canProduceError;
	}

	/**
	 * {@return true if this charset can produce Unicode codepoints that are in all scripts}
	 */
	public boolean supportsAllScripts() {
		return scripts.size() >= UNICODESCRIPT_COUNT - 1 /* ignore unknown */;
	}

	/**
	 * {@return the UnicodeScripts that this charset can produce}
	 */
	public Set<UnicodeScript> getScripts() {
		return scripts;
	}

	/**
	 * {@return true if this charset only consumes a fixed number of bytes per output codepoint}
	 */
	public boolean hasFixedLengthChars() {
		return minBytesPerChar > 0 && minBytesPerChar == maxBytesPerChar;
	}

	/**
	 * {@return the alignment value for this charset, typically 1 for most charsets, but for
	 * well-known fixed-width charsets, it will return those charsets fixed-width}
	 */
	public int getAlignment() {
		return alignment;
	}

	/**
	 * {@return the smallest number of bytes needed to produce a codepoint}
	 */
	public int getMinBytesPerChar() {
		return minBytesPerChar;
	}

	/**
	 * {@return the largest number of bytes needed to produce a codepoint}
	 */
	public int getMaxBytesPerChar() {
		return maxBytesPerChar;
	}

	/**
	 * {@return the number of codepoints that this charset can produce}
	 */
	public int getCodePointCount() {
		return codePointCount;
	}

	/**
	 * Returns the names of other charsets that this charset {@link Charset#contains(Charset)}.
	 * 
	 * @return names of other charsets
	 */
	public Set<String> getContains() {
		return contains;
	}

	/**
	 * {@return a string comment describing this charset, or null}
	 */
	public String getComment() {
		return comment;
	}

	@Override
	public int hashCode() {
		return Objects.hash(name);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof CharsetInfo other)) {
			return false;
		}
		return Objects.equals(name, other.name);
	}

	@Override
	public String toString() {
		return Json.toString(this);
	}
}
