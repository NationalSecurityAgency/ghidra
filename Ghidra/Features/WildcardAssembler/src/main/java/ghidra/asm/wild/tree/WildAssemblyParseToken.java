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
package ghidra.asm.wild.tree;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.LongStream;
import java.util.stream.Stream;

import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar;
import ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseToken;

public class WildAssemblyParseToken extends AssemblyParseToken {

	public interface Wildcard {
		public static Wildcard parse(String spec) {
			Matcher matRegex = RegexWildcard.PATTERN.matcher(spec);
			if (matRegex.matches()) {
				return RegexWildcard.get(matRegex);
			}
			Matcher matNumeric = NumericWildcard.PATTERN.matcher(spec);
			if (matNumeric.matches()) {
				return NumericWildcard.get(matNumeric);
			}
			Matcher matRanges = RangesWildcard.PATTERN.matcher(spec);
			if (matRanges.matches()) {
				return RangesWildcard.get(matRanges);
			}
			return new FreeWildcard(spec);
		}

		public String name();

		public boolean test(Object object);
	}

	public record FreeWildcard(String name) implements Wildcard {
		@Override
		public boolean test(Object object) {
			return true;
		}
	}

	public record RegexWildcard(String name, Pattern pat) implements Wildcard {
		static final Pattern PATTERN = Pattern.compile("(?<name>[^/]*)/(?<regex>.*)");

		public static RegexWildcard get(Matcher matcher) {
			return new RegexWildcard(matcher.group("name"),
				Pattern.compile(matcher.group("regex")));
		}

		@Override
		public boolean test(Object object) {
			if (!(object instanceof CharSequence cs)) {
				return false;
			}
			return pat.matcher(cs).matches();
		}

		@Override
		public boolean equals(Object o) {
			// Because Pattern does not override equals
			return o instanceof RegexWildcard that &&
				Objects.equals(this.name, that.name) &&
				Objects.equals(this.pat.toString(), that.pat.toString());
		}
	}

	public record NumericWildcard(String name) implements Wildcard {
		static final Pattern PATTERN = Pattern.compile("(?<name>.*)\\[\\.\\.\\]");

		public static NumericWildcard get(Matcher matcher) {
			return new NumericWildcard(matcher.group("name"));
		}

		@Override
		public boolean test(Object object) {
			return object instanceof Number;
		}
	}

	// TODO: It's possible we'll eventually want BigInteger's here.
	public record WildRange(long min, long max) implements Comparable<WildRange> {
		public WildRange(long min, long max) {
			if (min > max) {
				throw new AssertionError("max > max");
			}
			this.min = min;
			this.max = max;
		}

		public static WildRange parse(String str) {
			String[] parts = str.split("\\.\\.");
			if (parts.length == 1) {
				long val = Long.decode(parts[0]);
				return new WildRange(val, val);
			}
			if (parts.length == 2) {
				long min = Long.decode(parts[0]);
				long max = Long.decode(parts[1]);
				return new WildRange(min, max);
			}
			throw new IllegalArgumentException("Invalid range specification in wildcard: " + str);
		}

		public LongStream stream() {
			return LongStream.rangeClosed(min, max);
		}

		@Override
		public int compareTo(WildRange that) {
			return Long.compare(this.min, that.min);
		}
	}

	public record RangesWildcard(String name, List<WildRange> ranges) implements Wildcard {
		public static final Pattern PATTERN =
			Pattern.compile("(?<name>[^\\[]*)\\[(?<ranges>[^\\]]*)\\]");

		public static RangesWildcard get(Matcher matcher) {
			return new RangesWildcard(matcher.group("name"), parseRanges(matcher.group("ranges")));
		}

		public static List<WildRange> parseRanges(String str) {
			return Stream.of(str.split(",")).map(WildRange::parse).sorted().toList();
		}

		static long getLong(Object a) {
			if (a instanceof Number n) {
				return n.longValue();
			}
			if (a instanceof WildRange range) {
				return range.min;
			}
			throw new AssertionError();
		}

		static int searchComp(Object a, Object b) {
			return Long.compare(getLong(a), getLong(b));
		}

		public LongStream stream() {
			return ranges.stream().flatMapToLong(i -> i.stream());
		}

		@Override
		public boolean test(Object object) {
			if (!(object instanceof Number n)) {
				return false;
			}
			long lv = n.longValue();
			int i = Collections.binarySearch(ranges, lv, RangesWildcard::searchComp);
			if (i >= 0) {
				return true; // We're exactly at one of the mins
			}
			// -i-1 is first index greater (ceiling). I want last index lesser (floor).
			i = -i - 2;
			if (i < 0) {
				return false;
			}
			return lv <= ranges.get(i).max; // I already know lv >= min
		}
	}

	public final Wildcard wild;

	public WildAssemblyParseToken(AssemblyGrammar grammar, AssemblyTerminal term, String str,
			String spec) {
		super(grammar, term, str);
		this.wild = Wildcard.parse(spec);
	}

	public String wildcardName() {
		return wild.name();
	}
}
