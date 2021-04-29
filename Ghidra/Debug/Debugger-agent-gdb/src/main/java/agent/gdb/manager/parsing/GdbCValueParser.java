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
package agent.gdb.manager.parsing;

import java.math.BigInteger;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.collections4.list.AbstractListDecorator;
import org.apache.commons.collections4.map.AbstractMapDecorator;

import agent.gdb.manager.parsing.GdbParsingUtils.AbstractGdbParser;
import agent.gdb.manager.parsing.GdbParsingUtils.GdbParseError;
import utility.function.ExceptionalFunction;

public class GdbCValueParser extends AbstractGdbParser {
	public interface GdbCValue {
		public GdbCValue EMPTY = new GdbCValue() {
			@Override
			public boolean isEmpty() {
				return true;
			}
		};

		boolean isEmpty();

		default int expectInt() {
			return ((GdbIntValue) this).val.intValueExact();
		}

		default long expectLong() {
			return ((GdbIntValue) this).val.longValueExact();
		}

		default BigInteger expectedBigInt() {
			return ((GdbIntValue) this).val;
		}
	}

	public interface GdbCompositeValue extends GdbCValue, Map<String, GdbCValue> {
		public GdbCompositeValue EMPTY = new DefaultGdbCompositeValue(Map.of());

		public static class Builder {
			private final Map<String, GdbCValue> map = new LinkedHashMap<>();

			private Builder() {
			}

			public Builder put(String name, GdbCValue value) {
				if (map.containsKey(name)) {
					throw new IllegalArgumentException("field " + name + " already present");
				}
				map.put(name, value);
				return this;
			}

			public GdbCompositeValue build() {
				return new DefaultGdbCompositeValue(Map.copyOf(map));
			}
		}

		public static Builder builder() {
			return new Builder();
		}
	}

	public static class DefaultGdbCompositeValue extends AbstractMapDecorator<String, GdbCValue>
			implements GdbCompositeValue {
		private DefaultGdbCompositeValue(Map<String, GdbCValue> map) {
			super(map);
		}
	}

	public interface GdbArrayValue extends GdbCValue, List<GdbCValue> {
		public GdbArrayValue EMPTY = new DefaultGdbArrayValue(List.of());

		public static class Builder {
			private final List<GdbCValue> list = new ArrayList<>();

			private Builder() {
			}

			public Builder add(GdbCValue value) {
				list.add(value);
				return this;
			}

			public GdbArrayValue build() {
				return new DefaultGdbArrayValue(List.copyOf(list));
			}
		}

		public static Builder builder() {
			return new Builder();
		}

		public default List<Integer> expectInts() {
			return stream().map(v -> v.expectInt()).collect(Collectors.toList());
		}

		public default List<Long> expectLongs() {
			return stream().map(v -> v.expectLong()).collect(Collectors.toList());
		}

		public default List<BigInteger> expectBigInts() {
			return stream().map(v -> v.expectedBigInt()).collect(Collectors.toList());
		}
	}

	public static class DefaultGdbArrayValue extends AbstractListDecorator<GdbCValue>
			implements GdbArrayValue {
		private DefaultGdbArrayValue(List<GdbCValue> list) {
			super(list);
		}
	}

	public static class GdbIntValue implements GdbCValue {
		public static GdbIntValue valueOf(BigInteger val) {
			// There shouldn't be a lot of these around to need to intern them
			return new GdbIntValue(val);
		}

		public static GdbIntValue valueOf(long val) {
			return valueOf(BigInteger.valueOf(val));
		}

		@Override
		public String toString() {
			return "0x" + val.toString(16);
		}

		@Override
		public int hashCode() {
			return val.hashCode();
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof GdbIntValue)) {
				return false;
			}
			GdbIntValue that = (GdbIntValue) obj;
			return Objects.equals(this.val, that.val);
		}

		private final BigInteger val;

		private GdbIntValue(BigInteger val) {
			this.val = val;
		}

		public BigInteger getValue() {
			return val;
		}

		@Override
		public boolean isEmpty() {
			return false;
		}
	}

	protected static final Pattern COMMA = Pattern.compile(",");
	protected static final Pattern LBRACE = Pattern.compile("\\{");
	protected static final Pattern RBRACE = Pattern.compile("\\}");
	protected static final Pattern ID = Pattern.compile("(?<id>[A-Za-z_][0-9A-Za-z_]*)");
	protected static final Pattern EQUALS = Pattern.compile("=");
	protected static final Pattern REPEATS = Pattern.compile("<repeats\\s+");
	protected static final Pattern TIMES = Pattern.compile("\\s+times>");
	protected static final Pattern INT_OCT = Pattern.compile("0(?<oct>[0-7]+)");
	protected static final Pattern INT_DEC = Pattern.compile("(?<dec>\\d+)");
	protected static final Pattern INT_HEX = Pattern.compile("0x(?<hex>[0-9A-Fa-f]+)");

	public static <T extends GdbCValue> T parseValue(CharSequence text,
			ExceptionalFunction<GdbCValueParser, T, GdbParseError> func) throws GdbParseError {
		GdbCValueParser parser = new GdbCValueParser(text);
		T val = func.apply(parser);
		parser.checkEmpty(true);
		return val;
	}

	public static GdbCValue parseValue(CharSequence text) throws GdbParseError {
		return parseValue(text, GdbCValueParser::parseValue);
	}

	public static GdbArrayValue parseArray(CharSequence text) throws GdbParseError {
		return parseValue(text, GdbCValueParser::parseArray);
	}

	public GdbCValueParser(CharSequence text) {
		super(text);
	}

	public GdbCValue parseValue() throws GdbParseError {
		switch (peek(true)) {
			case '{':
				return parseCompositeOrArray();
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				return parseInteger();
			default:
				throw new GdbParseError("{ or digit", buf);
		}
	}

	public GdbIntValue parseInteger() throws GdbParseError {
		// Try hex first, so 0 in 0x doesn't get chewed by INT_DEC
		try {
			String match = match(INT_HEX, true, "hex");
			return GdbIntValue.valueOf(new BigInteger(match, 16));
		}
		catch (GdbParseError e) {
			// Just try next match
		}
		try {
			String match = match(INT_OCT, true, "oct");
			return GdbIntValue.valueOf(new BigInteger(match, 8));
		}
		catch (GdbParseError e) {
			// Just try next match
		}
		try {
			String match = match(INT_DEC, true, "dec");
			return GdbIntValue.valueOf(new BigInteger(match, 10));
		}
		catch (GdbParseError e) {
			// Fall through to error report
		}

		throw new GdbParseError("0x[hex], 0[oct], or [dec]", buf);
	}

	public GdbCValue parseCompositeOrArray() throws GdbParseError {
		match(LBRACE, true);
		char c = peek(true);
		if (c == '}') {
			match(RBRACE, true);
			return GdbCValue.EMPTY;
		}
		if (Character.isAlphabetic(c) || c == '_') {
			return parseCompositeAfterOpen();
		}
		return parseArrayAfterOpen();
	}

	public GdbCompositeValue parseCompositeAfterOpen() throws GdbParseError {
		GdbCompositeValue.Builder result = GdbCompositeValue.builder();
		while (true) {
			String id = match(ID, true);
			match(EQUALS, true);
			GdbCValue val = parseValue();
			result.put(id, val);

			char c = peek(true);
			if (c == '}') {
				match(RBRACE, false);
				return result.build();
			}
			else if (c == ',') {
				match(COMMA, false);
			}
			else {
				throw new GdbParseError("} or ,", buf);
			}
		}
	}

	public GdbArrayValue parseArray() throws GdbParseError {
		match(LBRACE, true);
		char c = peek(true);
		if (c == '}') {
			match(RBRACE, false);
			return GdbArrayValue.EMPTY;
		}
		return parseArrayAfterOpen();
	}

	public GdbArrayValue parseArrayAfterOpen() throws GdbParseError {
		GdbArrayValue.Builder result = GdbArrayValue.builder();
		while (true) {
			GdbCValue val = parseValue();
			result.add(val);

			char c = peek(true);
			if (c == '<') {
				match(REPEATS, false);
				GdbIntValue count = parseInteger();
				match(TIMES, false); // Pattern includes required whitespace
				long n = count.val.longValueExact();
				for (int i = 1 /* Already did i=0 */; i < n; i++) {
					result.add(val);
				}
				c = peek(true);
			}
			if (c == '}') {
				match(RBRACE, false);
				return result.build();
			}
			else if (c == ',') {
				match(COMMA, false);
			}
			else {
				throw new GdbParseError("} , or <repeats", buf);
			}
		}
	}
}
