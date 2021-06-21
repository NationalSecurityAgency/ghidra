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

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import org.junit.Test;

import agent.gdb.manager.parsing.GdbMiParser;
import agent.gdb.manager.parsing.GdbMiParser.GdbMiFieldList;
import agent.gdb.manager.parsing.GdbParsingUtils.GdbParseError;

public class GdbMiParserTest {
	protected GdbMiFieldList buildFieldList(Consumer<GdbMiFieldList.Builder> conf) {
		GdbMiFieldList.Builder builder = GdbMiFieldList.builder();
		conf.accept(builder);
		return builder.build();
	}

	@Test
	public void testMatch() throws GdbParseError {
		GdbMiParser parser = new GdbMiParser("Hello, World!");
		assertEquals("Hello", parser.match(Pattern.compile("\\w+"), true));
		assertEquals(",", parser.match(GdbMiParser.COMMA, true));
	}

	@Test
	public void testParseString() throws GdbParseError {
		GdbMiParser parser = new GdbMiParser("\"Hello, World!\\n\"");
		assertEquals("Hello, World!\n", parser.parseString());
	}

	@Test
	public void testParseList() throws GdbParseError {
		GdbMiParser parser = new GdbMiParser("[\"Hello\",\"World\"]");
		assertEquals(Arrays.asList(new String[] { "Hello", "World" }), parser.parseList());
	}

	@Test
	public void testParseMap() throws GdbParseError {
		GdbMiParser parser = new GdbMiParser("{h=\"Hello\",w=\"World\"}");
		assertEquals(buildFieldList((exp) -> {
			exp.add("h", "Hello");
			exp.add("w", "World");
		}), parser.parseMap());
	}
}
