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
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import org.junit.Test;

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
		GdbMiParser parser = new GdbMiParser("""
				Hello, World""");
		assertEquals("Hello", parser.match(Pattern.compile("\\w+"), true));
		assertEquals(",", parser.match(GdbMiParser.COMMA, true));
	}

	@Test
	public void testParseString() throws GdbParseError {
		GdbMiParser parser = new GdbMiParser("""
				"Hello, World!\\n"\
				""");
		assertEquals("Hello, World!\n", parser.parseString());
		parser.checkEmpty(false);
	}

	@Test
	public void testParseList() throws GdbParseError {
		GdbMiParser parser = new GdbMiParser("""
				["Hello","World"]""");
		assertEquals(Arrays.asList(new String[] { "Hello", "World" }), parser.parseList());
		parser.checkEmpty(false);
	}

	@Test
	public void testParseMap() throws GdbParseError {
		GdbMiParser parser = new GdbMiParser("""
				{h="Hello",w="World"}""");
		assertEquals(buildFieldList((exp) -> {
			exp.add("h", "Hello");
			exp.add("w", "World");
		}), parser.parseMap());
		parser.checkEmpty(false);
	}

	@Test
	public void testParseStringEscapes() throws GdbParseError {
		GdbMiParser parser = new GdbMiParser("""
				"basic=\\n\\b\\t\\f\\r c=\\e[0m\\a delim=\\\\\\" octal=\\000\\177"\
				""");
		assertEquals("basic=\n\b\t\f\r c=\033[0m\007 delim=\\\" octal=\000\177",
			parser.parseString());
		parser.checkEmpty(false);
	}

	@Test
	public void testParseStringUTF8() throws GdbParseError {
		GdbMiParser parser = new GdbMiParser("""
				"\\302\\244 \\342\\204\\212 \\343\\201\\251 \\351\\276\\231 \\360\\237\\230\\200"\
				""");
		assertEquals("\u00a4 \u210a \u3069 \u9f99 \ud83d\ude00", parser.parseString());
		parser.checkEmpty(false);
	}

	@Test
	public void testParseBreakpointCommandList() throws GdbParseError {
		GdbMiParser parser = new GdbMiParser("""
				BreakpointTable={nr_rows="1",nr_cols="6",hdr=[{width="7",alignment="-1",\
				col_name="number",colhdr="Num"},{width="14",alignment="-1",col_name="type",\
				colhdr="Type"},{width="4",alignment="-1",col_name="disp",colhdr="Disp"},\
				{width="3",alignment="-1",col_name="enabled",colhdr="Enb"},{width="18",\
				alignment="-1",col_name="addr",colhdr="Address"},{width="40",alignment="2",\
				col_name="what",colhdr="What"}],body=[bkpt={number="1",type="breakpoint",\
				disp="keep",enabled="y",addr="0x00007ffff779c96f",at="<poll+31>",\
				thread-groups=["i1"],times="0",script={"echo asdf","echo ghjk","echo asdf"},\
				original-location="*0x7ffff779c96f"}]}""");
		GdbMiFieldList result = parser.parseFields(false);
		GdbMiFieldList table = result.getFieldList("BreakpointTable");
		GdbMiFieldList body = table.getFieldList("body");
		List<Object> bkpts = List.copyOf(body.get("bkpt"));
		assertEquals(1, bkpts.size());
		GdbMiFieldList bkpt0 = (GdbMiFieldList) bkpts.get(0);
		GdbMiFieldList script = bkpt0.getFieldList("script");
		List<Object> lines = List.copyOf(script.get(null));
		assertEquals(List.of("echo asdf", "echo ghjk", "echo asdf"), lines);
		parser.checkEmpty(false);
	}
}
