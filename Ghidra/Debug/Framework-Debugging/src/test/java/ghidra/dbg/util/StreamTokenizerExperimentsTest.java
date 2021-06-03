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

import static org.junit.Assert.assertEquals;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

public class StreamTokenizerExperimentsTest {
	public static List<String> tokenize(String cmdLine) {
		List<String> list = new ArrayList<>();
		StreamTokenizer tokenizer =
			new StreamTokenizer(new StringReader(cmdLine));
		tokenizer.wordChars(0, 255);
		tokenizer.whitespaceChars(' ', ' ');
		tokenizer.quoteChar('"');

		try {
			@SuppressWarnings("unused")
			int type;
			while (StreamTokenizer.TT_EOF != (type = tokenizer.nextToken())) {
				//System.err.println("type=" + type);
				list.add(tokenizer.sval);
			}
		}
		catch (IOException e) {
			throw new AssertionError(e);
		}

		return list;
	}

	@Test
	public void testStreamTokenizerString() {
		assertEquals(List.of("echo", "Hello, World!"), tokenize("echo \"Hello, World!\""));
	}

	@Test
	public void testStreamTokenizerEscapedQuoteInString() {
		assertEquals(List.of("echo", "Hello, \"World!"), tokenize("echo \"Hello, \\\"World!\""));
	}

	/**
	 * Sigh. Escapes are not recognized outside of strings.
	 */
	@Test
	public void testStreamTokenizerEscapedSpace() {
		assertEquals(List.of("echo", "Hello,\\", "World!"), tokenize("echo Hello,\\ World!"));
	}
}
