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
package ghidra.sleigh.grammar;

import java.io.*;
import java.util.Iterator;
import java.util.List;

import org.antlr.runtime.CommonTokenStream;
import org.antlr.runtime.Token;
import org.antlr.runtime.tree.*;

public class ANTLRUtil {
	static String indent(int n) {
		StringBuilder sb = new StringBuilder();
		for (int ii = 0; ii < n; ++ii) {
			sb.append("    ");
		}
		return sb.toString();
	}

	public static void debugNodeStream(BufferedTreeNodeStream nodes, PrintStream out) {
		Iterator<Object> iterator = nodes.iterator();
		int indent = 0;
		while (iterator.hasNext()) {
			Object object = iterator.next();
			CommonTree node = (CommonTree) object;
			Token token = node.token;
			if (token != null) {
				if (token.getType() == 2) {
					++indent;
					continue;
				}
				else if (token.getType() == 3) {
					--indent;
					continue;
				}
			}
			String line =
				token == null ? "no pos" : token.getLine() + ":" + token.getCharPositionInLine();
			out.println(indent(indent) + "'" + object + "'     (" + line + ")");
		}
	}

	public static void debugTokenStream(CommonTokenStream tokens, PrintStream out) {
		List<? extends Token> list = tokens.getTokens();
		Iterator<? extends Token> iterator = list.iterator();
		int ii = -1;
		while (iterator.hasNext()) {
			++ii;
			Object object = iterator.next();
			out.println(object + "     (" + ii + ")");
		}
	}

	public static void debugTree(Tree tree, PrintStream out) {
		debugNodeStream(new BufferedTreeNodeStream(tree), out);
	}

	public static String getLine(Reader reader, int lineno) throws IOException {
		BufferedReader buf = new BufferedReader(reader);
		String line = null;
		while (lineno > 0) {
			line = buf.readLine();
			--lineno;
		}
		return line;
	}

	public static String getLine(LineArrayListWriter writer, int lineno) throws IOException {
		int line = StrictMath.min(writer.getLines().size() - 1, lineno - 1);
		final int size = writer.getLines().size();
		while (line < 0) {
			line += size;
		}
		return writer.getLines().get(line);
	}

	public static String generateArrow(int charPositionInLine) {
		StringBuilder sb = new StringBuilder();
		while (charPositionInLine > 0) {
			sb.append("-");
			--charPositionInLine;
		}
		sb.append("^");
		return sb.toString();
	}

	public static int tabCompensate(String line, int charPositionInLine) {
		if (charPositionInLine < 0) {
			return charPositionInLine;
		}
		int pos = 0;
		char[] cs = new char[charPositionInLine];
		line.getChars(0, charPositionInLine, cs, 0);
		int ii = 0;
		while (ii < charPositionInLine) {
			if (cs[ii] == '\t') {

				pos = (pos + 8) / 8 * 8;
			}
			else {
				++pos;
			}
			++ii;
		}
		return pos;
	}
}
