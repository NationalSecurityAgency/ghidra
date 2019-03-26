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

import java.io.File;

import org.antlr.runtime.*;
import org.antlr.runtime.tree.BufferedTreeNodeStream;

public class SleighEchoRun {
	public static void main(String[] args) {
		try {
			LineArrayListWriter writer = new LineArrayListWriter();
			ParsingEnvironment env = new ParsingEnvironment(writer);
			SleighPreprocessor sp = new SleighPreprocessor(
				new HashMapPreprocessorDefinitionsAdapter(), new File(args[0]));
			sp.process(writer);
			CharStream input = new ANTLRStringStream(writer.toString());
			SleighLexer lex = new SleighLexer(input);
			lex.setEnv(env);
			UnbufferedTokenStream tokens = new UnbufferedTokenStream(lex);
			SleighParser parser = new SleighParser(tokens);
			parser.setEnv(env);
			parser.setLexer(lex);
			SleighParser.spec_return root = parser.spec();
			BufferedTreeNodeStream nodes = new BufferedTreeNodeStream(root.tree);
			nodes.setTokenStream(tokens);
//			ANTLRUtil.debugNodeStream(nodes, System.out);
			SleighEcho walker = new SleighEcho(nodes);
			walker.root();
		}
		catch (Throwable t) {
			t.printStackTrace();
		}
	}
}
