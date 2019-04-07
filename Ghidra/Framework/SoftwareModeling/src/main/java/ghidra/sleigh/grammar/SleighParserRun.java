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

public class SleighParserRun {
	public static void main(String[] args) {
		ParsingEnvironment env = null;
		try {
			LineArrayListWriter writer = new LineArrayListWriter();
			env = new ParsingEnvironment(writer);
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
			// System.out.println("---------");
			// System.out.println(writer.toString());
			// System.out.println("---------");
			SleighParser.spec_return spec = parser.spec();
			ANTLRUtil.debugTree(spec.tree, System.out);
		}
		catch (BailoutException be) {
			System.err.println(env.format(be));
		}
		catch (Throwable t) {
			t.printStackTrace();
		}
	}
}
