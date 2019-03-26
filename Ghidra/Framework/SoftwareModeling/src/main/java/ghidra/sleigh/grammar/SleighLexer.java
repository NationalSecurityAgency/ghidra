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

import org.antlr.runtime.CharStream;
import org.antlr.runtime.TokenSource;

public class SleighLexer extends LexerMultiplexer implements SleighRecognizerConstants {
	public SleighLexer(CharStream input) {
		super(new BaseLexer(input), new DisplayLexer(input), new SemanticLexer(input));
	}

	public void setEnv(ParsingEnvironment env) {
		for (TokenSource src : modes) {
			AbstractSleighLexer lex = (AbstractSleighLexer) src;
			lex.setEnv(env);
		}
	}
}
