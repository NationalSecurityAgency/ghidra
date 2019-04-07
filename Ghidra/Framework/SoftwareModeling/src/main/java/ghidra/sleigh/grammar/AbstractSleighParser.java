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

import org.antlr.runtime.*;

import ghidra.util.Msg;

public class AbstractSleighParser extends Parser implements SleighRecognizerConstants {
	protected ParsingEnvironment env;
	protected SleighLexer lexer;

	public AbstractSleighParser(TokenStream input) {
		super(input);
	}

	public AbstractSleighParser(TokenStream input, RecognizerSharedState state) {
		super(input, state);
	}

	protected void bail(String msg) {
		throw new BailoutException(msg);
	}

	@Override
	public void emitErrorMessage(String msg) {
		Msg.error(this, msg);
	}

	@Override
	public String getErrorHeader(RecognitionException e) {
		return env.getErrorHeader(e);

	}

	@Override
	public String getErrorMessage(RecognitionException e, String[] tokenNames) {
		return env.getParserErrorMessage(e, tokenNames);
	}

	@Override
	public String getTokenErrorDisplay(Token t) {
		return env.getTokenErrorDisplay(t);
	}

	public void setEnv(ParsingEnvironment env) {
		this.env = env;
	}

	public void setLexer(SleighLexer lexer) {
		this.lexer = lexer;
	}
}
