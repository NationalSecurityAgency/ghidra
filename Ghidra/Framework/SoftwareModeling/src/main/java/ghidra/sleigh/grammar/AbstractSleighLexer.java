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

public abstract class AbstractSleighLexer extends Lexer implements SleighRecognizerConstants {
	protected ParsingEnvironment env = null;

	public AbstractSleighLexer() {
		super();
	}

	public AbstractSleighLexer(CharStream input, RecognizerSharedState state) {
		super(input, state);
	}

	@Override
	public Token emit() {
		SleighToken t = new SleighToken(input, state.type, state.channel, state.tokenStartCharIndex,
			getCharIndex() - 1);
		Location location = env.getLocator().getLocation(state.tokenStartLine);
		t.setLocation(location);
		t.setLine(state.tokenStartLine);
		t.setText(state.text);
		t.setCharPositionInLine(state.tokenStartCharPositionInLine);
		emit(t);
		return t;
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
		return env.getLexerErrorMessage(e, tokenNames);
	}

	@Override
	public String getTokenErrorDisplay(Token t) {
		return env.getTokenErrorDisplay(t);
	}

	protected void preprocess(String text) {
		String[] split = text.split("###");
		if (split.length == 2) {
			env.getLocator().registerLocation(input.getLine(),
				new Location(split[0], Integer.parseInt(split[1])));
		}
		// + 2 because of stripped \b characters in front and back
		input.setCharPositionInLine(input.getCharPositionInLine() - (text.length() + 2));
	}

	public void setEnv(ParsingEnvironment env) {
		this.env = env;
	}
}
