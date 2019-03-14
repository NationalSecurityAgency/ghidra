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

import java.util.HashSet;

import org.antlr.runtime.*;
import org.antlr.runtime.tree.CommonErrorNode;

public class ParsingEnvironment {
	public ParsingEnvironment(ParsingEnvironment env) {
		this.writer = env.writer;
		this.locator = env.locator;
		env.children.add(this);
	}

	public ParsingEnvironment(LineArrayListWriter writer) {
		this.writer = writer;
		this.locator = new Locator();
	}

	private HashSet<ParsingEnvironment> children = new HashSet<>();

	private int lexingErrors = 0;
	private int parsingErrors = 0;

	public int getLexingErrors() {
		return lexingErrors + getChildEnvLexingErrors();
	}

	private int getChildEnvLexingErrors() {
		int childErrors = 0;
		for (ParsingEnvironment env : children) {
			childErrors += env.lexingErrors;
		}
		return childErrors;
	}

	public int getParsingErrors() {
		return parsingErrors + getChildEnvParsingErrors();
	}

	private int getChildEnvParsingErrors() {
		int childErrors = 0;
		for (ParsingEnvironment env : children) {
			childErrors += env.parsingErrors;
		}
		return childErrors;
	}

	public void lexingError() {
		++lexingErrors;
	}

	public void parsingError() {
		++parsingErrors;
	}

	private final Locator locator;

	public Locator getLocator() {
		return locator;
	}

	private final LineArrayListWriter writer;

	public LineArrayListWriter getWriter() {
		return writer;
	}

	public String getErrorHeader(RecognitionException e) {
		if (e.node != null) {
			try {
				e = ((CommonErrorNode) e.node).trappedException;
			}
			catch (ClassCastException cce) {
				// ignore for now
			}
		}
		Location location = locator.getLocation(e.line);
		if (location == null) {
			return "UNKNOWN LOCATION (uncorrelated parser line " + e.line + ")";
		}
		if (location.lineno < 0) {
			System.out.println("whoa, line < 0");
		}
		return location.filename + " line " + location.lineno + ":";
	}

	public String getLexerErrorMessage(RecognitionException e, String[] tokenNames) {
		lexingError();
		return getErrorMessage(e, tokenNames, writer);
	}

	public String getParserErrorMessage(RecognitionException e, String[] tokenNames) {
		parsingError();
		return getErrorMessage(e, tokenNames, writer);
	}

	static final String NEWLINE = System.getProperty("line.separator");

	public String getErrorMessage(RecognitionException e, String[] tokenNames,
			LineArrayListWriter mywriter) {
		int lineno = e.line;
		int charpos = e.charPositionInLine;
		if (e.node != null) {
			try {
				e = ((CommonErrorNode) e.node).trappedException;
			}
			catch (ClassCastException cce) {
				// ignore for now
			}
		}
		String msg = e.getMessage();
		if (e instanceof UnwantedTokenException) {
			UnwantedTokenException ute = (UnwantedTokenException) e;
			String tokenName = "<unknown>";
			if (ute.expecting == Token.EOF) {
				tokenName = "EOF";
			}
			else {
				if (tokenNames != null) {
					tokenName = tokenNames[ute.expecting];
				}
			}
			msg = "extraneous input " + getTokenErrorDisplay(ute.getUnexpectedToken()) +
				" expecting " + tokenName;
		}
		else if (e instanceof MissingTokenException) {
			MissingTokenException mte = (MissingTokenException) e;
			if (mte.expecting == Token.EOF) {
				msg = "unexpected token: " + getTokenErrorDisplay(e.token);
			}
			else {
				msg = "missing " + tokenNames[mte.getMissingType()] + ", unexpected " +
					tokenNames[mte.getUnexpectedType()] + " at " + getTokenErrorDisplay(e.token);
			}
		}
		else if (e instanceof MismatchedTokenException) {
			MismatchedTokenException mte = (MismatchedTokenException) e;
			if (mte.token == null) {
				msg = "expecting '" + ((char) mte.expecting) + "', unexpected characer: '" +
					((char) mte.c) + "'";
			}
			else {
				msg = "expecting " + (mte.expecting == -1 ? "EOF" : tokenNames[mte.expecting]) +
					", unexpected token: " + getTokenErrorDisplay(e.token);
			}
			if (mte.expecting == SleighCompiler.RBRACKET) {
				msg += " (forget to close an identifier list above?)";
			}
		}
		else if (e instanceof MismatchedTreeNodeException) {
			MismatchedTreeNodeException mtne = (MismatchedTreeNodeException) e;
			String tokenName = "<unknown>";
			if (mtne.expecting == Token.EOF) {
				tokenName = "EOF";
			}
			else {
				if (tokenNames != null) {
					tokenName = tokenNames[mtne.expecting];
				}
			}
			msg = "mismatched tree node: " + mtne.node + " expecting " + tokenName;
		}
		else if (e instanceof NoViableAltException) {
			NoViableAltException nvae = (NoViableAltException) e;
			if (e.token == null) {
				msg = "unexpected text";
			}
			else {
				if (nvae.c == -1) {
					msg = "no viable alternative on EOF (missing semi-colon after this?)";
				}
				else {
					msg = "no viable alternative on " + tokenNames[nvae.c] + ": " +
						getTokenErrorDisplay(e.token);
				}
			}
		}
		else if (e instanceof EarlyExitException) {
			// EarlyExitException eee = (EarlyExitException)e;
			// for development, can add "(decision="+eee.decisionNumber+")"
			msg = "required (...)+ loop did not match anything at input " +
				getTokenErrorDisplay(e.token);
		}
		else if (e instanceof MismatchedSetException) {
			MismatchedSetException mse = (MismatchedSetException) e;
			msg = "mismatched input " + getTokenErrorDisplay(e.token) + " expecting set " +
				mse.expecting;
		}
		else if (e instanceof MismatchedNotSetException) {
			MismatchedNotSetException mse = (MismatchedNotSetException) e;
			msg = "mismatched input " + getTokenErrorDisplay(e.token) + " expecting set " +
				mse.expecting;
		}
		else if (e instanceof FailedPredicateException) {
			FailedPredicateException fpe = (FailedPredicateException) e;
			msg = "rule " + fpe.ruleName + " failed predicate: {" + fpe.predicateText + "}?";
		}
		String line = "<internal error fetching line>";
		try {
			line = removePreprocessor(ANTLRUtil.getLine(mywriter, lineno));
		}
		catch (Exception e1) {
			e1.printStackTrace();
		}
		int position = ANTLRUtil.tabCompensate(line, charpos);
		return msg + ":" + NEWLINE + NEWLINE + line + NEWLINE + ANTLRUtil.generateArrow(position) +
			NEWLINE;
	}

	private String removePreprocessor(String line) {
		return line.replaceAll("\b.*?\b", "");
	}

	public String getTokenErrorDisplay(Token t) {
		if (t == null) {
			return "(null)";
		}
		String s = t.getText();
		if (s == null) {
			if (t.getType() == Token.EOF) {
				s = "<EOF>";
			}
			else {
				s = "<" + t.getType() + ">";
			}
		}
		s = s.replaceAll("\n", "\\\\n");
		s = s.replaceAll("\r", "\\\\r");
		s = s.replaceAll("\t", "\\\\t");
		return "'" + s + "'";
	}

	public String format(BailoutException be) {
		if (getLexingErrors() > 0) {
			if (getParsingErrors() > 0) {
				return be.getMessage() + ": " + getLexingErrors() + " lexing errors, " +
					getParsingErrors() + " parsing errors";

			}
			return be.getMessage() + ": " + getLexingErrors() + " lexing errors";
		}
		if (getParsingErrors() > 0) {
			return be.getMessage() + ": " + getParsingErrors() + " parsing errors";
		}
		return be.getMessage();
	}
}
