package ghidra.sleigh.grammar;
// $ANTLR 3.5.2 ghidra/sleigh/grammar/BooleanExpression.g 2019-02-28 12:48:45

import org.antlr.runtime.*;
import java.util.Stack;
import java.util.List;
import java.util.ArrayList;

@SuppressWarnings("all")
public class BooleanExpressionLexer extends Lexer {
	public static final int EOF=-1;
	public static final int T__20=20;
	public static final int T__21=21;
	public static final int ALPHA=4;
	public static final int DIGIT=5;
	public static final int ESCAPE=6;
	public static final int HEXDIGIT=7;
	public static final int IDENTIFIER=8;
	public static final int KEY_DEFINED=9;
	public static final int OCTAL_ESCAPE=10;
	public static final int OP_AND=11;
	public static final int OP_EQ=12;
	public static final int OP_NEQ=13;
	public static final int OP_NOT=14;
	public static final int OP_OR=15;
	public static final int OP_XOR=16;
	public static final int QSTRING=17;
	public static final int UNICODE_ESCAPE=18;
	public static final int WS=19;

	// delegates
	// delegators
	public Lexer[] getDelegates() {
		return new Lexer[] {};
	}

	public BooleanExpressionLexer() {} 
	public BooleanExpressionLexer(CharStream input) {
		this(input, new RecognizerSharedState());
	}
	public BooleanExpressionLexer(CharStream input, RecognizerSharedState state) {
		super(input,state);
	}
	@Override public String getGrammarFileName() { return "ghidra/sleigh/grammar/BooleanExpression.g"; }

	// $ANTLR start "KEY_DEFINED"
	public final void mKEY_DEFINED() throws RecognitionException {
		try {
			int _type = KEY_DEFINED;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/BooleanExpression.g:2:13: ( 'defined' )
			// ghidra/sleigh/grammar/BooleanExpression.g:2:15: 'defined'
			{
			match("defined"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_DEFINED"

	// $ANTLR start "OP_AND"
	public final void mOP_AND() throws RecognitionException {
		try {
			int _type = OP_AND;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/BooleanExpression.g:3:8: ( '&&' )
			// ghidra/sleigh/grammar/BooleanExpression.g:3:10: '&&'
			{
			match("&&"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "OP_AND"

	// $ANTLR start "OP_EQ"
	public final void mOP_EQ() throws RecognitionException {
		try {
			int _type = OP_EQ;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/BooleanExpression.g:4:7: ( '==' )
			// ghidra/sleigh/grammar/BooleanExpression.g:4:9: '=='
			{
			match("=="); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "OP_EQ"

	// $ANTLR start "OP_NEQ"
	public final void mOP_NEQ() throws RecognitionException {
		try {
			int _type = OP_NEQ;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/BooleanExpression.g:5:8: ( '!=' )
			// ghidra/sleigh/grammar/BooleanExpression.g:5:10: '!='
			{
			match("!="); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "OP_NEQ"

	// $ANTLR start "OP_NOT"
	public final void mOP_NOT() throws RecognitionException {
		try {
			int _type = OP_NOT;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/BooleanExpression.g:6:8: ( '!' )
			// ghidra/sleigh/grammar/BooleanExpression.g:6:10: '!'
			{
			match('!'); 
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "OP_NOT"

	// $ANTLR start "OP_OR"
	public final void mOP_OR() throws RecognitionException {
		try {
			int _type = OP_OR;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/BooleanExpression.g:7:7: ( '||' )
			// ghidra/sleigh/grammar/BooleanExpression.g:7:9: '||'
			{
			match("||"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "OP_OR"

	// $ANTLR start "OP_XOR"
	public final void mOP_XOR() throws RecognitionException {
		try {
			int _type = OP_XOR;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/BooleanExpression.g:8:8: ( '^^' )
			// ghidra/sleigh/grammar/BooleanExpression.g:8:10: '^^'
			{
			match("^^"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "OP_XOR"

	// $ANTLR start "T__20"
	public final void mT__20() throws RecognitionException {
		try {
			int _type = T__20;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/BooleanExpression.g:9:7: ( '(' )
			// ghidra/sleigh/grammar/BooleanExpression.g:9:9: '('
			{
			match('('); 
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "T__20"

	// $ANTLR start "T__21"
	public final void mT__21() throws RecognitionException {
		try {
			int _type = T__21;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/BooleanExpression.g:10:7: ( ')' )
			// ghidra/sleigh/grammar/BooleanExpression.g:10:9: ')'
			{
			match(')'); 
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "T__21"

	// $ANTLR start "IDENTIFIER"
	public final void mIDENTIFIER() throws RecognitionException {
		try {
			int _type = IDENTIFIER;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/BooleanExpression.g:76:5: ( ( ALPHA | '_' | DIGIT )+ )
			// ghidra/sleigh/grammar/BooleanExpression.g:76:9: ( ALPHA | '_' | DIGIT )+
			{
			// ghidra/sleigh/grammar/BooleanExpression.g:76:9: ( ALPHA | '_' | DIGIT )+
			int cnt1=0;
			loop1:
			while (true) {
				int alt1=2;
				int LA1_0 = input.LA(1);
				if ( ((LA1_0 >= '0' && LA1_0 <= '9')||(LA1_0 >= 'A' && LA1_0 <= 'Z')||LA1_0=='_'||(LA1_0 >= 'a' && LA1_0 <= 'z')) ) {
					alt1=1;
				}

				switch (alt1) {
				case 1 :
					// ghidra/sleigh/grammar/BooleanExpression.g:
					{
					if ( (input.LA(1) >= '0' && input.LA(1) <= '9')||(input.LA(1) >= 'A' && input.LA(1) <= 'Z')||input.LA(1)=='_'||(input.LA(1) >= 'a' && input.LA(1) <= 'z') ) {
						input.consume();
					}
					else {
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					}
					break;

				default :
					if ( cnt1 >= 1 ) break loop1;
					EarlyExitException eee = new EarlyExitException(1, input);
					throw eee;
				}
				cnt1++;
			}

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "IDENTIFIER"

	// $ANTLR start "QSTRING"
	public final void mQSTRING() throws RecognitionException {
		try {
			int _type = QSTRING;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/BooleanExpression.g:80:5: ( '\"' ( ESCAPE |~ ( '\\\\' | '\"' ) )* '\"' )
			// ghidra/sleigh/grammar/BooleanExpression.g:80:9: '\"' ( ESCAPE |~ ( '\\\\' | '\"' ) )* '\"'
			{
			match('\"'); 
			// ghidra/sleigh/grammar/BooleanExpression.g:80:13: ( ESCAPE |~ ( '\\\\' | '\"' ) )*
			loop2:
			while (true) {
				int alt2=3;
				int LA2_0 = input.LA(1);
				if ( (LA2_0=='\\') ) {
					alt2=1;
				}
				else if ( ((LA2_0 >= '\u0000' && LA2_0 <= '!')||(LA2_0 >= '#' && LA2_0 <= '[')||(LA2_0 >= ']' && LA2_0 <= '\uFFFF')) ) {
					alt2=2;
				}

				switch (alt2) {
				case 1 :
					// ghidra/sleigh/grammar/BooleanExpression.g:80:14: ESCAPE
					{
					mESCAPE(); 

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/BooleanExpression.g:80:23: ~ ( '\\\\' | '\"' )
					{
					if ( (input.LA(1) >= '\u0000' && input.LA(1) <= '!')||(input.LA(1) >= '#' && input.LA(1) <= '[')||(input.LA(1) >= ']' && input.LA(1) <= '\uFFFF') ) {
						input.consume();
					}
					else {
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					}
					break;

				default :
					break loop2;
				}
			}

			match('\"'); 
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "QSTRING"

	// $ANTLR start "ESCAPE"
	public final void mESCAPE() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/BooleanExpression.g:86:5: ( '\\\\' ( 'b' | 't' | 'n' | 'f' | 'r' | '\\\"' | '\\'' | '\\\\' ) | UNICODE_ESCAPE | OCTAL_ESCAPE )
			int alt3=3;
			int LA3_0 = input.LA(1);
			if ( (LA3_0=='\\') ) {
				switch ( input.LA(2) ) {
				case '\"':
				case '\'':
				case '\\':
				case 'b':
				case 'f':
				case 'n':
				case 'r':
				case 't':
					{
					alt3=1;
					}
					break;
				case 'u':
					{
					alt3=2;
					}
					break;
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
					{
					alt3=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 3, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 3, 0, input);
				throw nvae;
			}

			switch (alt3) {
				case 1 :
					// ghidra/sleigh/grammar/BooleanExpression.g:86:9: '\\\\' ( 'b' | 't' | 'n' | 'f' | 'r' | '\\\"' | '\\'' | '\\\\' )
					{
					match('\\'); 
					if ( input.LA(1)=='\"'||input.LA(1)=='\''||input.LA(1)=='\\'||input.LA(1)=='b'||input.LA(1)=='f'||input.LA(1)=='n'||input.LA(1)=='r'||input.LA(1)=='t' ) {
						input.consume();
					}
					else {
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/BooleanExpression.g:87:9: UNICODE_ESCAPE
					{
					mUNICODE_ESCAPE(); 

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/BooleanExpression.g:88:9: OCTAL_ESCAPE
					{
					mOCTAL_ESCAPE(); 

					}
					break;

			}
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "ESCAPE"

	// $ANTLR start "OCTAL_ESCAPE"
	public final void mOCTAL_ESCAPE() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/BooleanExpression.g:93:5: ( '\\\\' ( '0' .. '3' ) ( '0' .. '7' ) ( '0' .. '7' ) | '\\\\' ( '0' .. '7' ) ( '0' .. '7' ) | '\\\\' ( '0' .. '7' ) )
			int alt4=3;
			int LA4_0 = input.LA(1);
			if ( (LA4_0=='\\') ) {
				int LA4_1 = input.LA(2);
				if ( ((LA4_1 >= '0' && LA4_1 <= '3')) ) {
					int LA4_2 = input.LA(3);
					if ( ((LA4_2 >= '0' && LA4_2 <= '7')) ) {
						int LA4_4 = input.LA(4);
						if ( ((LA4_4 >= '0' && LA4_4 <= '7')) ) {
							alt4=1;
						}

						else {
							alt4=2;
						}

					}

					else {
						alt4=3;
					}

				}
				else if ( ((LA4_1 >= '4' && LA4_1 <= '7')) ) {
					int LA4_3 = input.LA(3);
					if ( ((LA4_3 >= '0' && LA4_3 <= '7')) ) {
						alt4=2;
					}

					else {
						alt4=3;
					}

				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 4, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 4, 0, input);
				throw nvae;
			}

			switch (alt4) {
				case 1 :
					// ghidra/sleigh/grammar/BooleanExpression.g:93:9: '\\\\' ( '0' .. '3' ) ( '0' .. '7' ) ( '0' .. '7' )
					{
					match('\\'); 
					if ( (input.LA(1) >= '0' && input.LA(1) <= '3') ) {
						input.consume();
					}
					else {
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					if ( (input.LA(1) >= '0' && input.LA(1) <= '7') ) {
						input.consume();
					}
					else {
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					if ( (input.LA(1) >= '0' && input.LA(1) <= '7') ) {
						input.consume();
					}
					else {
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/BooleanExpression.g:94:9: '\\\\' ( '0' .. '7' ) ( '0' .. '7' )
					{
					match('\\'); 
					if ( (input.LA(1) >= '0' && input.LA(1) <= '7') ) {
						input.consume();
					}
					else {
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					if ( (input.LA(1) >= '0' && input.LA(1) <= '7') ) {
						input.consume();
					}
					else {
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/BooleanExpression.g:95:9: '\\\\' ( '0' .. '7' )
					{
					match('\\'); 
					if ( (input.LA(1) >= '0' && input.LA(1) <= '7') ) {
						input.consume();
					}
					else {
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					}
					break;

			}
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "OCTAL_ESCAPE"

	// $ANTLR start "UNICODE_ESCAPE"
	public final void mUNICODE_ESCAPE() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/BooleanExpression.g:100:5: ( '\\\\' 'u' HEXDIGIT HEXDIGIT HEXDIGIT HEXDIGIT )
			// ghidra/sleigh/grammar/BooleanExpression.g:100:9: '\\\\' 'u' HEXDIGIT HEXDIGIT HEXDIGIT HEXDIGIT
			{
			match('\\'); 
			match('u'); 
			mHEXDIGIT(); 

			mHEXDIGIT(); 

			mHEXDIGIT(); 

			mHEXDIGIT(); 

			}

		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "UNICODE_ESCAPE"

	// $ANTLR start "HEXDIGIT"
	public final void mHEXDIGIT() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/BooleanExpression.g:105:5: ( '0' .. '9' | 'a' .. 'f' | 'A' .. 'F' )
			// ghidra/sleigh/grammar/BooleanExpression.g:
			{
			if ( (input.LA(1) >= '0' && input.LA(1) <= '9')||(input.LA(1) >= 'A' && input.LA(1) <= 'F')||(input.LA(1) >= 'a' && input.LA(1) <= 'f') ) {
				input.consume();
			}
			else {
				MismatchedSetException mse = new MismatchedSetException(null,input);
				recover(mse);
				throw mse;
			}
			}

		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "HEXDIGIT"

	// $ANTLR start "DIGIT"
	public final void mDIGIT() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/BooleanExpression.g:112:5: ( '0' .. '9' )
			// ghidra/sleigh/grammar/BooleanExpression.g:
			{
			if ( (input.LA(1) >= '0' && input.LA(1) <= '9') ) {
				input.consume();
			}
			else {
				MismatchedSetException mse = new MismatchedSetException(null,input);
				recover(mse);
				throw mse;
			}
			}

		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "DIGIT"

	// $ANTLR start "ALPHA"
	public final void mALPHA() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/BooleanExpression.g:117:5: ( 'A' .. 'Z' | 'a' .. 'z' )
			// ghidra/sleigh/grammar/BooleanExpression.g:
			{
			if ( (input.LA(1) >= 'A' && input.LA(1) <= 'Z')||(input.LA(1) >= 'a' && input.LA(1) <= 'z') ) {
				input.consume();
			}
			else {
				MismatchedSetException mse = new MismatchedSetException(null,input);
				recover(mse);
				throw mse;
			}
			}

		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "ALPHA"

	// $ANTLR start "WS"
	public final void mWS() throws RecognitionException {
		try {
			int _type = WS;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/BooleanExpression.g:121:5: ( ( ' ' | '\\t' | '\\r' | '\\n' )+ )
			// ghidra/sleigh/grammar/BooleanExpression.g:121:9: ( ' ' | '\\t' | '\\r' | '\\n' )+
			{
			// ghidra/sleigh/grammar/BooleanExpression.g:121:9: ( ' ' | '\\t' | '\\r' | '\\n' )+
			int cnt5=0;
			loop5:
			while (true) {
				int alt5=2;
				int LA5_0 = input.LA(1);
				if ( ((LA5_0 >= '\t' && LA5_0 <= '\n')||LA5_0=='\r'||LA5_0==' ') ) {
					alt5=1;
				}

				switch (alt5) {
				case 1 :
					// ghidra/sleigh/grammar/BooleanExpression.g:
					{
					if ( (input.LA(1) >= '\t' && input.LA(1) <= '\n')||input.LA(1)=='\r'||input.LA(1)==' ' ) {
						input.consume();
					}
					else {
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					}
					break;

				default :
					if ( cnt5 >= 1 ) break loop5;
					EarlyExitException eee = new EarlyExitException(5, input);
					throw eee;
				}
				cnt5++;
			}

			 _channel = HIDDEN; 
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "WS"

	@Override
	public void mTokens() throws RecognitionException {
		// ghidra/sleigh/grammar/BooleanExpression.g:1:8: ( KEY_DEFINED | OP_AND | OP_EQ | OP_NEQ | OP_NOT | OP_OR | OP_XOR | T__20 | T__21 | IDENTIFIER | QSTRING | WS )
		int alt6=12;
		switch ( input.LA(1) ) {
		case 'd':
			{
			int LA6_1 = input.LA(2);
			if ( (LA6_1=='e') ) {
				int LA6_12 = input.LA(3);
				if ( (LA6_12=='f') ) {
					int LA6_15 = input.LA(4);
					if ( (LA6_15=='i') ) {
						int LA6_16 = input.LA(5);
						if ( (LA6_16=='n') ) {
							int LA6_17 = input.LA(6);
							if ( (LA6_17=='e') ) {
								int LA6_18 = input.LA(7);
								if ( (LA6_18=='d') ) {
									int LA6_19 = input.LA(8);
									if ( ((LA6_19 >= '0' && LA6_19 <= '9')||(LA6_19 >= 'A' && LA6_19 <= 'Z')||LA6_19=='_'||(LA6_19 >= 'a' && LA6_19 <= 'z')) ) {
										alt6=10;
									}

									else {
										alt6=1;
									}

								}

								else {
									alt6=10;
								}

							}

							else {
								alt6=10;
							}

						}

						else {
							alt6=10;
						}

					}

					else {
						alt6=10;
					}

				}

				else {
					alt6=10;
				}

			}

			else {
				alt6=10;
			}

			}
			break;
		case '&':
			{
			alt6=2;
			}
			break;
		case '=':
			{
			alt6=3;
			}
			break;
		case '!':
			{
			int LA6_4 = input.LA(2);
			if ( (LA6_4=='=') ) {
				alt6=4;
			}

			else {
				alt6=5;
			}

			}
			break;
		case '|':
			{
			alt6=6;
			}
			break;
		case '^':
			{
			alt6=7;
			}
			break;
		case '(':
			{
			alt6=8;
			}
			break;
		case ')':
			{
			alt6=9;
			}
			break;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case '_':
		case 'a':
		case 'b':
		case 'c':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z':
			{
			alt6=10;
			}
			break;
		case '\"':
			{
			alt6=11;
			}
			break;
		case '\t':
		case '\n':
		case '\r':
		case ' ':
			{
			alt6=12;
			}
			break;
		default:
			NoViableAltException nvae =
				new NoViableAltException("", 6, 0, input);
			throw nvae;
		}
		switch (alt6) {
			case 1 :
				// ghidra/sleigh/grammar/BooleanExpression.g:1:10: KEY_DEFINED
				{
				mKEY_DEFINED(); 

				}
				break;
			case 2 :
				// ghidra/sleigh/grammar/BooleanExpression.g:1:22: OP_AND
				{
				mOP_AND(); 

				}
				break;
			case 3 :
				// ghidra/sleigh/grammar/BooleanExpression.g:1:29: OP_EQ
				{
				mOP_EQ(); 

				}
				break;
			case 4 :
				// ghidra/sleigh/grammar/BooleanExpression.g:1:35: OP_NEQ
				{
				mOP_NEQ(); 

				}
				break;
			case 5 :
				// ghidra/sleigh/grammar/BooleanExpression.g:1:42: OP_NOT
				{
				mOP_NOT(); 

				}
				break;
			case 6 :
				// ghidra/sleigh/grammar/BooleanExpression.g:1:49: OP_OR
				{
				mOP_OR(); 

				}
				break;
			case 7 :
				// ghidra/sleigh/grammar/BooleanExpression.g:1:55: OP_XOR
				{
				mOP_XOR(); 

				}
				break;
			case 8 :
				// ghidra/sleigh/grammar/BooleanExpression.g:1:62: T__20
				{
				mT__20(); 

				}
				break;
			case 9 :
				// ghidra/sleigh/grammar/BooleanExpression.g:1:68: T__21
				{
				mT__21(); 

				}
				break;
			case 10 :
				// ghidra/sleigh/grammar/BooleanExpression.g:1:74: IDENTIFIER
				{
				mIDENTIFIER(); 

				}
				break;
			case 11 :
				// ghidra/sleigh/grammar/BooleanExpression.g:1:85: QSTRING
				{
				mQSTRING(); 

				}
				break;
			case 12 :
				// ghidra/sleigh/grammar/BooleanExpression.g:1:93: WS
				{
				mWS(); 

				}
				break;

		}
	}



}
