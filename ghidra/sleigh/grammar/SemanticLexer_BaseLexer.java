package ghidra.sleigh.grammar;
// $ANTLR 3.5.2 BaseLexer.g 2019-02-28 12:48:47

import org.antlr.runtime.*;
import java.util.Stack;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;

@SuppressWarnings("all")
public class SemanticLexer_BaseLexer extends AbstractSleighLexer {
	public static final int EOF=-1;
	public static final int ALPHA=4;
	public static final int ALPHAUP=5;
	public static final int AMPERSAND=6;
	public static final int ASSIGN=7;
	public static final int ASTERISK=8;
	public static final int BINDIGIT=9;
	public static final int BIN_INT=10;
	public static final int BOOL_AND=11;
	public static final int BOOL_OR=12;
	public static final int BOOL_XOR=13;
	public static final int CARET=14;
	public static final int COLON=15;
	public static final int COMMA=16;
	public static final int CPPCOMMENT=17;
	public static final int DEC_INT=18;
	public static final int DIGIT=19;
	public static final int DISPCHAR=20;
	public static final int ELLIPSIS=21;
	public static final int EOL=22;
	public static final int EQUAL=23;
	public static final int ESCAPE=24;
	public static final int EXCLAIM=25;
	public static final int FDIV=26;
	public static final int FEQUAL=27;
	public static final int FGREAT=28;
	public static final int FGREATEQUAL=29;
	public static final int FLESS=30;
	public static final int FLESSEQUAL=31;
	public static final int FMINUS=32;
	public static final int FMULT=33;
	public static final int FNOTEQUAL=34;
	public static final int FPLUS=35;
	public static final int GREAT=36;
	public static final int GREATEQUAL=37;
	public static final int HEXDIGIT=38;
	public static final int HEX_INT=39;
	public static final int IDENTIFIER=40;
	public static final int KEY_ALIGNMENT=41;
	public static final int KEY_ATTACH=42;
	public static final int KEY_BIG=43;
	public static final int KEY_BITRANGE=44;
	public static final int KEY_BUILD=45;
	public static final int KEY_CALL=46;
	public static final int KEY_CONTEXT=47;
	public static final int KEY_CROSSBUILD=48;
	public static final int KEY_DEC=49;
	public static final int KEY_DEFAULT=50;
	public static final int KEY_DEFINE=51;
	public static final int KEY_ENDIAN=52;
	public static final int KEY_EXPORT=53;
	public static final int KEY_GOTO=54;
	public static final int KEY_HEX=55;
	public static final int KEY_LITTLE=56;
	public static final int KEY_LOCAL=57;
	public static final int KEY_MACRO=58;
	public static final int KEY_NAMES=59;
	public static final int KEY_NOFLOW=60;
	public static final int KEY_OFFSET=61;
	public static final int KEY_PCODEOP=62;
	public static final int KEY_RETURN=63;
	public static final int KEY_SIGNED=64;
	public static final int KEY_SIZE=65;
	public static final int KEY_SPACE=66;
	public static final int KEY_TOKEN=67;
	public static final int KEY_TYPE=68;
	public static final int KEY_UNIMPL=69;
	public static final int KEY_VALUES=70;
	public static final int KEY_VARIABLES=71;
	public static final int KEY_WORDSIZE=72;
	public static final int LBRACE=73;
	public static final int LBRACKET=74;
	public static final int LEFT=75;
	public static final int LESS=76;
	public static final int LESSEQUAL=77;
	public static final int LINECOMMENT=78;
	public static final int LPAREN=79;
	public static final int MINUS=80;
	public static final int NOTEQUAL=81;
	public static final int OCTAL_ESCAPE=82;
	public static final int OP_ADD=83;
	public static final int OP_ADDRESS_OF=84;
	public static final int OP_ALIGNMENT=85;
	public static final int OP_AND=86;
	public static final int OP_APPLY=87;
	public static final int OP_ARGUMENTS=88;
	public static final int OP_ASSIGN=89;
	public static final int OP_BIG=90;
	public static final int OP_BIN_CONSTANT=91;
	public static final int OP_BITRANGE=92;
	public static final int OP_BITRANGE2=93;
	public static final int OP_BITRANGES=94;
	public static final int OP_BIT_PATTERN=95;
	public static final int OP_BOOL_AND=96;
	public static final int OP_BOOL_OR=97;
	public static final int OP_BOOL_XOR=98;
	public static final int OP_BUILD=99;
	public static final int OP_CALL=100;
	public static final int OP_CONCATENATE=101;
	public static final int OP_CONSTRUCTOR=102;
	public static final int OP_CONTEXT=103;
	public static final int OP_CONTEXT_BLOCK=104;
	public static final int OP_CROSSBUILD=105;
	public static final int OP_CTLIST=106;
	public static final int OP_DEC=107;
	public static final int OP_DECLARATIVE_SIZE=108;
	public static final int OP_DEC_CONSTANT=109;
	public static final int OP_DEFAULT=110;
	public static final int OP_DEREFERENCE=111;
	public static final int OP_DISPLAY=112;
	public static final int OP_DIV=113;
	public static final int OP_ELLIPSIS=114;
	public static final int OP_ELLIPSIS_RIGHT=115;
	public static final int OP_EMPTY_LIST=116;
	public static final int OP_ENDIAN=117;
	public static final int OP_EQUAL=118;
	public static final int OP_EXPORT=119;
	public static final int OP_FADD=120;
	public static final int OP_FDIV=121;
	public static final int OP_FEQUAL=122;
	public static final int OP_FGREAT=123;
	public static final int OP_FGREATEQUAL=124;
	public static final int OP_FIELDDEF=125;
	public static final int OP_FIELDDEFS=126;
	public static final int OP_FIELD_MODS=127;
	public static final int OP_FLESS=128;
	public static final int OP_FLESSEQUAL=129;
	public static final int OP_FMULT=130;
	public static final int OP_FNEGATE=131;
	public static final int OP_FNOTEQUAL=132;
	public static final int OP_FSUB=133;
	public static final int OP_GOTO=134;
	public static final int OP_GREAT=135;
	public static final int OP_GREATEQUAL=136;
	public static final int OP_HEX=137;
	public static final int OP_HEX_CONSTANT=138;
	public static final int OP_IDENTIFIER=139;
	public static final int OP_IDENTIFIER_LIST=140;
	public static final int OP_IF=141;
	public static final int OP_INTBLIST=142;
	public static final int OP_INVERT=143;
	public static final int OP_JUMPDEST_ABSOLUTE=144;
	public static final int OP_JUMPDEST_DYNAMIC=145;
	public static final int OP_JUMPDEST_LABEL=146;
	public static final int OP_JUMPDEST_RELATIVE=147;
	public static final int OP_JUMPDEST_SYMBOL=148;
	public static final int OP_LABEL=149;
	public static final int OP_LEFT=150;
	public static final int OP_LESS=151;
	public static final int OP_LESSEQUAL=152;
	public static final int OP_LITTLE=153;
	public static final int OP_LOCAL=154;
	public static final int OP_MACRO=155;
	public static final int OP_MULT=156;
	public static final int OP_NAMES=157;
	public static final int OP_NEGATE=158;
	public static final int OP_NIL=159;
	public static final int OP_NOFLOW=160;
	public static final int OP_NOP=161;
	public static final int OP_NOT=162;
	public static final int OP_NOTEQUAL=163;
	public static final int OP_NOT_DEFAULT=164;
	public static final int OP_NO_CONTEXT_BLOCK=165;
	public static final int OP_NO_FIELD_MOD=166;
	public static final int OP_OR=167;
	public static final int OP_PARENTHESIZED=168;
	public static final int OP_PCODE=169;
	public static final int OP_PCODEOP=170;
	public static final int OP_QSTRING=171;
	public static final int OP_REM=172;
	public static final int OP_RETURN=173;
	public static final int OP_RIGHT=174;
	public static final int OP_SDIV=175;
	public static final int OP_SECTION_LABEL=176;
	public static final int OP_SEMANTIC=177;
	public static final int OP_SEQUENCE=178;
	public static final int OP_SGREAT=179;
	public static final int OP_SGREATEQUAL=180;
	public static final int OP_SIGNED=181;
	public static final int OP_SIZE=182;
	public static final int OP_SIZING_SIZE=183;
	public static final int OP_SLESS=184;
	public static final int OP_SLESSEQUAL=185;
	public static final int OP_SPACE=186;
	public static final int OP_SPACEMODS=187;
	public static final int OP_SREM=188;
	public static final int OP_SRIGHT=189;
	public static final int OP_STRING=190;
	public static final int OP_STRING_OR_IDENT_LIST=191;
	public static final int OP_SUB=192;
	public static final int OP_SUBTABLE=193;
	public static final int OP_TABLE=194;
	public static final int OP_TOKEN=195;
	public static final int OP_TRUNCATION_SIZE=196;
	public static final int OP_TYPE=197;
	public static final int OP_UNIMPL=198;
	public static final int OP_VALUES=199;
	public static final int OP_VARIABLES=200;
	public static final int OP_VARNODE=201;
	public static final int OP_WHITESPACE=202;
	public static final int OP_WILDCARD=203;
	public static final int OP_WITH=204;
	public static final int OP_WORDSIZE=205;
	public static final int OP_XOR=206;
	public static final int PERCENT=207;
	public static final int PIPE=208;
	public static final int PLUS=209;
	public static final int PP_ESCAPE=210;
	public static final int PP_POSITION=211;
	public static final int QSTRING=212;
	public static final int RBRACE=213;
	public static final int RBRACKET=214;
	public static final int RES_IF=215;
	public static final int RES_IS=216;
	public static final int RES_WITH=217;
	public static final int RIGHT=218;
	public static final int RPAREN=219;
	public static final int SDIV=220;
	public static final int SEMI=221;
	public static final int SGREAT=222;
	public static final int SGREATEQUAL=223;
	public static final int SLASH=224;
	public static final int SLESS=225;
	public static final int SLESSEQUAL=226;
	public static final int SPEC_AND=227;
	public static final int SPEC_OR=228;
	public static final int SPEC_XOR=229;
	public static final int SREM=230;
	public static final int SRIGHT=231;
	public static final int TILDE=232;
	public static final int Tokens=233;
	public static final int UNDERSCORE=234;
	public static final int UNICODE_ESCAPE=235;
	public static final int UNKNOWN=236;
	public static final int WS=237;

	// delegates
	// delegators
	public SemanticLexer gSemanticLexer;
	public SemanticLexer gParent;
	public AbstractSleighLexer[] getDelegates() {
		return new AbstractSleighLexer[] {};
	}

	public SemanticLexer_BaseLexer() {} 
	public SemanticLexer_BaseLexer(CharStream input, SemanticLexer gSemanticLexer) {
		this(input, new RecognizerSharedState(), gSemanticLexer);
	}
	public SemanticLexer_BaseLexer(CharStream input, RecognizerSharedState state, SemanticLexer gSemanticLexer) {
		super(input,state);
		this.gSemanticLexer = gSemanticLexer;
		gParent = gSemanticLexer;
	}
	@Override public String getGrammarFileName() { return "BaseLexer.g"; }

	// $ANTLR start "PP_ESCAPE"
	public final void mPP_ESCAPE() throws RecognitionException {
		try {
			// BaseLexer.g:146:2: ( '\\b' )
			// BaseLexer.g:146:4: '\\b'
			{
			match('\b'); if (state.failed) return;
			}

		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "PP_ESCAPE"

	// $ANTLR start "PP_POSITION"
	public final void mPP_POSITION() throws RecognitionException {
		try {
			int _type = PP_POSITION;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:150:2: ( PP_ESCAPE (~ ( '\\n' | PP_ESCAPE ) )* PP_ESCAPE )
			// BaseLexer.g:150:4: PP_ESCAPE (~ ( '\\n' | PP_ESCAPE ) )* PP_ESCAPE
			{
			mPP_ESCAPE(); if (state.failed) return;

			// BaseLexer.g:150:14: (~ ( '\\n' | PP_ESCAPE ) )*
			loop1:
			while (true) {
				int alt1=2;
				int LA1_0 = input.LA(1);
				if ( ((LA1_0 >= '\u0000' && LA1_0 <= '\u0007')||LA1_0=='\t'||(LA1_0 >= '\u000B' && LA1_0 <= '\uFFFF')) ) {
					alt1=1;
				}

				switch (alt1) {
				case 1 :
					// BaseLexer.g:
					{
					if ( (input.LA(1) >= '\u0000' && input.LA(1) <= '\u0007')||input.LA(1)=='\t'||(input.LA(1) >= '\u000B' && input.LA(1) <= '\uFFFF') ) {
						input.consume();
						state.failed=false;
					}
					else {
						if (state.backtracking>0) {state.failed=true; return;}
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					}
					break;

				default :
					break loop1;
				}
			}

			mPP_ESCAPE(); if (state.failed) return;

			if ( state.backtracking==0 ) { setText(getText().substring(1, getText().length()-1)); preprocess(getText()); _channel = PREPROC; }
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "PP_POSITION"

	// $ANTLR start "RES_WITH"
	public final void mRES_WITH() throws RecognitionException {
		try {
			int _type = RES_WITH;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:154:11: ( 'with' )
			// BaseLexer.g:154:13: 'with'
			{
			match("with"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "RES_WITH"

	// $ANTLR start "KEY_ALIGNMENT"
	public final void mKEY_ALIGNMENT() throws RecognitionException {
		try {
			int _type = KEY_ALIGNMENT;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:156:15: ( 'alignment' )
			// BaseLexer.g:156:17: 'alignment'
			{
			match("alignment"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_ALIGNMENT"

	// $ANTLR start "KEY_ATTACH"
	public final void mKEY_ATTACH() throws RecognitionException {
		try {
			int _type = KEY_ATTACH;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:157:13: ( 'attach' )
			// BaseLexer.g:157:15: 'attach'
			{
			match("attach"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_ATTACH"

	// $ANTLR start "KEY_BIG"
	public final void mKEY_BIG() throws RecognitionException {
		try {
			int _type = KEY_BIG;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:158:11: ( 'big' )
			// BaseLexer.g:158:13: 'big'
			{
			match("big"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_BIG"

	// $ANTLR start "KEY_BITRANGE"
	public final void mKEY_BITRANGE() throws RecognitionException {
		try {
			int _type = KEY_BITRANGE;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:159:14: ( 'bitrange' )
			// BaseLexer.g:159:16: 'bitrange'
			{
			match("bitrange"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_BITRANGE"

	// $ANTLR start "KEY_BUILD"
	public final void mKEY_BUILD() throws RecognitionException {
		try {
			int _type = KEY_BUILD;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:160:12: ( 'build' )
			// BaseLexer.g:160:14: 'build'
			{
			match("build"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_BUILD"

	// $ANTLR start "KEY_CALL"
	public final void mKEY_CALL() throws RecognitionException {
		try {
			int _type = KEY_CALL;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:161:11: ( 'call' )
			// BaseLexer.g:161:13: 'call'
			{
			match("call"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_CALL"

	// $ANTLR start "KEY_CONTEXT"
	public final void mKEY_CONTEXT() throws RecognitionException {
		try {
			int _type = KEY_CONTEXT;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:162:14: ( 'context' )
			// BaseLexer.g:162:16: 'context'
			{
			match("context"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_CONTEXT"

	// $ANTLR start "KEY_CROSSBUILD"
	public final void mKEY_CROSSBUILD() throws RecognitionException {
		try {
			int _type = KEY_CROSSBUILD;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:163:16: ( 'crossbuild' )
			// BaseLexer.g:163:18: 'crossbuild'
			{
			match("crossbuild"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_CROSSBUILD"

	// $ANTLR start "KEY_DEC"
	public final void mKEY_DEC() throws RecognitionException {
		try {
			int _type = KEY_DEC;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:164:11: ( 'dec' )
			// BaseLexer.g:164:13: 'dec'
			{
			match("dec"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_DEC"

	// $ANTLR start "KEY_DEFAULT"
	public final void mKEY_DEFAULT() throws RecognitionException {
		try {
			int _type = KEY_DEFAULT;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:165:14: ( 'default' )
			// BaseLexer.g:165:16: 'default'
			{
			match("default"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_DEFAULT"

	// $ANTLR start "KEY_DEFINE"
	public final void mKEY_DEFINE() throws RecognitionException {
		try {
			int _type = KEY_DEFINE;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:166:13: ( 'define' )
			// BaseLexer.g:166:15: 'define'
			{
			match("define"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_DEFINE"

	// $ANTLR start "KEY_ENDIAN"
	public final void mKEY_ENDIAN() throws RecognitionException {
		try {
			int _type = KEY_ENDIAN;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:167:13: ( 'endian' )
			// BaseLexer.g:167:15: 'endian'
			{
			match("endian"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_ENDIAN"

	// $ANTLR start "KEY_EXPORT"
	public final void mKEY_EXPORT() throws RecognitionException {
		try {
			int _type = KEY_EXPORT;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:168:13: ( 'export' )
			// BaseLexer.g:168:15: 'export'
			{
			match("export"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_EXPORT"

	// $ANTLR start "KEY_GOTO"
	public final void mKEY_GOTO() throws RecognitionException {
		try {
			int _type = KEY_GOTO;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:169:11: ( 'goto' )
			// BaseLexer.g:169:13: 'goto'
			{
			match("goto"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_GOTO"

	// $ANTLR start "KEY_HEX"
	public final void mKEY_HEX() throws RecognitionException {
		try {
			int _type = KEY_HEX;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:170:11: ( 'hex' )
			// BaseLexer.g:170:13: 'hex'
			{
			match("hex"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_HEX"

	// $ANTLR start "KEY_LITTLE"
	public final void mKEY_LITTLE() throws RecognitionException {
		try {
			int _type = KEY_LITTLE;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:171:13: ( 'little' )
			// BaseLexer.g:171:15: 'little'
			{
			match("little"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_LITTLE"

	// $ANTLR start "KEY_LOCAL"
	public final void mKEY_LOCAL() throws RecognitionException {
		try {
			int _type = KEY_LOCAL;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:172:12: ( 'local' )
			// BaseLexer.g:172:14: 'local'
			{
			match("local"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_LOCAL"

	// $ANTLR start "KEY_MACRO"
	public final void mKEY_MACRO() throws RecognitionException {
		try {
			int _type = KEY_MACRO;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:173:12: ( 'macro' )
			// BaseLexer.g:173:14: 'macro'
			{
			match("macro"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_MACRO"

	// $ANTLR start "KEY_NAMES"
	public final void mKEY_NAMES() throws RecognitionException {
		try {
			int _type = KEY_NAMES;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:174:12: ( 'names' )
			// BaseLexer.g:174:14: 'names'
			{
			match("names"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_NAMES"

	// $ANTLR start "KEY_NOFLOW"
	public final void mKEY_NOFLOW() throws RecognitionException {
		try {
			int _type = KEY_NOFLOW;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:175:13: ( 'noflow' )
			// BaseLexer.g:175:15: 'noflow'
			{
			match("noflow"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_NOFLOW"

	// $ANTLR start "KEY_OFFSET"
	public final void mKEY_OFFSET() throws RecognitionException {
		try {
			int _type = KEY_OFFSET;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:176:13: ( 'offset' )
			// BaseLexer.g:176:15: 'offset'
			{
			match("offset"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_OFFSET"

	// $ANTLR start "KEY_PCODEOP"
	public final void mKEY_PCODEOP() throws RecognitionException {
		try {
			int _type = KEY_PCODEOP;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:177:14: ( 'pcodeop' )
			// BaseLexer.g:177:16: 'pcodeop'
			{
			match("pcodeop"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_PCODEOP"

	// $ANTLR start "KEY_RETURN"
	public final void mKEY_RETURN() throws RecognitionException {
		try {
			int _type = KEY_RETURN;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:178:13: ( 'return' )
			// BaseLexer.g:178:15: 'return'
			{
			match("return"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_RETURN"

	// $ANTLR start "KEY_SIGNED"
	public final void mKEY_SIGNED() throws RecognitionException {
		try {
			int _type = KEY_SIGNED;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:179:13: ( 'signed' )
			// BaseLexer.g:179:15: 'signed'
			{
			match("signed"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_SIGNED"

	// $ANTLR start "KEY_SIZE"
	public final void mKEY_SIZE() throws RecognitionException {
		try {
			int _type = KEY_SIZE;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:180:11: ( 'size' )
			// BaseLexer.g:180:13: 'size'
			{
			match("size"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_SIZE"

	// $ANTLR start "KEY_SPACE"
	public final void mKEY_SPACE() throws RecognitionException {
		try {
			int _type = KEY_SPACE;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:181:12: ( 'space' )
			// BaseLexer.g:181:14: 'space'
			{
			match("space"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_SPACE"

	// $ANTLR start "KEY_TOKEN"
	public final void mKEY_TOKEN() throws RecognitionException {
		try {
			int _type = KEY_TOKEN;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:182:12: ( 'token' )
			// BaseLexer.g:182:14: 'token'
			{
			match("token"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_TOKEN"

	// $ANTLR start "KEY_TYPE"
	public final void mKEY_TYPE() throws RecognitionException {
		try {
			int _type = KEY_TYPE;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:183:11: ( 'type' )
			// BaseLexer.g:183:13: 'type'
			{
			match("type"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_TYPE"

	// $ANTLR start "KEY_UNIMPL"
	public final void mKEY_UNIMPL() throws RecognitionException {
		try {
			int _type = KEY_UNIMPL;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:184:13: ( 'unimpl' )
			// BaseLexer.g:184:15: 'unimpl'
			{
			match("unimpl"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_UNIMPL"

	// $ANTLR start "KEY_VALUES"
	public final void mKEY_VALUES() throws RecognitionException {
		try {
			int _type = KEY_VALUES;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:185:13: ( 'values' )
			// BaseLexer.g:185:15: 'values'
			{
			match("values"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_VALUES"

	// $ANTLR start "KEY_VARIABLES"
	public final void mKEY_VARIABLES() throws RecognitionException {
		try {
			int _type = KEY_VARIABLES;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:186:15: ( 'variables' )
			// BaseLexer.g:186:17: 'variables'
			{
			match("variables"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_VARIABLES"

	// $ANTLR start "KEY_WORDSIZE"
	public final void mKEY_WORDSIZE() throws RecognitionException {
		try {
			int _type = KEY_WORDSIZE;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:187:14: ( 'wordsize' )
			// BaseLexer.g:187:16: 'wordsize'
			{
			match("wordsize"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "KEY_WORDSIZE"

	// $ANTLR start "LBRACE"
	public final void mLBRACE() throws RecognitionException {
		try {
			int _type = LBRACE;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:191:10: ( '{' )
			// BaseLexer.g:191:12: '{'
			{
			match('{'); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "LBRACE"

	// $ANTLR start "RBRACE"
	public final void mRBRACE() throws RecognitionException {
		try {
			int _type = RBRACE;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:192:10: ( '}' )
			// BaseLexer.g:192:12: '}'
			{
			match('}'); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "RBRACE"

	// $ANTLR start "LBRACKET"
	public final void mLBRACKET() throws RecognitionException {
		try {
			int _type = LBRACKET;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:193:11: ( '[' )
			// BaseLexer.g:193:13: '['
			{
			match('['); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "LBRACKET"

	// $ANTLR start "RBRACKET"
	public final void mRBRACKET() throws RecognitionException {
		try {
			int _type = RBRACKET;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:194:11: ( ']' )
			// BaseLexer.g:194:13: ']'
			{
			match(']'); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "RBRACKET"

	// $ANTLR start "LPAREN"
	public final void mLPAREN() throws RecognitionException {
		try {
			int _type = LPAREN;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:195:10: ( '(' )
			// BaseLexer.g:195:12: '('
			{
			match('('); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "LPAREN"

	// $ANTLR start "RPAREN"
	public final void mRPAREN() throws RecognitionException {
		try {
			int _type = RPAREN;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:196:10: ( ')' )
			// BaseLexer.g:196:12: ')'
			{
			match(')'); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "RPAREN"

	// $ANTLR start "ELLIPSIS"
	public final void mELLIPSIS() throws RecognitionException {
		try {
			int _type = ELLIPSIS;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:199:11: ( '...' )
			// BaseLexer.g:199:13: '...'
			{
			match("..."); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "ELLIPSIS"

	// $ANTLR start "UNDERSCORE"
	public final void mUNDERSCORE() throws RecognitionException {
		try {
			int _type = UNDERSCORE;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:200:13: ( '_' )
			// BaseLexer.g:200:15: '_'
			{
			match('_'); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "UNDERSCORE"

	// $ANTLR start "COLON"
	public final void mCOLON() throws RecognitionException {
		try {
			int _type = COLON;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:201:9: ( ':' )
			// BaseLexer.g:201:11: ':'
			{
			match(':'); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "COLON"

	// $ANTLR start "COMMA"
	public final void mCOMMA() throws RecognitionException {
		try {
			int _type = COMMA;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:202:9: ( ',' )
			// BaseLexer.g:202:11: ','
			{
			match(','); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "COMMA"

	// $ANTLR start "EXCLAIM"
	public final void mEXCLAIM() throws RecognitionException {
		try {
			int _type = EXCLAIM;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:203:11: ( '!' )
			// BaseLexer.g:203:13: '!'
			{
			match('!'); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "EXCLAIM"

	// $ANTLR start "TILDE"
	public final void mTILDE() throws RecognitionException {
		try {
			int _type = TILDE;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:204:9: ( '~' )
			// BaseLexer.g:204:11: '~'
			{
			match('~'); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "TILDE"

	// $ANTLR start "SEMI"
	public final void mSEMI() throws RecognitionException {
		try {
			int _type = SEMI;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:205:8: ( ';' )
			// BaseLexer.g:205:10: ';'
			{
			match(';'); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "SEMI"

	// $ANTLR start "ASSIGN"
	public final void mASSIGN() throws RecognitionException {
		try {
			int _type = ASSIGN;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:211:10: ( '=' )
			// BaseLexer.g:211:12: '='
			{
			match('='); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "ASSIGN"

	// $ANTLR start "EQUAL"
	public final void mEQUAL() throws RecognitionException {
		try {
			int _type = EQUAL;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:214:9: ( '==' )
			// BaseLexer.g:214:11: '=='
			{
			match("=="); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "EQUAL"

	// $ANTLR start "NOTEQUAL"
	public final void mNOTEQUAL() throws RecognitionException {
		try {
			int _type = NOTEQUAL;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:215:11: ( '!=' )
			// BaseLexer.g:215:13: '!='
			{
			match("!="); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "NOTEQUAL"

	// $ANTLR start "LESS"
	public final void mLESS() throws RecognitionException {
		try {
			int _type = LESS;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:216:8: ( '<' )
			// BaseLexer.g:216:10: '<'
			{
			match('<'); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "LESS"

	// $ANTLR start "GREAT"
	public final void mGREAT() throws RecognitionException {
		try {
			int _type = GREAT;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:217:9: ( '>' )
			// BaseLexer.g:217:11: '>'
			{
			match('>'); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "GREAT"

	// $ANTLR start "LESSEQUAL"
	public final void mLESSEQUAL() throws RecognitionException {
		try {
			int _type = LESSEQUAL;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:218:12: ( '<=' )
			// BaseLexer.g:218:14: '<='
			{
			match("<="); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "LESSEQUAL"

	// $ANTLR start "GREATEQUAL"
	public final void mGREATEQUAL() throws RecognitionException {
		try {
			int _type = GREATEQUAL;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:219:13: ( '>=' )
			// BaseLexer.g:219:15: '>='
			{
			match(">="); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "GREATEQUAL"

	// $ANTLR start "BOOL_OR"
	public final void mBOOL_OR() throws RecognitionException {
		try {
			int _type = BOOL_OR;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:222:11: ( '||' )
			// BaseLexer.g:222:13: '||'
			{
			match("||"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "BOOL_OR"

	// $ANTLR start "BOOL_XOR"
	public final void mBOOL_XOR() throws RecognitionException {
		try {
			int _type = BOOL_XOR;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:223:11: ( '^^' )
			// BaseLexer.g:223:13: '^^'
			{
			match("^^"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "BOOL_XOR"

	// $ANTLR start "BOOL_AND"
	public final void mBOOL_AND() throws RecognitionException {
		try {
			int _type = BOOL_AND;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:224:11: ( '&&' )
			// BaseLexer.g:224:13: '&&'
			{
			match("&&"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "BOOL_AND"

	// $ANTLR start "PIPE"
	public final void mPIPE() throws RecognitionException {
		try {
			int _type = PIPE;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:225:8: ( '|' )
			// BaseLexer.g:225:10: '|'
			{
			match('|'); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "PIPE"

	// $ANTLR start "CARET"
	public final void mCARET() throws RecognitionException {
		try {
			int _type = CARET;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:226:9: ( '^' )
			// BaseLexer.g:226:11: '^'
			{
			match('^'); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "CARET"

	// $ANTLR start "AMPERSAND"
	public final void mAMPERSAND() throws RecognitionException {
		try {
			int _type = AMPERSAND;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:227:12: ( '&' )
			// BaseLexer.g:227:14: '&'
			{
			match('&'); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "AMPERSAND"

	// $ANTLR start "LEFT"
	public final void mLEFT() throws RecognitionException {
		try {
			int _type = LEFT;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:230:8: ( '<<' )
			// BaseLexer.g:230:10: '<<'
			{
			match("<<"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "LEFT"

	// $ANTLR start "RIGHT"
	public final void mRIGHT() throws RecognitionException {
		try {
			int _type = RIGHT;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:231:9: ( '>>' )
			// BaseLexer.g:231:11: '>>'
			{
			match(">>"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "RIGHT"

	// $ANTLR start "PLUS"
	public final void mPLUS() throws RecognitionException {
		try {
			int _type = PLUS;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:234:8: ( '+' )
			// BaseLexer.g:234:10: '+'
			{
			match('+'); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "PLUS"

	// $ANTLR start "MINUS"
	public final void mMINUS() throws RecognitionException {
		try {
			int _type = MINUS;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:235:9: ( '-' )
			// BaseLexer.g:235:11: '-'
			{
			match('-'); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "MINUS"

	// $ANTLR start "ASTERISK"
	public final void mASTERISK() throws RecognitionException {
		try {
			int _type = ASTERISK;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:236:11: ( '*' )
			// BaseLexer.g:236:13: '*'
			{
			match('*'); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "ASTERISK"

	// $ANTLR start "SLASH"
	public final void mSLASH() throws RecognitionException {
		try {
			int _type = SLASH;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:237:9: ( '/' )
			// BaseLexer.g:237:11: '/'
			{
			match('/'); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "SLASH"

	// $ANTLR start "PERCENT"
	public final void mPERCENT() throws RecognitionException {
		try {
			int _type = PERCENT;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:238:11: ( '%' )
			// BaseLexer.g:238:13: '%'
			{
			match('%'); if (state.failed) return;
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "PERCENT"

	// $ANTLR start "SPEC_OR"
	public final void mSPEC_OR() throws RecognitionException {
		try {
			int _type = SPEC_OR;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:241:11: ( '$or' )
			// BaseLexer.g:241:13: '$or'
			{
			match("$or"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "SPEC_OR"

	// $ANTLR start "SPEC_AND"
	public final void mSPEC_AND() throws RecognitionException {
		try {
			int _type = SPEC_AND;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:242:11: ( '$and' )
			// BaseLexer.g:242:13: '$and'
			{
			match("$and"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "SPEC_AND"

	// $ANTLR start "SPEC_XOR"
	public final void mSPEC_XOR() throws RecognitionException {
		try {
			int _type = SPEC_XOR;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:243:11: ( '$xor' )
			// BaseLexer.g:243:13: '$xor'
			{
			match("$xor"); if (state.failed) return;

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "SPEC_XOR"

	// $ANTLR start "IDENTIFIER"
	public final void mIDENTIFIER() throws RecognitionException {
		try {
			int _type = IDENTIFIER;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:249:2: ( ALPHAUP ( ALPHAUP | DIGIT )* )
			// BaseLexer.g:249:4: ALPHAUP ( ALPHAUP | DIGIT )*
			{
			mALPHAUP(); if (state.failed) return;

			// BaseLexer.g:249:12: ( ALPHAUP | DIGIT )*
			loop2:
			while (true) {
				int alt2=2;
				int LA2_0 = input.LA(1);
				if ( (LA2_0=='.'||(LA2_0 >= '0' && LA2_0 <= '9')||(LA2_0 >= 'A' && LA2_0 <= 'Z')||LA2_0=='_'||(LA2_0 >= 'a' && LA2_0 <= 'z')) ) {
					alt2=1;
				}

				switch (alt2) {
				case 1 :
					// BaseLexer.g:
					{
					if ( input.LA(1)=='.'||(input.LA(1) >= '0' && input.LA(1) <= '9')||(input.LA(1) >= 'A' && input.LA(1) <= 'Z')||input.LA(1)=='_'||(input.LA(1) >= 'a' && input.LA(1) <= 'z') ) {
						input.consume();
						state.failed=false;
					}
					else {
						if (state.backtracking>0) {state.failed=true; return;}
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

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "IDENTIFIER"

	// $ANTLR start "ALPHA"
	public final void mALPHA() throws RecognitionException {
		try {
			// BaseLexer.g:254:2: ( 'A' .. 'Z' | 'a' .. 'z' )
			// BaseLexer.g:
			{
			if ( (input.LA(1) >= 'A' && input.LA(1) <= 'Z')||(input.LA(1) >= 'a' && input.LA(1) <= 'z') ) {
				input.consume();
				state.failed=false;
			}
			else {
				if (state.backtracking>0) {state.failed=true; return;}
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

	// $ANTLR start "ALPHAUP"
	public final void mALPHAUP() throws RecognitionException {
		try {
			// BaseLexer.g:260:2: ( ALPHA | '_' | '.' )
			// BaseLexer.g:
			{
			if ( input.LA(1)=='.'||(input.LA(1) >= 'A' && input.LA(1) <= 'Z')||input.LA(1)=='_'||(input.LA(1) >= 'a' && input.LA(1) <= 'z') ) {
				input.consume();
				state.failed=false;
			}
			else {
				if (state.backtracking>0) {state.failed=true; return;}
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
	// $ANTLR end "ALPHAUP"

	// $ANTLR start "DIGIT"
	public final void mDIGIT() throws RecognitionException {
		try {
			// BaseLexer.g:267:2: ( '0' .. '9' )
			// BaseLexer.g:
			{
			if ( (input.LA(1) >= '0' && input.LA(1) <= '9') ) {
				input.consume();
				state.failed=false;
			}
			else {
				if (state.backtracking>0) {state.failed=true; return;}
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

	// $ANTLR start "QSTRING"
	public final void mQSTRING() throws RecognitionException {
		try {
			int _type = QSTRING;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:271:5: ( '\"' ( ESCAPE |~ ( '\\\\' | '\"' ) )* '\"' )
			// BaseLexer.g:271:9: '\"' ( ESCAPE |~ ( '\\\\' | '\"' ) )* '\"'
			{
			match('\"'); if (state.failed) return;
			// BaseLexer.g:271:13: ( ESCAPE |~ ( '\\\\' | '\"' ) )*
			loop3:
			while (true) {
				int alt3=3;
				int LA3_0 = input.LA(1);
				if ( (LA3_0=='\\') ) {
					alt3=1;
				}
				else if ( ((LA3_0 >= '\u0000' && LA3_0 <= '!')||(LA3_0 >= '#' && LA3_0 <= '[')||(LA3_0 >= ']' && LA3_0 <= '\uFFFF')) ) {
					alt3=2;
				}

				switch (alt3) {
				case 1 :
					// BaseLexer.g:271:14: ESCAPE
					{
					mESCAPE(); if (state.failed) return;

					}
					break;
				case 2 :
					// BaseLexer.g:271:23: ~ ( '\\\\' | '\"' )
					{
					if ( (input.LA(1) >= '\u0000' && input.LA(1) <= '!')||(input.LA(1) >= '#' && input.LA(1) <= '[')||(input.LA(1) >= ']' && input.LA(1) <= '\uFFFF') ) {
						input.consume();
						state.failed=false;
					}
					else {
						if (state.backtracking>0) {state.failed=true; return;}
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					}
					break;

				default :
					break loop3;
				}
			}

			match('\"'); if (state.failed) return;
			if ( state.backtracking==0 ) { setText(getText().substring(1, getText().length()-1)); }
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
			// BaseLexer.g:276:5: ( '\\\\' ( 'b' | 't' | 'n' | 'f' | 'r' | '\\\"' | '\\'' | '\\\\' ) | UNICODE_ESCAPE | OCTAL_ESCAPE )
			int alt4=3;
			int LA4_0 = input.LA(1);
			if ( (LA4_0=='\\') ) {
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
					alt4=1;
					}
					break;
				case 'u':
					{
					alt4=2;
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
					alt4=3;
					}
					break;
				default:
					if (state.backtracking>0) {state.failed=true; return;}
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
				if (state.backtracking>0) {state.failed=true; return;}
				NoViableAltException nvae =
					new NoViableAltException("", 4, 0, input);
				throw nvae;
			}

			switch (alt4) {
				case 1 :
					// BaseLexer.g:276:9: '\\\\' ( 'b' | 't' | 'n' | 'f' | 'r' | '\\\"' | '\\'' | '\\\\' )
					{
					match('\\'); if (state.failed) return;
					if ( input.LA(1)=='\"'||input.LA(1)=='\''||input.LA(1)=='\\'||input.LA(1)=='b'||input.LA(1)=='f'||input.LA(1)=='n'||input.LA(1)=='r'||input.LA(1)=='t' ) {
						input.consume();
						state.failed=false;
					}
					else {
						if (state.backtracking>0) {state.failed=true; return;}
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					}
					break;
				case 2 :
					// BaseLexer.g:277:9: UNICODE_ESCAPE
					{
					mUNICODE_ESCAPE(); if (state.failed) return;

					}
					break;
				case 3 :
					// BaseLexer.g:278:9: OCTAL_ESCAPE
					{
					mOCTAL_ESCAPE(); if (state.failed) return;

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
			// BaseLexer.g:283:5: ( '\\\\' ( '0' .. '3' ) ( '0' .. '7' ) ( '0' .. '7' ) | '\\\\' ( '0' .. '7' ) ( '0' .. '7' ) | '\\\\' ( '0' .. '7' ) )
			int alt5=3;
			int LA5_0 = input.LA(1);
			if ( (LA5_0=='\\') ) {
				int LA5_1 = input.LA(2);
				if ( ((LA5_1 >= '0' && LA5_1 <= '3')) ) {
					int LA5_2 = input.LA(3);
					if ( ((LA5_2 >= '0' && LA5_2 <= '7')) ) {
						int LA5_4 = input.LA(4);
						if ( ((LA5_4 >= '0' && LA5_4 <= '7')) ) {
							alt5=1;
						}

						else {
							alt5=2;
						}

					}

					else {
						alt5=3;
					}

				}
				else if ( ((LA5_1 >= '4' && LA5_1 <= '7')) ) {
					int LA5_3 = input.LA(3);
					if ( ((LA5_3 >= '0' && LA5_3 <= '7')) ) {
						alt5=2;
					}

					else {
						alt5=3;
					}

				}

				else {
					if (state.backtracking>0) {state.failed=true; return;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 5, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

			}

			else {
				if (state.backtracking>0) {state.failed=true; return;}
				NoViableAltException nvae =
					new NoViableAltException("", 5, 0, input);
				throw nvae;
			}

			switch (alt5) {
				case 1 :
					// BaseLexer.g:283:9: '\\\\' ( '0' .. '3' ) ( '0' .. '7' ) ( '0' .. '7' )
					{
					match('\\'); if (state.failed) return;
					if ( (input.LA(1) >= '0' && input.LA(1) <= '3') ) {
						input.consume();
						state.failed=false;
					}
					else {
						if (state.backtracking>0) {state.failed=true; return;}
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					if ( (input.LA(1) >= '0' && input.LA(1) <= '7') ) {
						input.consume();
						state.failed=false;
					}
					else {
						if (state.backtracking>0) {state.failed=true; return;}
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					if ( (input.LA(1) >= '0' && input.LA(1) <= '7') ) {
						input.consume();
						state.failed=false;
					}
					else {
						if (state.backtracking>0) {state.failed=true; return;}
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					}
					break;
				case 2 :
					// BaseLexer.g:284:9: '\\\\' ( '0' .. '7' ) ( '0' .. '7' )
					{
					match('\\'); if (state.failed) return;
					if ( (input.LA(1) >= '0' && input.LA(1) <= '7') ) {
						input.consume();
						state.failed=false;
					}
					else {
						if (state.backtracking>0) {state.failed=true; return;}
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					if ( (input.LA(1) >= '0' && input.LA(1) <= '7') ) {
						input.consume();
						state.failed=false;
					}
					else {
						if (state.backtracking>0) {state.failed=true; return;}
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					}
					break;
				case 3 :
					// BaseLexer.g:285:9: '\\\\' ( '0' .. '7' )
					{
					match('\\'); if (state.failed) return;
					if ( (input.LA(1) >= '0' && input.LA(1) <= '7') ) {
						input.consume();
						state.failed=false;
					}
					else {
						if (state.backtracking>0) {state.failed=true; return;}
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
			// BaseLexer.g:290:5: ( '\\\\' 'u' HEXDIGIT HEXDIGIT HEXDIGIT HEXDIGIT )
			// BaseLexer.g:290:9: '\\\\' 'u' HEXDIGIT HEXDIGIT HEXDIGIT HEXDIGIT
			{
			match('\\'); if (state.failed) return;
			match('u'); if (state.failed) return;
			mHEXDIGIT(); if (state.failed) return;

			mHEXDIGIT(); if (state.failed) return;

			mHEXDIGIT(); if (state.failed) return;

			mHEXDIGIT(); if (state.failed) return;

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
			// BaseLexer.g:295:5: ( DIGIT | 'a' .. 'f' | 'A' .. 'F' )
			// BaseLexer.g:
			{
			if ( (input.LA(1) >= '0' && input.LA(1) <= '9')||(input.LA(1) >= 'A' && input.LA(1) <= 'F')||(input.LA(1) >= 'a' && input.LA(1) <= 'f') ) {
				input.consume();
				state.failed=false;
			}
			else {
				if (state.backtracking>0) {state.failed=true; return;}
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

	// $ANTLR start "DEC_INT"
	public final void mDEC_INT() throws RecognitionException {
		try {
			int _type = DEC_INT;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:301:2: ( ( DIGIT )+ )
			// BaseLexer.g:301:4: ( DIGIT )+
			{
			// BaseLexer.g:301:4: ( DIGIT )+
			int cnt6=0;
			loop6:
			while (true) {
				int alt6=2;
				int LA6_0 = input.LA(1);
				if ( ((LA6_0 >= '0' && LA6_0 <= '9')) ) {
					alt6=1;
				}

				switch (alt6) {
				case 1 :
					// BaseLexer.g:
					{
					if ( (input.LA(1) >= '0' && input.LA(1) <= '9') ) {
						input.consume();
						state.failed=false;
					}
					else {
						if (state.backtracking>0) {state.failed=true; return;}
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					}
					break;

				default :
					if ( cnt6 >= 1 ) break loop6;
					if (state.backtracking>0) {state.failed=true; return;}
					EarlyExitException eee = new EarlyExitException(6, input);
					throw eee;
				}
				cnt6++;
			}

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "DEC_INT"

	// $ANTLR start "HEX_INT"
	public final void mHEX_INT() throws RecognitionException {
		try {
			int _type = HEX_INT;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:305:2: ( '0x' ( HEXDIGIT )+ )
			// BaseLexer.g:305:4: '0x' ( HEXDIGIT )+
			{
			match("0x"); if (state.failed) return;

			// BaseLexer.g:305:9: ( HEXDIGIT )+
			int cnt7=0;
			loop7:
			while (true) {
				int alt7=2;
				int LA7_0 = input.LA(1);
				if ( ((LA7_0 >= '0' && LA7_0 <= '9')||(LA7_0 >= 'A' && LA7_0 <= 'F')||(LA7_0 >= 'a' && LA7_0 <= 'f')) ) {
					alt7=1;
				}

				switch (alt7) {
				case 1 :
					// BaseLexer.g:
					{
					if ( (input.LA(1) >= '0' && input.LA(1) <= '9')||(input.LA(1) >= 'A' && input.LA(1) <= 'F')||(input.LA(1) >= 'a' && input.LA(1) <= 'f') ) {
						input.consume();
						state.failed=false;
					}
					else {
						if (state.backtracking>0) {state.failed=true; return;}
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					}
					break;

				default :
					if ( cnt7 >= 1 ) break loop7;
					if (state.backtracking>0) {state.failed=true; return;}
					EarlyExitException eee = new EarlyExitException(7, input);
					throw eee;
				}
				cnt7++;
			}

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "HEX_INT"

	// $ANTLR start "BIN_INT"
	public final void mBIN_INT() throws RecognitionException {
		try {
			int _type = BIN_INT;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:309:2: ( '0b' ( BINDIGIT )+ )
			// BaseLexer.g:309:4: '0b' ( BINDIGIT )+
			{
			match("0b"); if (state.failed) return;

			// BaseLexer.g:309:9: ( BINDIGIT )+
			int cnt8=0;
			loop8:
			while (true) {
				int alt8=2;
				int LA8_0 = input.LA(1);
				if ( ((LA8_0 >= '0' && LA8_0 <= '1')) ) {
					alt8=1;
				}

				switch (alt8) {
				case 1 :
					// BaseLexer.g:
					{
					if ( (input.LA(1) >= '0' && input.LA(1) <= '1') ) {
						input.consume();
						state.failed=false;
					}
					else {
						if (state.backtracking>0) {state.failed=true; return;}
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					}
					break;

				default :
					if ( cnt8 >= 1 ) break loop8;
					if (state.backtracking>0) {state.failed=true; return;}
					EarlyExitException eee = new EarlyExitException(8, input);
					throw eee;
				}
				cnt8++;
			}

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "BIN_INT"

	// $ANTLR start "BINDIGIT"
	public final void mBINDIGIT() throws RecognitionException {
		try {
			// BaseLexer.g:314:2: ( '0' .. '1' )
			// BaseLexer.g:
			{
			if ( (input.LA(1) >= '0' && input.LA(1) <= '1') ) {
				input.consume();
				state.failed=false;
			}
			else {
				if (state.backtracking>0) {state.failed=true; return;}
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
	// $ANTLR end "BINDIGIT"

	// $ANTLR start "LINECOMMENT"
	public final void mLINECOMMENT() throws RecognitionException {
		try {
			int _type = LINECOMMENT;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:320:2: ( '#' (~ ( '\\n' | '\\r' ) )* EOL )
			// BaseLexer.g:320:4: '#' (~ ( '\\n' | '\\r' ) )* EOL
			{
			match('#'); if (state.failed) return;
			// BaseLexer.g:320:8: (~ ( '\\n' | '\\r' ) )*
			loop9:
			while (true) {
				int alt9=2;
				int LA9_0 = input.LA(1);
				if ( ((LA9_0 >= '\u0000' && LA9_0 <= '\t')||(LA9_0 >= '\u000B' && LA9_0 <= '\f')||(LA9_0 >= '\u000E' && LA9_0 <= '\uFFFF')) ) {
					alt9=1;
				}

				switch (alt9) {
				case 1 :
					// BaseLexer.g:
					{
					if ( (input.LA(1) >= '\u0000' && input.LA(1) <= '\t')||(input.LA(1) >= '\u000B' && input.LA(1) <= '\f')||(input.LA(1) >= '\u000E' && input.LA(1) <= '\uFFFF') ) {
						input.consume();
						state.failed=false;
					}
					else {
						if (state.backtracking>0) {state.failed=true; return;}
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					}
					break;

				default :
					break loop9;
				}
			}

			mEOL(); if (state.failed) return;

			if ( state.backtracking==0 ) { _channel = COMMENT; }
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "LINECOMMENT"

	// $ANTLR start "EOL"
	public final void mEOL() throws RecognitionException {
		try {
			// BaseLexer.g:325:2: ( ( ( '\\r' )? '\\n' )=> ( '\\r' )? '\\n' | '\\r' )
			int alt11=2;
			int LA11_0 = input.LA(1);
			if ( (LA11_0=='\r') ) {
				int LA11_1 = input.LA(2);
				if ( (LA11_1=='\n') && (synpred1_BaseLexer())) {
					alt11=1;
				}

			}
			else if ( (LA11_0=='\n') && (synpred1_BaseLexer())) {
				alt11=1;
			}

			switch (alt11) {
				case 1 :
					// BaseLexer.g:325:4: ( ( '\\r' )? '\\n' )=> ( '\\r' )? '\\n'
					{
					// BaseLexer.g:325:19: ( '\\r' )?
					int alt10=2;
					int LA10_0 = input.LA(1);
					if ( (LA10_0=='\r') ) {
						alt10=1;
					}
					switch (alt10) {
						case 1 :
							// BaseLexer.g:325:19: '\\r'
							{
							match('\r'); if (state.failed) return;
							}
							break;

					}

					match('\n'); if (state.failed) return;
					}
					break;
				case 2 :
					// BaseLexer.g:326:4: '\\r'
					{
					match('\r'); if (state.failed) return;
					}
					break;

			}
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "EOL"

	// $ANTLR start "CPPCOMMENT"
	public final void mCPPCOMMENT() throws RecognitionException {
		try {
			int _type = CPPCOMMENT;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:330:2: ( '//' )
			// BaseLexer.g:330:4: '//'
			{
			match("//"); if (state.failed) return;

			if ( state.backtracking==0 ) {
					SleighToken st = new SleighToken(_type, getText());
					UnwantedTokenException ute = new UnwantedTokenException(0, input);
					ute.token = st;
					reportError(ute);
				}
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "CPPCOMMENT"

	// $ANTLR start "WS"
	public final void mWS() throws RecognitionException {
		try {
			int _type = WS;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:340:2: ( ( ' ' | '\\t' | '\\r' | '\\n' )+ )
			// BaseLexer.g:340:4: ( ' ' | '\\t' | '\\r' | '\\n' )+
			{
			// BaseLexer.g:340:4: ( ' ' | '\\t' | '\\r' | '\\n' )+
			int cnt12=0;
			loop12:
			while (true) {
				int alt12=2;
				int LA12_0 = input.LA(1);
				if ( ((LA12_0 >= '\t' && LA12_0 <= '\n')||LA12_0=='\r'||LA12_0==' ') ) {
					alt12=1;
				}

				switch (alt12) {
				case 1 :
					// BaseLexer.g:
					{
					if ( (input.LA(1) >= '\t' && input.LA(1) <= '\n')||input.LA(1)=='\r'||input.LA(1)==' ' ) {
						input.consume();
						state.failed=false;
					}
					else {
						if (state.backtracking>0) {state.failed=true; return;}
						MismatchedSetException mse = new MismatchedSetException(null,input);
						recover(mse);
						throw mse;
					}
					}
					break;

				default :
					if ( cnt12 >= 1 ) break loop12;
					if (state.backtracking>0) {state.failed=true; return;}
					EarlyExitException eee = new EarlyExitException(12, input);
					throw eee;
				}
				cnt12++;
			}

			if ( state.backtracking==0 ) { _channel = HIDDEN; }
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "WS"

	// $ANTLR start "UNKNOWN"
	public final void mUNKNOWN() throws RecognitionException {
		try {
			int _type = UNKNOWN;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// BaseLexer.g:344:2: ( . )
			// BaseLexer.g:344:4: .
			{
			matchAny(); if (state.failed) return;
			if ( state.backtracking==0 ) {
					SleighToken st = new SleighToken(_type, getText());
					UnwantedTokenException ute = new UnwantedTokenException(0, input);
					ute.token = st;
					reportError(ute);
				}
			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "UNKNOWN"

	@Override
	public void mTokens() throws RecognitionException {
		// BaseLexer.g:1:8: ( PP_POSITION | RES_WITH | KEY_ALIGNMENT | KEY_ATTACH | KEY_BIG | KEY_BITRANGE | KEY_BUILD | KEY_CALL | KEY_CONTEXT | KEY_CROSSBUILD | KEY_DEC | KEY_DEFAULT | KEY_DEFINE | KEY_ENDIAN | KEY_EXPORT | KEY_GOTO | KEY_HEX | KEY_LITTLE | KEY_LOCAL | KEY_MACRO | KEY_NAMES | KEY_NOFLOW | KEY_OFFSET | KEY_PCODEOP | KEY_RETURN | KEY_SIGNED | KEY_SIZE | KEY_SPACE | KEY_TOKEN | KEY_TYPE | KEY_UNIMPL | KEY_VALUES | KEY_VARIABLES | KEY_WORDSIZE | LBRACE | RBRACE | LBRACKET | RBRACKET | LPAREN | RPAREN | ELLIPSIS | UNDERSCORE | COLON | COMMA | EXCLAIM | TILDE | SEMI | ASSIGN | EQUAL | NOTEQUAL | LESS | GREAT | LESSEQUAL | GREATEQUAL | BOOL_OR | BOOL_XOR | BOOL_AND | PIPE | CARET | AMPERSAND | LEFT | RIGHT | PLUS | MINUS | ASTERISK | SLASH | PERCENT | SPEC_OR | SPEC_AND | SPEC_XOR | IDENTIFIER | QSTRING | DEC_INT | HEX_INT | BIN_INT | LINECOMMENT | CPPCOMMENT | WS | UNKNOWN )
		int alt13=79;
		alt13 = dfa13.predict(input);
		switch (alt13) {
			case 1 :
				// BaseLexer.g:1:10: PP_POSITION
				{
				mPP_POSITION(); if (state.failed) return;

				}
				break;
			case 2 :
				// BaseLexer.g:1:22: RES_WITH
				{
				mRES_WITH(); if (state.failed) return;

				}
				break;
			case 3 :
				// BaseLexer.g:1:31: KEY_ALIGNMENT
				{
				mKEY_ALIGNMENT(); if (state.failed) return;

				}
				break;
			case 4 :
				// BaseLexer.g:1:45: KEY_ATTACH
				{
				mKEY_ATTACH(); if (state.failed) return;

				}
				break;
			case 5 :
				// BaseLexer.g:1:56: KEY_BIG
				{
				mKEY_BIG(); if (state.failed) return;

				}
				break;
			case 6 :
				// BaseLexer.g:1:64: KEY_BITRANGE
				{
				mKEY_BITRANGE(); if (state.failed) return;

				}
				break;
			case 7 :
				// BaseLexer.g:1:77: KEY_BUILD
				{
				mKEY_BUILD(); if (state.failed) return;

				}
				break;
			case 8 :
				// BaseLexer.g:1:87: KEY_CALL
				{
				mKEY_CALL(); if (state.failed) return;

				}
				break;
			case 9 :
				// BaseLexer.g:1:96: KEY_CONTEXT
				{
				mKEY_CONTEXT(); if (state.failed) return;

				}
				break;
			case 10 :
				// BaseLexer.g:1:108: KEY_CROSSBUILD
				{
				mKEY_CROSSBUILD(); if (state.failed) return;

				}
				break;
			case 11 :
				// BaseLexer.g:1:123: KEY_DEC
				{
				mKEY_DEC(); if (state.failed) return;

				}
				break;
			case 12 :
				// BaseLexer.g:1:131: KEY_DEFAULT
				{
				mKEY_DEFAULT(); if (state.failed) return;

				}
				break;
			case 13 :
				// BaseLexer.g:1:143: KEY_DEFINE
				{
				mKEY_DEFINE(); if (state.failed) return;

				}
				break;
			case 14 :
				// BaseLexer.g:1:154: KEY_ENDIAN
				{
				mKEY_ENDIAN(); if (state.failed) return;

				}
				break;
			case 15 :
				// BaseLexer.g:1:165: KEY_EXPORT
				{
				mKEY_EXPORT(); if (state.failed) return;

				}
				break;
			case 16 :
				// BaseLexer.g:1:176: KEY_GOTO
				{
				mKEY_GOTO(); if (state.failed) return;

				}
				break;
			case 17 :
				// BaseLexer.g:1:185: KEY_HEX
				{
				mKEY_HEX(); if (state.failed) return;

				}
				break;
			case 18 :
				// BaseLexer.g:1:193: KEY_LITTLE
				{
				mKEY_LITTLE(); if (state.failed) return;

				}
				break;
			case 19 :
				// BaseLexer.g:1:204: KEY_LOCAL
				{
				mKEY_LOCAL(); if (state.failed) return;

				}
				break;
			case 20 :
				// BaseLexer.g:1:214: KEY_MACRO
				{
				mKEY_MACRO(); if (state.failed) return;

				}
				break;
			case 21 :
				// BaseLexer.g:1:224: KEY_NAMES
				{
				mKEY_NAMES(); if (state.failed) return;

				}
				break;
			case 22 :
				// BaseLexer.g:1:234: KEY_NOFLOW
				{
				mKEY_NOFLOW(); if (state.failed) return;

				}
				break;
			case 23 :
				// BaseLexer.g:1:245: KEY_OFFSET
				{
				mKEY_OFFSET(); if (state.failed) return;

				}
				break;
			case 24 :
				// BaseLexer.g:1:256: KEY_PCODEOP
				{
				mKEY_PCODEOP(); if (state.failed) return;

				}
				break;
			case 25 :
				// BaseLexer.g:1:268: KEY_RETURN
				{
				mKEY_RETURN(); if (state.failed) return;

				}
				break;
			case 26 :
				// BaseLexer.g:1:279: KEY_SIGNED
				{
				mKEY_SIGNED(); if (state.failed) return;

				}
				break;
			case 27 :
				// BaseLexer.g:1:290: KEY_SIZE
				{
				mKEY_SIZE(); if (state.failed) return;

				}
				break;
			case 28 :
				// BaseLexer.g:1:299: KEY_SPACE
				{
				mKEY_SPACE(); if (state.failed) return;

				}
				break;
			case 29 :
				// BaseLexer.g:1:309: KEY_TOKEN
				{
				mKEY_TOKEN(); if (state.failed) return;

				}
				break;
			case 30 :
				// BaseLexer.g:1:319: KEY_TYPE
				{
				mKEY_TYPE(); if (state.failed) return;

				}
				break;
			case 31 :
				// BaseLexer.g:1:328: KEY_UNIMPL
				{
				mKEY_UNIMPL(); if (state.failed) return;

				}
				break;
			case 32 :
				// BaseLexer.g:1:339: KEY_VALUES
				{
				mKEY_VALUES(); if (state.failed) return;

				}
				break;
			case 33 :
				// BaseLexer.g:1:350: KEY_VARIABLES
				{
				mKEY_VARIABLES(); if (state.failed) return;

				}
				break;
			case 34 :
				// BaseLexer.g:1:364: KEY_WORDSIZE
				{
				mKEY_WORDSIZE(); if (state.failed) return;

				}
				break;
			case 35 :
				// BaseLexer.g:1:377: LBRACE
				{
				mLBRACE(); if (state.failed) return;

				}
				break;
			case 36 :
				// BaseLexer.g:1:384: RBRACE
				{
				mRBRACE(); if (state.failed) return;

				}
				break;
			case 37 :
				// BaseLexer.g:1:391: LBRACKET
				{
				mLBRACKET(); if (state.failed) return;

				}
				break;
			case 38 :
				// BaseLexer.g:1:400: RBRACKET
				{
				mRBRACKET(); if (state.failed) return;

				}
				break;
			case 39 :
				// BaseLexer.g:1:409: LPAREN
				{
				mLPAREN(); if (state.failed) return;

				}
				break;
			case 40 :
				// BaseLexer.g:1:416: RPAREN
				{
				mRPAREN(); if (state.failed) return;

				}
				break;
			case 41 :
				// BaseLexer.g:1:423: ELLIPSIS
				{
				mELLIPSIS(); if (state.failed) return;

				}
				break;
			case 42 :
				// BaseLexer.g:1:432: UNDERSCORE
				{
				mUNDERSCORE(); if (state.failed) return;

				}
				break;
			case 43 :
				// BaseLexer.g:1:443: COLON
				{
				mCOLON(); if (state.failed) return;

				}
				break;
			case 44 :
				// BaseLexer.g:1:449: COMMA
				{
				mCOMMA(); if (state.failed) return;

				}
				break;
			case 45 :
				// BaseLexer.g:1:455: EXCLAIM
				{
				mEXCLAIM(); if (state.failed) return;

				}
				break;
			case 46 :
				// BaseLexer.g:1:463: TILDE
				{
				mTILDE(); if (state.failed) return;

				}
				break;
			case 47 :
				// BaseLexer.g:1:469: SEMI
				{
				mSEMI(); if (state.failed) return;

				}
				break;
			case 48 :
				// BaseLexer.g:1:474: ASSIGN
				{
				mASSIGN(); if (state.failed) return;

				}
				break;
			case 49 :
				// BaseLexer.g:1:481: EQUAL
				{
				mEQUAL(); if (state.failed) return;

				}
				break;
			case 50 :
				// BaseLexer.g:1:487: NOTEQUAL
				{
				mNOTEQUAL(); if (state.failed) return;

				}
				break;
			case 51 :
				// BaseLexer.g:1:496: LESS
				{
				mLESS(); if (state.failed) return;

				}
				break;
			case 52 :
				// BaseLexer.g:1:501: GREAT
				{
				mGREAT(); if (state.failed) return;

				}
				break;
			case 53 :
				// BaseLexer.g:1:507: LESSEQUAL
				{
				mLESSEQUAL(); if (state.failed) return;

				}
				break;
			case 54 :
				// BaseLexer.g:1:517: GREATEQUAL
				{
				mGREATEQUAL(); if (state.failed) return;

				}
				break;
			case 55 :
				// BaseLexer.g:1:528: BOOL_OR
				{
				mBOOL_OR(); if (state.failed) return;

				}
				break;
			case 56 :
				// BaseLexer.g:1:536: BOOL_XOR
				{
				mBOOL_XOR(); if (state.failed) return;

				}
				break;
			case 57 :
				// BaseLexer.g:1:545: BOOL_AND
				{
				mBOOL_AND(); if (state.failed) return;

				}
				break;
			case 58 :
				// BaseLexer.g:1:554: PIPE
				{
				mPIPE(); if (state.failed) return;

				}
				break;
			case 59 :
				// BaseLexer.g:1:559: CARET
				{
				mCARET(); if (state.failed) return;

				}
				break;
			case 60 :
				// BaseLexer.g:1:565: AMPERSAND
				{
				mAMPERSAND(); if (state.failed) return;

				}
				break;
			case 61 :
				// BaseLexer.g:1:575: LEFT
				{
				mLEFT(); if (state.failed) return;

				}
				break;
			case 62 :
				// BaseLexer.g:1:580: RIGHT
				{
				mRIGHT(); if (state.failed) return;

				}
				break;
			case 63 :
				// BaseLexer.g:1:586: PLUS
				{
				mPLUS(); if (state.failed) return;

				}
				break;
			case 64 :
				// BaseLexer.g:1:591: MINUS
				{
				mMINUS(); if (state.failed) return;

				}
				break;
			case 65 :
				// BaseLexer.g:1:597: ASTERISK
				{
				mASTERISK(); if (state.failed) return;

				}
				break;
			case 66 :
				// BaseLexer.g:1:606: SLASH
				{
				mSLASH(); if (state.failed) return;

				}
				break;
			case 67 :
				// BaseLexer.g:1:612: PERCENT
				{
				mPERCENT(); if (state.failed) return;

				}
				break;
			case 68 :
				// BaseLexer.g:1:620: SPEC_OR
				{
				mSPEC_OR(); if (state.failed) return;

				}
				break;
			case 69 :
				// BaseLexer.g:1:628: SPEC_AND
				{
				mSPEC_AND(); if (state.failed) return;

				}
				break;
			case 70 :
				// BaseLexer.g:1:637: SPEC_XOR
				{
				mSPEC_XOR(); if (state.failed) return;

				}
				break;
			case 71 :
				// BaseLexer.g:1:646: IDENTIFIER
				{
				mIDENTIFIER(); if (state.failed) return;

				}
				break;
			case 72 :
				// BaseLexer.g:1:657: QSTRING
				{
				mQSTRING(); if (state.failed) return;

				}
				break;
			case 73 :
				// BaseLexer.g:1:665: DEC_INT
				{
				mDEC_INT(); if (state.failed) return;

				}
				break;
			case 74 :
				// BaseLexer.g:1:673: HEX_INT
				{
				mHEX_INT(); if (state.failed) return;

				}
				break;
			case 75 :
				// BaseLexer.g:1:681: BIN_INT
				{
				mBIN_INT(); if (state.failed) return;

				}
				break;
			case 76 :
				// BaseLexer.g:1:689: LINECOMMENT
				{
				mLINECOMMENT(); if (state.failed) return;

				}
				break;
			case 77 :
				// BaseLexer.g:1:701: CPPCOMMENT
				{
				mCPPCOMMENT(); if (state.failed) return;

				}
				break;
			case 78 :
				// BaseLexer.g:1:712: WS
				{
				mWS(); if (state.failed) return;

				}
				break;
			case 79 :
				// BaseLexer.g:1:715: UNKNOWN
				{
				mUNKNOWN(); if (state.failed) return;

				}
				break;

		}
	}

	// $ANTLR start synpred1_BaseLexer
	public final void synpred1_BaseLexer_fragment() throws RecognitionException {
		// BaseLexer.g:325:4: ( ( '\\r' )? '\\n' )
		// BaseLexer.g:325:5: ( '\\r' )? '\\n'
		{
		// BaseLexer.g:325:5: ( '\\r' )?
		int alt14=2;
		int LA14_0 = input.LA(1);
		if ( (LA14_0=='\r') ) {
			alt14=1;
		}
		switch (alt14) {
			case 1 :
				// BaseLexer.g:325:5: '\\r'
				{
				match('\r'); if (state.failed) return;
				}
				break;

		}

		match('\n'); if (state.failed) return;
		}

	}
	// $ANTLR end synpred1_BaseLexer

	public final boolean synpred1_BaseLexer() {
		state.backtracking++;
		int start = input.mark();
		try {
			synpred1_BaseLexer_fragment(); // can never throw exception
		} catch (RecognitionException re) {
			System.err.println("impossible: "+re);
		}
		boolean success = !state.failed;
		input.rewind(start);
		state.backtracking--;
		state.failed=false;
		return success;
	}


	protected DFA13 dfa13 = new DFA13(this);
	static final String DFA13_eotS =
		"\1\uffff\1\63\22\67\6\uffff\1\67\1\131\2\uffff\1\135\2\uffff\1\141\1\144"+
		"\1\147\1\151\1\153\1\155\3\uffff\1\162\1\uffff\1\63\1\uffff\1\63\1\172"+
		"\1\uffff\1\63\3\uffff\2\67\1\uffff\32\67\6\uffff\1\67\44\uffff\4\67\1"+
		"\u00a2\5\67\1\u00a8\4\67\1\u00ae\20\67\1\u00bf\1\u00c0\3\67\1\uffff\2"+
		"\67\1\u00c6\2\67\1\uffff\4\67\1\u00cd\1\uffff\11\67\1\u00d7\2\67\1\u00da"+
		"\3\67\2\uffff\4\67\1\u00e2\1\uffff\6\67\1\uffff\1\67\1\u00ea\1\u00eb\1"+
		"\u00ec\5\67\1\uffff\1\u00f2\1\u00f3\1\uffff\5\67\1\u00f9\1\67\1\uffff"+
		"\3\67\1\u00fe\1\u00ff\1\u0100\1\u0101\3\uffff\1\u0102\1\u0103\1\67\1\u0105"+
		"\1\u0106\2\uffff\1\u0107\1\u0108\3\67\1\uffff\1\67\1\u010d\1\67\1\u010f"+
		"\6\uffff\1\u0110\4\uffff\1\67\1\u0112\1\67\1\u0114\1\uffff\1\67\2\uffff"+
		"\1\67\1\uffff\1\u0117\1\uffff\1\67\1\u0119\1\uffff\1\u011a\2\uffff";
	static final String DFA13_eofS =
		"\u011b\uffff";
	static final String DFA13_minS =
		"\2\0\1\151\1\154\1\151\1\141\1\145\1\156\1\157\1\145\1\151\2\141\1\146"+
		"\1\143\1\145\1\151\1\157\1\156\1\141\6\uffff\2\56\2\uffff\1\75\2\uffff"+
		"\1\75\1\74\1\75\1\174\1\136\1\46\3\uffff\1\57\1\uffff\1\141\1\uffff\1"+
		"\0\1\142\1\uffff\1\0\3\uffff\1\164\1\162\1\uffff\1\151\1\164\1\147\1\151"+
		"\1\154\1\156\1\157\1\143\1\144\1\160\1\164\1\170\1\164\2\143\1\155\2\146"+
		"\1\157\1\164\1\147\1\141\1\153\1\160\1\151\1\154\6\uffff\1\56\44\uffff"+
		"\1\150\1\144\1\147\1\141\1\56\1\162\2\154\1\164\1\163\1\56\1\141\1\151"+
		"\2\157\1\56\1\164\1\141\1\162\1\145\1\154\1\163\1\144\1\165\1\156\1\145"+
		"\1\143\2\145\1\155\1\165\1\151\2\56\1\163\1\156\1\143\1\uffff\1\141\1"+
		"\144\1\56\1\145\1\163\1\uffff\1\165\1\156\1\141\1\162\1\56\1\uffff\2\154"+
		"\1\157\1\163\1\157\2\145\1\162\1\145\1\56\1\145\1\156\1\56\1\160\1\145"+
		"\1\141\2\uffff\1\151\1\155\1\150\1\156\1\56\1\uffff\1\170\1\142\1\154"+
		"\1\145\1\156\1\164\1\uffff\1\145\3\56\1\167\1\164\1\157\1\156\1\144\1"+
		"\uffff\2\56\1\uffff\1\154\1\163\1\142\1\172\1\145\1\56\1\147\1\uffff\1"+
		"\164\1\165\1\164\4\56\3\uffff\2\56\1\160\2\56\2\uffff\2\56\1\154\1\145"+
		"\1\156\1\uffff\1\145\1\56\1\151\1\56\6\uffff\1\56\4\uffff\1\145\1\56\1"+
		"\164\1\56\1\uffff\1\154\2\uffff\1\163\1\uffff\1\56\1\uffff\1\144\1\56"+
		"\1\uffff\1\56\2\uffff";
	static final String DFA13_maxS =
		"\2\uffff\1\157\1\164\1\165\1\162\1\145\1\170\1\157\1\145\1\157\1\141\1"+
		"\157\1\146\1\143\1\145\1\160\1\171\1\156\1\141\6\uffff\1\56\1\172\2\uffff"+
		"\1\75\2\uffff\2\75\1\76\1\174\1\136\1\46\3\uffff\1\57\1\uffff\1\170\1"+
		"\uffff\1\uffff\1\170\1\uffff\1\uffff\3\uffff\1\164\1\162\1\uffff\1\151"+
		"\2\164\1\151\1\154\1\156\1\157\1\146\1\144\1\160\1\164\1\170\1\164\2\143"+
		"\1\155\2\146\1\157\1\164\1\172\1\141\1\153\1\160\1\151\1\162\6\uffff\1"+
		"\56\44\uffff\1\150\1\144\1\147\1\141\1\172\1\162\2\154\1\164\1\163\1\172"+
		"\2\151\2\157\1\172\1\164\1\141\1\162\1\145\1\154\1\163\1\144\1\165\1\156"+
		"\1\145\1\143\2\145\1\155\1\165\1\151\2\172\1\163\1\156\1\143\1\uffff\1"+
		"\141\1\144\1\172\1\145\1\163\1\uffff\1\165\1\156\1\141\1\162\1\172\1\uffff"+
		"\2\154\1\157\1\163\1\157\2\145\1\162\1\145\1\172\1\145\1\156\1\172\1\160"+
		"\1\145\1\141\2\uffff\1\151\1\155\1\150\1\156\1\172\1\uffff\1\170\1\142"+
		"\1\154\1\145\1\156\1\164\1\uffff\1\145\3\172\1\167\1\164\1\157\1\156\1"+
		"\144\1\uffff\2\172\1\uffff\1\154\1\163\1\142\1\172\1\145\1\172\1\147\1"+
		"\uffff\1\164\1\165\1\164\4\172\3\uffff\2\172\1\160\2\172\2\uffff\2\172"+
		"\1\154\1\145\1\156\1\uffff\1\145\1\172\1\151\1\172\6\uffff\1\172\4\uffff"+
		"\1\145\1\172\1\164\1\172\1\uffff\1\154\2\uffff\1\163\1\uffff\1\172\1\uffff"+
		"\1\144\1\172\1\uffff\1\172\2\uffff";
	static final String DFA13_acceptS =
		"\24\uffff\1\43\1\44\1\45\1\46\1\47\1\50\2\uffff\1\53\1\54\1\uffff\1\56"+
		"\1\57\6\uffff\1\77\1\100\1\101\1\uffff\1\103\1\uffff\1\107\2\uffff\1\111"+
		"\1\uffff\1\116\1\117\1\1\2\uffff\1\107\32\uffff\1\43\1\44\1\45\1\46\1"+
		"\47\1\50\1\uffff\1\52\1\53\1\54\1\62\1\55\1\56\1\57\1\61\1\60\1\65\1\75"+
		"\1\63\1\66\1\76\1\64\1\67\1\72\1\70\1\73\1\71\1\74\1\77\1\100\1\101\1"+
		"\115\1\102\1\103\1\104\1\105\1\106\1\110\1\112\1\113\1\111\1\114\1\116"+
		"\45\uffff\1\5\5\uffff\1\13\5\uffff\1\21\20\uffff\1\51\1\2\5\uffff\1\10"+
		"\6\uffff\1\20\11\uffff\1\33\2\uffff\1\36\7\uffff\1\7\7\uffff\1\23\1\24"+
		"\1\25\5\uffff\1\34\1\35\5\uffff\1\4\4\uffff\1\15\1\16\1\17\1\22\1\26\1"+
		"\27\1\uffff\1\31\1\32\1\37\1\40\4\uffff\1\11\1\uffff\1\14\1\30\1\uffff"+
		"\1\42\1\uffff\1\6\2\uffff\1\3\1\uffff\1\41\1\12";
	static final String DFA13_specialS =
		"\1\3\1\1\54\uffff\1\2\2\uffff\1\0\u00e9\uffff}>";
	static final String[] DFA13_transitionS = {
			"\10\63\1\1\2\62\2\63\1\62\22\63\1\62\1\36\1\56\1\61\1\54\1\53\1\46\1"+
			"\63\1\30\1\31\1\51\1\47\1\35\1\50\1\32\1\52\1\57\11\60\1\34\1\40\1\42"+
			"\1\41\1\43\2\63\32\55\1\26\1\63\1\27\1\45\1\33\1\63\1\3\1\4\1\5\1\6\1"+
			"\7\1\55\1\10\1\11\3\55\1\12\1\13\1\14\1\15\1\16\1\55\1\17\1\20\1\21\1"+
			"\22\1\23\1\2\3\55\1\24\1\44\1\25\1\37\uff81\63",
			"\12\64\1\uffff\ufff5\64",
			"\1\65\5\uffff\1\66",
			"\1\70\7\uffff\1\71",
			"\1\72\13\uffff\1\73",
			"\1\74\15\uffff\1\75\2\uffff\1\76",
			"\1\77",
			"\1\100\11\uffff\1\101",
			"\1\102",
			"\1\103",
			"\1\104\5\uffff\1\105",
			"\1\106",
			"\1\107\15\uffff\1\110",
			"\1\111",
			"\1\112",
			"\1\113",
			"\1\114\6\uffff\1\115",
			"\1\116\11\uffff\1\117",
			"\1\120",
			"\1\121",
			"",
			"",
			"",
			"",
			"",
			"",
			"\1\130",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"",
			"",
			"\1\134",
			"",
			"",
			"\1\140",
			"\1\143\1\142",
			"\1\145\1\146",
			"\1\150",
			"\1\152",
			"\1\154",
			"",
			"",
			"",
			"\1\161",
			"",
			"\1\165\15\uffff\1\164\10\uffff\1\166",
			"",
			"\0\167",
			"\1\171\25\uffff\1\170",
			"",
			"\0\173",
			"",
			"",
			"",
			"\1\175",
			"\1\176",
			"",
			"\1\177",
			"\1\u0080",
			"\1\u0081\14\uffff\1\u0082",
			"\1\u0083",
			"\1\u0084",
			"\1\u0085",
			"\1\u0086",
			"\1\u0087\2\uffff\1\u0088",
			"\1\u0089",
			"\1\u008a",
			"\1\u008b",
			"\1\u008c",
			"\1\u008d",
			"\1\u008e",
			"\1\u008f",
			"\1\u0090",
			"\1\u0091",
			"\1\u0092",
			"\1\u0093",
			"\1\u0094",
			"\1\u0095\22\uffff\1\u0096",
			"\1\u0097",
			"\1\u0098",
			"\1\u0099",
			"\1\u009a",
			"\1\u009b\5\uffff\1\u009c",
			"",
			"",
			"",
			"",
			"",
			"",
			"\1\u009d",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"\1\u009e",
			"\1\u009f",
			"\1\u00a0",
			"\1\u00a1",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\u00a3",
			"\1\u00a4",
			"\1\u00a5",
			"\1\u00a6",
			"\1\u00a7",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\u00a9\7\uffff\1\u00aa",
			"\1\u00ab",
			"\1\u00ac",
			"\1\u00ad",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\u00af",
			"\1\u00b0",
			"\1\u00b1",
			"\1\u00b2",
			"\1\u00b3",
			"\1\u00b4",
			"\1\u00b5",
			"\1\u00b6",
			"\1\u00b7",
			"\1\u00b8",
			"\1\u00b9",
			"\1\u00ba",
			"\1\u00bb",
			"\1\u00bc",
			"\1\u00bd",
			"\1\u00be",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\u00c1",
			"\1\u00c2",
			"\1\u00c3",
			"",
			"\1\u00c4",
			"\1\u00c5",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\u00c7",
			"\1\u00c8",
			"",
			"\1\u00c9",
			"\1\u00ca",
			"\1\u00cb",
			"\1\u00cc",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"",
			"\1\u00ce",
			"\1\u00cf",
			"\1\u00d0",
			"\1\u00d1",
			"\1\u00d2",
			"\1\u00d3",
			"\1\u00d4",
			"\1\u00d5",
			"\1\u00d6",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\u00d8",
			"\1\u00d9",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\u00db",
			"\1\u00dc",
			"\1\u00dd",
			"",
			"",
			"\1\u00de",
			"\1\u00df",
			"\1\u00e0",
			"\1\u00e1",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"",
			"\1\u00e3",
			"\1\u00e4",
			"\1\u00e5",
			"\1\u00e6",
			"\1\u00e7",
			"\1\u00e8",
			"",
			"\1\u00e9",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\u00ed",
			"\1\u00ee",
			"\1\u00ef",
			"\1\u00f0",
			"\1\u00f1",
			"",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"",
			"\1\u00f4",
			"\1\u00f5",
			"\1\u00f6",
			"\1\u00f7",
			"\1\u00f8",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\u00fa",
			"",
			"\1\u00fb",
			"\1\u00fc",
			"\1\u00fd",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"",
			"",
			"",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\u0104",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"",
			"",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\u0109",
			"\1\u010a",
			"\1\u010b",
			"",
			"\1\u010c",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\u010e",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"",
			"",
			"",
			"",
			"",
			"",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"",
			"",
			"",
			"",
			"\1\u0111",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"\1\u0113",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"",
			"\1\u0115",
			"",
			"",
			"\1\u0116",
			"",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"",
			"\1\u0118",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"",
			"\1\67\1\uffff\12\67\7\uffff\32\67\4\uffff\1\67\1\uffff\32\67",
			"",
			""
	};

	static final short[] DFA13_eot = DFA.unpackEncodedString(DFA13_eotS);
	static final short[] DFA13_eof = DFA.unpackEncodedString(DFA13_eofS);
	static final char[] DFA13_min = DFA.unpackEncodedStringToUnsignedChars(DFA13_minS);
	static final char[] DFA13_max = DFA.unpackEncodedStringToUnsignedChars(DFA13_maxS);
	static final short[] DFA13_accept = DFA.unpackEncodedString(DFA13_acceptS);
	static final short[] DFA13_special = DFA.unpackEncodedString(DFA13_specialS);
	static final short[][] DFA13_transition;

	static {
		int numStates = DFA13_transitionS.length;
		DFA13_transition = new short[numStates][];
		for (int i=0; i<numStates; i++) {
			DFA13_transition[i] = DFA.unpackEncodedString(DFA13_transitionS[i]);
		}
	}

	protected class DFA13 extends DFA {

		public DFA13(BaseRecognizer recognizer) {
			this.recognizer = recognizer;
			this.decisionNumber = 13;
			this.eot = DFA13_eot;
			this.eof = DFA13_eof;
			this.min = DFA13_min;
			this.max = DFA13_max;
			this.accept = DFA13_accept;
			this.special = DFA13_special;
			this.transition = DFA13_transition;
		}
		@Override
		public String getDescription() {
			return "1:1: Tokens : ( PP_POSITION | RES_WITH | KEY_ALIGNMENT | KEY_ATTACH | KEY_BIG | KEY_BITRANGE | KEY_BUILD | KEY_CALL | KEY_CONTEXT | KEY_CROSSBUILD | KEY_DEC | KEY_DEFAULT | KEY_DEFINE | KEY_ENDIAN | KEY_EXPORT | KEY_GOTO | KEY_HEX | KEY_LITTLE | KEY_LOCAL | KEY_MACRO | KEY_NAMES | KEY_NOFLOW | KEY_OFFSET | KEY_PCODEOP | KEY_RETURN | KEY_SIGNED | KEY_SIZE | KEY_SPACE | KEY_TOKEN | KEY_TYPE | KEY_UNIMPL | KEY_VALUES | KEY_VARIABLES | KEY_WORDSIZE | LBRACE | RBRACE | LBRACKET | RBRACKET | LPAREN | RPAREN | ELLIPSIS | UNDERSCORE | COLON | COMMA | EXCLAIM | TILDE | SEMI | ASSIGN | EQUAL | NOTEQUAL | LESS | GREAT | LESSEQUAL | GREATEQUAL | BOOL_OR | BOOL_XOR | BOOL_AND | PIPE | CARET | AMPERSAND | LEFT | RIGHT | PLUS | MINUS | ASTERISK | SLASH | PERCENT | SPEC_OR | SPEC_AND | SPEC_XOR | IDENTIFIER | QSTRING | DEC_INT | HEX_INT | BIN_INT | LINECOMMENT | CPPCOMMENT | WS | UNKNOWN );";
		}
		@Override
		public int specialStateTransition(int s, IntStream _input) throws NoViableAltException {
			IntStream input = _input;
			int _s = s;
			switch ( s ) {
					case 0 : 
						int LA13_49 = input.LA(1);
						s = -1;
						if ( ((LA13_49 >= '\u0000' && LA13_49 <= '\uFFFF')) ) {s = 123;}
						else s = 51;
						if ( s>=0 ) return s;
						break;

					case 1 : 
						int LA13_1 = input.LA(1);
						s = -1;
						if ( ((LA13_1 >= '\u0000' && LA13_1 <= '\t')||(LA13_1 >= '\u000B' && LA13_1 <= '\uFFFF')) ) {s = 52;}
						else s = 51;
						if ( s>=0 ) return s;
						break;

					case 2 : 
						int LA13_46 = input.LA(1);
						s = -1;
						if ( ((LA13_46 >= '\u0000' && LA13_46 <= '\uFFFF')) ) {s = 119;}
						else s = 51;
						if ( s>=0 ) return s;
						break;

					case 3 : 
						int LA13_0 = input.LA(1);
						s = -1;
						if ( (LA13_0=='\b') ) {s = 1;}
						else if ( (LA13_0=='w') ) {s = 2;}
						else if ( (LA13_0=='a') ) {s = 3;}
						else if ( (LA13_0=='b') ) {s = 4;}
						else if ( (LA13_0=='c') ) {s = 5;}
						else if ( (LA13_0=='d') ) {s = 6;}
						else if ( (LA13_0=='e') ) {s = 7;}
						else if ( (LA13_0=='g') ) {s = 8;}
						else if ( (LA13_0=='h') ) {s = 9;}
						else if ( (LA13_0=='l') ) {s = 10;}
						else if ( (LA13_0=='m') ) {s = 11;}
						else if ( (LA13_0=='n') ) {s = 12;}
						else if ( (LA13_0=='o') ) {s = 13;}
						else if ( (LA13_0=='p') ) {s = 14;}
						else if ( (LA13_0=='r') ) {s = 15;}
						else if ( (LA13_0=='s') ) {s = 16;}
						else if ( (LA13_0=='t') ) {s = 17;}
						else if ( (LA13_0=='u') ) {s = 18;}
						else if ( (LA13_0=='v') ) {s = 19;}
						else if ( (LA13_0=='{') ) {s = 20;}
						else if ( (LA13_0=='}') ) {s = 21;}
						else if ( (LA13_0=='[') ) {s = 22;}
						else if ( (LA13_0==']') ) {s = 23;}
						else if ( (LA13_0=='(') ) {s = 24;}
						else if ( (LA13_0==')') ) {s = 25;}
						else if ( (LA13_0=='.') ) {s = 26;}
						else if ( (LA13_0=='_') ) {s = 27;}
						else if ( (LA13_0==':') ) {s = 28;}
						else if ( (LA13_0==',') ) {s = 29;}
						else if ( (LA13_0=='!') ) {s = 30;}
						else if ( (LA13_0=='~') ) {s = 31;}
						else if ( (LA13_0==';') ) {s = 32;}
						else if ( (LA13_0=='=') ) {s = 33;}
						else if ( (LA13_0=='<') ) {s = 34;}
						else if ( (LA13_0=='>') ) {s = 35;}
						else if ( (LA13_0=='|') ) {s = 36;}
						else if ( (LA13_0=='^') ) {s = 37;}
						else if ( (LA13_0=='&') ) {s = 38;}
						else if ( (LA13_0=='+') ) {s = 39;}
						else if ( (LA13_0=='-') ) {s = 40;}
						else if ( (LA13_0=='*') ) {s = 41;}
						else if ( (LA13_0=='/') ) {s = 42;}
						else if ( (LA13_0=='%') ) {s = 43;}
						else if ( (LA13_0=='$') ) {s = 44;}
						else if ( ((LA13_0 >= 'A' && LA13_0 <= 'Z')||LA13_0=='f'||(LA13_0 >= 'i' && LA13_0 <= 'k')||LA13_0=='q'||(LA13_0 >= 'x' && LA13_0 <= 'z')) ) {s = 45;}
						else if ( (LA13_0=='\"') ) {s = 46;}
						else if ( (LA13_0=='0') ) {s = 47;}
						else if ( ((LA13_0 >= '1' && LA13_0 <= '9')) ) {s = 48;}
						else if ( (LA13_0=='#') ) {s = 49;}
						else if ( ((LA13_0 >= '\t' && LA13_0 <= '\n')||LA13_0=='\r'||LA13_0==' ') ) {s = 50;}
						else if ( ((LA13_0 >= '\u0000' && LA13_0 <= '\u0007')||(LA13_0 >= '\u000B' && LA13_0 <= '\f')||(LA13_0 >= '\u000E' && LA13_0 <= '\u001F')||LA13_0=='\''||(LA13_0 >= '?' && LA13_0 <= '@')||LA13_0=='\\'||LA13_0=='`'||(LA13_0 >= '\u007F' && LA13_0 <= '\uFFFF')) ) {s = 51;}
						if ( s>=0 ) return s;
						break;
			}
			if (state.backtracking>0) {state.failed=true; return -1;}
			NoViableAltException nvae =
				new NoViableAltException(getDescription(), 13, _s, input);
			error(nvae);
			throw nvae;
		}
	}

}
