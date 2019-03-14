package ghidra.sleigh.grammar;
// $ANTLR 3.5.2 ghidra/sleigh/grammar/SemanticLexer.g 2019-02-28 12:48:47

import org.antlr.runtime.*;
import java.util.Stack;
import java.util.List;
import java.util.ArrayList;

@SuppressWarnings("all")
public class SemanticLexer extends AbstractSleighLexer {
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

		@Override
		public void setEnv(ParsingEnvironment env) {
			super.setEnv(env);
			gBaseLexer.setEnv(env);
		}


	// delegates
	public SemanticLexer_BaseLexer gBaseLexer;
	// delegators
	public AbstractSleighLexer[] getDelegates() {
		return new AbstractSleighLexer[] {gBaseLexer};
	}

	public SemanticLexer() {} 
	public SemanticLexer(CharStream input) {
		this(input, new RecognizerSharedState());
	}
	public SemanticLexer(CharStream input, RecognizerSharedState state) {
		super(input,state);
		gBaseLexer = new SemanticLexer_BaseLexer(input, state, this);
	}
	@Override public String getGrammarFileName() { return "ghidra/sleigh/grammar/SemanticLexer.g"; }

	// $ANTLR start "FEQUAL"
	public final void mFEQUAL() throws RecognitionException {
		try {
			int _type = FEQUAL;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/SemanticLexer.g:31:10: ( 'f==' )
			// ghidra/sleigh/grammar/SemanticLexer.g:31:12: 'f=='
			{
			match("f=="); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "FEQUAL"

	// $ANTLR start "FNOTEQUAL"
	public final void mFNOTEQUAL() throws RecognitionException {
		try {
			int _type = FNOTEQUAL;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/SemanticLexer.g:32:12: ( 'f!=' )
			// ghidra/sleigh/grammar/SemanticLexer.g:32:14: 'f!='
			{
			match("f!="); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "FNOTEQUAL"

	// $ANTLR start "FLESS"
	public final void mFLESS() throws RecognitionException {
		try {
			int _type = FLESS;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/SemanticLexer.g:33:9: ( 'f<' )
			// ghidra/sleigh/grammar/SemanticLexer.g:33:11: 'f<'
			{
			match("f<"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "FLESS"

	// $ANTLR start "FGREAT"
	public final void mFGREAT() throws RecognitionException {
		try {
			int _type = FGREAT;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/SemanticLexer.g:34:10: ( 'f>' )
			// ghidra/sleigh/grammar/SemanticLexer.g:34:12: 'f>'
			{
			match("f>"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "FGREAT"

	// $ANTLR start "FLESSEQUAL"
	public final void mFLESSEQUAL() throws RecognitionException {
		try {
			int _type = FLESSEQUAL;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/SemanticLexer.g:35:13: ( 'f<=' )
			// ghidra/sleigh/grammar/SemanticLexer.g:35:15: 'f<='
			{
			match("f<="); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "FLESSEQUAL"

	// $ANTLR start "FGREATEQUAL"
	public final void mFGREATEQUAL() throws RecognitionException {
		try {
			int _type = FGREATEQUAL;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/SemanticLexer.g:36:14: ( 'f>=' )
			// ghidra/sleigh/grammar/SemanticLexer.g:36:16: 'f>='
			{
			match("f>="); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "FGREATEQUAL"

	// $ANTLR start "FPLUS"
	public final void mFPLUS() throws RecognitionException {
		try {
			int _type = FPLUS;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/SemanticLexer.g:39:9: ( 'f+' )
			// ghidra/sleigh/grammar/SemanticLexer.g:39:11: 'f+'
			{
			match("f+"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "FPLUS"

	// $ANTLR start "FMINUS"
	public final void mFMINUS() throws RecognitionException {
		try {
			int _type = FMINUS;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/SemanticLexer.g:40:10: ( 'f-' )
			// ghidra/sleigh/grammar/SemanticLexer.g:40:12: 'f-'
			{
			match("f-"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "FMINUS"

	// $ANTLR start "FMULT"
	public final void mFMULT() throws RecognitionException {
		try {
			int _type = FMULT;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/SemanticLexer.g:41:9: ( 'f*' )
			// ghidra/sleigh/grammar/SemanticLexer.g:41:11: 'f*'
			{
			match("f*"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "FMULT"

	// $ANTLR start "FDIV"
	public final void mFDIV() throws RecognitionException {
		try {
			int _type = FDIV;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/SemanticLexer.g:42:8: ( 'f/' )
			// ghidra/sleigh/grammar/SemanticLexer.g:42:10: 'f/'
			{
			match("f/"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "FDIV"

	// $ANTLR start "SLESS"
	public final void mSLESS() throws RecognitionException {
		try {
			int _type = SLESS;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/SemanticLexer.g:45:9: ( 's<' )
			// ghidra/sleigh/grammar/SemanticLexer.g:45:11: 's<'
			{
			match("s<"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "SLESS"

	// $ANTLR start "SGREAT"
	public final void mSGREAT() throws RecognitionException {
		try {
			int _type = SGREAT;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/SemanticLexer.g:46:10: ( 's>' )
			// ghidra/sleigh/grammar/SemanticLexer.g:46:12: 's>'
			{
			match("s>"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "SGREAT"

	// $ANTLR start "SLESSEQUAL"
	public final void mSLESSEQUAL() throws RecognitionException {
		try {
			int _type = SLESSEQUAL;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/SemanticLexer.g:47:13: ( 's<=' )
			// ghidra/sleigh/grammar/SemanticLexer.g:47:15: 's<='
			{
			match("s<="); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "SLESSEQUAL"

	// $ANTLR start "SGREATEQUAL"
	public final void mSGREATEQUAL() throws RecognitionException {
		try {
			int _type = SGREATEQUAL;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/SemanticLexer.g:48:14: ( 's>=' )
			// ghidra/sleigh/grammar/SemanticLexer.g:48:16: 's>='
			{
			match("s>="); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "SGREATEQUAL"

	// $ANTLR start "SRIGHT"
	public final void mSRIGHT() throws RecognitionException {
		try {
			int _type = SRIGHT;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/SemanticLexer.g:51:10: ( 's>>' )
			// ghidra/sleigh/grammar/SemanticLexer.g:51:12: 's>>'
			{
			match("s>>"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "SRIGHT"

	// $ANTLR start "SDIV"
	public final void mSDIV() throws RecognitionException {
		try {
			int _type = SDIV;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/SemanticLexer.g:52:8: ( 's/' )
			// ghidra/sleigh/grammar/SemanticLexer.g:52:10: 's/'
			{
			match("s/"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "SDIV"

	// $ANTLR start "SREM"
	public final void mSREM() throws RecognitionException {
		try {
			int _type = SREM;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/SemanticLexer.g:53:8: ( 's%' )
			// ghidra/sleigh/grammar/SemanticLexer.g:53:10: 's%'
			{
			match("s%"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "SREM"

	// $ANTLR start "RES_IF"
	public final void mRES_IF() throws RecognitionException {
		try {
			int _type = RES_IF;
			int _channel = DEFAULT_TOKEN_CHANNEL;
			// ghidra/sleigh/grammar/SemanticLexer.g:56:10: ( 'if' )
			// ghidra/sleigh/grammar/SemanticLexer.g:56:12: 'if'
			{
			match("if"); 

			}

			state.type = _type;
			state.channel = _channel;
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "RES_IF"

	@Override
	public void mTokens() throws RecognitionException {
		// ghidra/sleigh/grammar/SemanticLexer.g:1:8: ( FEQUAL | FNOTEQUAL | FLESS | FGREAT | FLESSEQUAL | FGREATEQUAL | FPLUS | FMINUS | FMULT | FDIV | SLESS | SGREAT | SLESSEQUAL | SGREATEQUAL | SRIGHT | SDIV | SREM | RES_IF | BaseLexer. Tokens )
		int alt1=19;
		int LA1_0 = input.LA(1);
		if ( (LA1_0=='f') ) {
			switch ( input.LA(2) ) {
			case '=':
				{
				alt1=1;
				}
				break;
			case '!':
				{
				alt1=2;
				}
				break;
			case '<':
				{
				int LA1_7 = input.LA(3);
				if ( (LA1_7=='=') ) {
					alt1=5;
				}

				else {
					alt1=3;
				}

				}
				break;
			case '>':
				{
				int LA1_8 = input.LA(3);
				if ( (LA1_8=='=') ) {
					alt1=6;
				}

				else {
					alt1=4;
				}

				}
				break;
			case '+':
				{
				alt1=7;
				}
				break;
			case '-':
				{
				alt1=8;
				}
				break;
			case '*':
				{
				alt1=9;
				}
				break;
			case '/':
				{
				alt1=10;
				}
				break;
			default:
				alt1=19;
			}
		}
		else if ( (LA1_0=='s') ) {
			switch ( input.LA(2) ) {
			case '<':
				{
				int LA1_13 = input.LA(3);
				if ( (LA1_13=='=') ) {
					alt1=13;
				}

				else {
					alt1=11;
				}

				}
				break;
			case '>':
				{
				switch ( input.LA(3) ) {
				case '=':
					{
					alt1=14;
					}
					break;
				case '>':
					{
					alt1=15;
					}
					break;
				default:
					alt1=12;
				}
				}
				break;
			case '/':
				{
				alt1=16;
				}
				break;
			case '%':
				{
				alt1=17;
				}
				break;
			default:
				alt1=19;
			}
		}
		else if ( (LA1_0=='i') ) {
			int LA1_3 = input.LA(2);
			if ( (LA1_3=='f') ) {
				int LA1_17 = input.LA(3);
				if ( (LA1_17=='.'||(LA1_17 >= '0' && LA1_17 <= '9')||(LA1_17 >= 'A' && LA1_17 <= 'Z')||LA1_17=='_'||(LA1_17 >= 'a' && LA1_17 <= 'z')) ) {
					alt1=19;
				}

				else {
					alt1=18;
				}

			}

			else {
				alt1=19;
			}

		}
		else if ( ((LA1_0 >= '\u0000' && LA1_0 <= 'e')||(LA1_0 >= 'g' && LA1_0 <= 'h')||(LA1_0 >= 'j' && LA1_0 <= 'r')||(LA1_0 >= 't' && LA1_0 <= '\uFFFF')) ) {
			alt1=19;
		}

		else {
			NoViableAltException nvae =
				new NoViableAltException("", 1, 0, input);
			throw nvae;
		}

		switch (alt1) {
			case 1 :
				// ghidra/sleigh/grammar/SemanticLexer.g:1:10: FEQUAL
				{
				mFEQUAL(); 

				}
				break;
			case 2 :
				// ghidra/sleigh/grammar/SemanticLexer.g:1:17: FNOTEQUAL
				{
				mFNOTEQUAL(); 

				}
				break;
			case 3 :
				// ghidra/sleigh/grammar/SemanticLexer.g:1:27: FLESS
				{
				mFLESS(); 

				}
				break;
			case 4 :
				// ghidra/sleigh/grammar/SemanticLexer.g:1:33: FGREAT
				{
				mFGREAT(); 

				}
				break;
			case 5 :
				// ghidra/sleigh/grammar/SemanticLexer.g:1:40: FLESSEQUAL
				{
				mFLESSEQUAL(); 

				}
				break;
			case 6 :
				// ghidra/sleigh/grammar/SemanticLexer.g:1:51: FGREATEQUAL
				{
				mFGREATEQUAL(); 

				}
				break;
			case 7 :
				// ghidra/sleigh/grammar/SemanticLexer.g:1:63: FPLUS
				{
				mFPLUS(); 

				}
				break;
			case 8 :
				// ghidra/sleigh/grammar/SemanticLexer.g:1:69: FMINUS
				{
				mFMINUS(); 

				}
				break;
			case 9 :
				// ghidra/sleigh/grammar/SemanticLexer.g:1:76: FMULT
				{
				mFMULT(); 

				}
				break;
			case 10 :
				// ghidra/sleigh/grammar/SemanticLexer.g:1:82: FDIV
				{
				mFDIV(); 

				}
				break;
			case 11 :
				// ghidra/sleigh/grammar/SemanticLexer.g:1:87: SLESS
				{
				mSLESS(); 

				}
				break;
			case 12 :
				// ghidra/sleigh/grammar/SemanticLexer.g:1:93: SGREAT
				{
				mSGREAT(); 

				}
				break;
			case 13 :
				// ghidra/sleigh/grammar/SemanticLexer.g:1:100: SLESSEQUAL
				{
				mSLESSEQUAL(); 

				}
				break;
			case 14 :
				// ghidra/sleigh/grammar/SemanticLexer.g:1:111: SGREATEQUAL
				{
				mSGREATEQUAL(); 

				}
				break;
			case 15 :
				// ghidra/sleigh/grammar/SemanticLexer.g:1:123: SRIGHT
				{
				mSRIGHT(); 

				}
				break;
			case 16 :
				// ghidra/sleigh/grammar/SemanticLexer.g:1:130: SDIV
				{
				mSDIV(); 

				}
				break;
			case 17 :
				// ghidra/sleigh/grammar/SemanticLexer.g:1:135: SREM
				{
				mSREM(); 

				}
				break;
			case 18 :
				// ghidra/sleigh/grammar/SemanticLexer.g:1:140: RES_IF
				{
				mRES_IF(); 

				}
				break;
			case 19 :
				// ghidra/sleigh/grammar/SemanticLexer.g:1:147: BaseLexer. Tokens
				{
				gBaseLexer.mTokens(); 

				}
				break;

		}
	}



}
