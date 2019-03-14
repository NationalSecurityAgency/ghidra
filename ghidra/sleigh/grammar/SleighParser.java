package ghidra.sleigh.grammar;
// $ANTLR 3.5.2 ghidra/sleigh/grammar/SleighParser.g 2019-02-28 12:48:46

import org.antlr.runtime.*;
import java.util.Stack;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;

import org.antlr.runtime.tree.*;


@SuppressWarnings("all")
public class SleighParser extends AbstractSleighParser {
	public static final String[] tokenNames = new String[] {
		"<invalid>", "<EOR>", "<DOWN>", "<UP>", "ALPHA", "ALPHAUP", "AMPERSAND", 
		"ASSIGN", "ASTERISK", "BINDIGIT", "BIN_INT", "BOOL_AND", "BOOL_OR", "BOOL_XOR", 
		"CARET", "COLON", "COMMA", "CPPCOMMENT", "DEC_INT", "DIGIT", "DISPCHAR", 
		"ELLIPSIS", "EOL", "EQUAL", "ESCAPE", "EXCLAIM", "FDIV", "FEQUAL", "FGREAT", 
		"FGREATEQUAL", "FLESS", "FLESSEQUAL", "FMINUS", "FMULT", "FNOTEQUAL", 
		"FPLUS", "GREAT", "GREATEQUAL", "HEXDIGIT", "HEX_INT", "IDENTIFIER", "KEY_ALIGNMENT", 
		"KEY_ATTACH", "KEY_BIG", "KEY_BITRANGE", "KEY_BUILD", "KEY_CALL", "KEY_CONTEXT", 
		"KEY_CROSSBUILD", "KEY_DEC", "KEY_DEFAULT", "KEY_DEFINE", "KEY_ENDIAN", 
		"KEY_EXPORT", "KEY_GOTO", "KEY_HEX", "KEY_LITTLE", "KEY_LOCAL", "KEY_MACRO", 
		"KEY_NAMES", "KEY_NOFLOW", "KEY_OFFSET", "KEY_PCODEOP", "KEY_RETURN", 
		"KEY_SIGNED", "KEY_SIZE", "KEY_SPACE", "KEY_TOKEN", "KEY_TYPE", "KEY_UNIMPL", 
		"KEY_VALUES", "KEY_VARIABLES", "KEY_WORDSIZE", "LBRACE", "LBRACKET", "LEFT", 
		"LESS", "LESSEQUAL", "LINECOMMENT", "LPAREN", "MINUS", "NOTEQUAL", "OCTAL_ESCAPE", 
		"OP_ADD", "OP_ADDRESS_OF", "OP_ALIGNMENT", "OP_AND", "OP_APPLY", "OP_ARGUMENTS", 
		"OP_ASSIGN", "OP_BIG", "OP_BIN_CONSTANT", "OP_BITRANGE", "OP_BITRANGE2", 
		"OP_BITRANGES", "OP_BIT_PATTERN", "OP_BOOL_AND", "OP_BOOL_OR", "OP_BOOL_XOR", 
		"OP_BUILD", "OP_CALL", "OP_CONCATENATE", "OP_CONSTRUCTOR", "OP_CONTEXT", 
		"OP_CONTEXT_BLOCK", "OP_CROSSBUILD", "OP_CTLIST", "OP_DEC", "OP_DECLARATIVE_SIZE", 
		"OP_DEC_CONSTANT", "OP_DEFAULT", "OP_DEREFERENCE", "OP_DISPLAY", "OP_DIV", 
		"OP_ELLIPSIS", "OP_ELLIPSIS_RIGHT", "OP_EMPTY_LIST", "OP_ENDIAN", "OP_EQUAL", 
		"OP_EXPORT", "OP_FADD", "OP_FDIV", "OP_FEQUAL", "OP_FGREAT", "OP_FGREATEQUAL", 
		"OP_FIELDDEF", "OP_FIELDDEFS", "OP_FIELD_MODS", "OP_FLESS", "OP_FLESSEQUAL", 
		"OP_FMULT", "OP_FNEGATE", "OP_FNOTEQUAL", "OP_FSUB", "OP_GOTO", "OP_GREAT", 
		"OP_GREATEQUAL", "OP_HEX", "OP_HEX_CONSTANT", "OP_IDENTIFIER", "OP_IDENTIFIER_LIST", 
		"OP_IF", "OP_INTBLIST", "OP_INVERT", "OP_JUMPDEST_ABSOLUTE", "OP_JUMPDEST_DYNAMIC", 
		"OP_JUMPDEST_LABEL", "OP_JUMPDEST_RELATIVE", "OP_JUMPDEST_SYMBOL", "OP_LABEL", 
		"OP_LEFT", "OP_LESS", "OP_LESSEQUAL", "OP_LITTLE", "OP_LOCAL", "OP_MACRO", 
		"OP_MULT", "OP_NAMES", "OP_NEGATE", "OP_NIL", "OP_NOFLOW", "OP_NOP", "OP_NOT", 
		"OP_NOTEQUAL", "OP_NOT_DEFAULT", "OP_NO_CONTEXT_BLOCK", "OP_NO_FIELD_MOD", 
		"OP_OR", "OP_PARENTHESIZED", "OP_PCODE", "OP_PCODEOP", "OP_QSTRING", "OP_REM", 
		"OP_RETURN", "OP_RIGHT", "OP_SDIV", "OP_SECTION_LABEL", "OP_SEMANTIC", 
		"OP_SEQUENCE", "OP_SGREAT", "OP_SGREATEQUAL", "OP_SIGNED", "OP_SIZE", 
		"OP_SIZING_SIZE", "OP_SLESS", "OP_SLESSEQUAL", "OP_SPACE", "OP_SPACEMODS", 
		"OP_SREM", "OP_SRIGHT", "OP_STRING", "OP_STRING_OR_IDENT_LIST", "OP_SUB", 
		"OP_SUBTABLE", "OP_TABLE", "OP_TOKEN", "OP_TRUNCATION_SIZE", "OP_TYPE", 
		"OP_UNIMPL", "OP_VALUES", "OP_VARIABLES", "OP_VARNODE", "OP_WHITESPACE", 
		"OP_WILDCARD", "OP_WITH", "OP_WORDSIZE", "OP_XOR", "PERCENT", "PIPE", 
		"PLUS", "PP_ESCAPE", "PP_POSITION", "QSTRING", "RBRACE", "RBRACKET", "RES_IF", 
		"RES_IS", "RES_WITH", "RIGHT", "RPAREN", "SDIV", "SEMI", "SGREAT", "SGREATEQUAL", 
		"SLASH", "SLESS", "SLESSEQUAL", "SPEC_AND", "SPEC_OR", "SPEC_XOR", "SREM", 
		"SRIGHT", "TILDE", "Tokens", "UNDERSCORE", "UNICODE_ESCAPE", "UNKNOWN", 
		"WS", "238", "239", "240", "241", "242", "243", "244", "245", "246", "247", 
		"248", "249", "250", "251", "252", "253", "254", "255", "256", "257", 
		"258", "259", "260", "261", "262", "263", "264", "265", "266", "267", 
		"268", "269", "270", "271", "272", "273", "274", "275", "276", "277", 
		"278", "279", "280", "281", "282", "283", "284", "285", "286", "287", 
		"288", "289", "290", "291", "292", "293", "294", "295", "296", "297", 
		"298", "299", "300", "301", "302", "303", "304", "305"
	};
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
	public SleighParser_DisplayParser gDisplayParser;
	public SleighParser_SemanticParser gSemanticParser;
	public AbstractSleighParser[] getDelegates() {
		return new AbstractSleighParser[] {gDisplayParser, gSemanticParser};
	}

	// delegators


	public SleighParser(TokenStream input) {
		this(input, new RecognizerSharedState());
	}
	public SleighParser(TokenStream input, RecognizerSharedState state) {
		super(input, state);
		gDisplayParser = new SleighParser_DisplayParser(input, state, this);
		gSemanticParser = new SleighParser_SemanticParser(input, state, this);
	}

	protected TreeAdaptor adaptor = new CommonTreeAdaptor();

	public void setTreeAdaptor(TreeAdaptor adaptor) {
		this.adaptor = adaptor;
		gDisplayParser.setTreeAdaptor(this.adaptor);gSemanticParser.setTreeAdaptor(this.adaptor);
	}
	public TreeAdaptor getTreeAdaptor() {
		return adaptor;
	}
	@Override public String[] getTokenNames() { return SleighParser.tokenNames; }
	@Override public String getGrammarFileName() { return "ghidra/sleigh/grammar/SleighParser.g"; }


		@Override
		public void setLexer(SleighLexer lexer) {
			super.setLexer(lexer);
			gDisplayParser.setLexer(lexer);
			gSemanticParser.setLexer(lexer);
		}


	public static class spec_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "spec"
	// ghidra/sleigh/grammar/SleighParser.g:25:1: spec : endiandef ( definition | constructorlike )* EOF ;
	public final SleighParser.spec_return spec() throws RecognitionException {
		SleighParser.spec_return retval = new SleighParser.spec_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token EOF4=null;
		ParserRuleReturnScope endiandef1 =null;
		ParserRuleReturnScope definition2 =null;
		ParserRuleReturnScope constructorlike3 =null;

		CommonTree EOF4_tree=null;

		try {
			// ghidra/sleigh/grammar/SleighParser.g:31:2: ( endiandef ( definition | constructorlike )* EOF )
			// ghidra/sleigh/grammar/SleighParser.g:31:4: endiandef ( definition | constructorlike )* EOF
			{
			root_0 = (CommonTree)adaptor.nil();


			if ( state.backtracking==0 ) {
						if (env.getLexingErrors() > 0) {
							bail("Abort");
						}
					}
			pushFollow(FOLLOW_endiandef_in_spec78);
			endiandef1=endiandef();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, endiandef1.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:37:3: ( definition | constructorlike )*
			loop1:
			while (true) {
				int alt1=3;
				switch ( input.LA(1) ) {
				case KEY_DEFINE:
					{
					int LA1_2 = input.LA(2);
					if ( ((LA1_2 >= IDENTIFIER && LA1_2 <= KEY_WORDSIZE)) ) {
						alt1=1;
					}
					else if ( (LA1_2==COLON) ) {
						alt1=2;
					}

					}
					break;
				case KEY_ATTACH:
					{
					int LA1_3 = input.LA(2);
					if ( (LA1_3==KEY_NAMES||(LA1_3 >= KEY_VALUES && LA1_3 <= KEY_VARIABLES)) ) {
						alt1=1;
					}
					else if ( (LA1_3==COLON) ) {
						alt1=2;
					}

					}
					break;
				case COLON:
				case IDENTIFIER:
				case KEY_ALIGNMENT:
				case KEY_BIG:
				case KEY_BITRANGE:
				case KEY_BUILD:
				case KEY_CALL:
				case KEY_CONTEXT:
				case KEY_CROSSBUILD:
				case KEY_DEC:
				case KEY_DEFAULT:
				case KEY_ENDIAN:
				case KEY_EXPORT:
				case KEY_GOTO:
				case KEY_HEX:
				case KEY_LITTLE:
				case KEY_LOCAL:
				case KEY_MACRO:
				case KEY_NAMES:
				case KEY_NOFLOW:
				case KEY_OFFSET:
				case KEY_PCODEOP:
				case KEY_RETURN:
				case KEY_SIGNED:
				case KEY_SIZE:
				case KEY_SPACE:
				case KEY_TOKEN:
				case KEY_TYPE:
				case KEY_UNIMPL:
				case KEY_VALUES:
				case KEY_VARIABLES:
				case KEY_WORDSIZE:
				case RES_WITH:
					{
					alt1=2;
					}
					break;
				}
				switch (alt1) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:37:5: definition
					{
					pushFollow(FOLLOW_definition_in_spec84);
					definition2=definition();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, definition2.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:38:5: constructorlike
					{
					pushFollow(FOLLOW_constructorlike_in_spec90);
					constructorlike3=constructorlike();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, constructorlike3.getTree());

					}
					break;

				default :
					break loop1;
				}
			}

			EOF4=(Token)match(input,EOF,FOLLOW_EOF_in_spec97); if (state.failed) return retval;
			if ( state.backtracking==0 ) {
			EOF4_tree = (CommonTree)adaptor.create(EOF4);
			adaptor.addChild(root_0, EOF4_tree);
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
			if ( state.backtracking==0 ) {
					if (env.getParsingErrors() > 0) {
						bail("Abort");
					}
				}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "spec"


	public static class endiandef_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "endiandef"
	// ghidra/sleigh/grammar/SleighParser.g:42:1: endiandef : lc= KEY_DEFINE KEY_ENDIAN ASSIGN endian SEMI -> ^( OP_ENDIAN[$lc,\"define endian\"] endian ) ;
	public final SleighParser.endiandef_return endiandef() throws RecognitionException {
		SleighParser.endiandef_return retval = new SleighParser.endiandef_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token KEY_ENDIAN5=null;
		Token ASSIGN6=null;
		Token SEMI8=null;
		ParserRuleReturnScope endian7 =null;

		CommonTree lc_tree=null;
		CommonTree KEY_ENDIAN5_tree=null;
		CommonTree ASSIGN6_tree=null;
		CommonTree SEMI8_tree=null;
		RewriteRuleTokenStream stream_KEY_ENDIAN=new RewriteRuleTokenStream(adaptor,"token KEY_ENDIAN");
		RewriteRuleTokenStream stream_SEMI=new RewriteRuleTokenStream(adaptor,"token SEMI");
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleTokenStream stream_KEY_DEFINE=new RewriteRuleTokenStream(adaptor,"token KEY_DEFINE");
		RewriteRuleSubtreeStream stream_endian=new RewriteRuleSubtreeStream(adaptor,"rule endian");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:43:2: (lc= KEY_DEFINE KEY_ENDIAN ASSIGN endian SEMI -> ^( OP_ENDIAN[$lc,\"define endian\"] endian ) )
			// ghidra/sleigh/grammar/SleighParser.g:43:4: lc= KEY_DEFINE KEY_ENDIAN ASSIGN endian SEMI
			{
			lc=(Token)match(input,KEY_DEFINE,FOLLOW_KEY_DEFINE_in_endiandef110); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_DEFINE.add(lc);

			KEY_ENDIAN5=(Token)match(input,KEY_ENDIAN,FOLLOW_KEY_ENDIAN_in_endiandef112); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_ENDIAN.add(KEY_ENDIAN5);

			ASSIGN6=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_endiandef114); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_ASSIGN.add(ASSIGN6);

			pushFollow(FOLLOW_endian_in_endiandef116);
			endian7=endian();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_endian.add(endian7.getTree());
			SEMI8=(Token)match(input,SEMI,FOLLOW_SEMI_in_endiandef118); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_SEMI.add(SEMI8);

			// AST REWRITE
			// elements: endian
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 43:48: -> ^( OP_ENDIAN[$lc,\"define endian\"] endian )
			{
				// ghidra/sleigh/grammar/SleighParser.g:43:51: ^( OP_ENDIAN[$lc,\"define endian\"] endian )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_ENDIAN, lc, "define endian"), root_1);
				adaptor.addChild(root_1, stream_endian.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "endiandef"


	public static class endian_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "endian"
	// ghidra/sleigh/grammar/SleighParser.g:46:1: endian : (lc= KEY_BIG -> OP_BIG[$lc] |lc= KEY_LITTLE -> OP_LITTLE[$lc] );
	public final SleighParser.endian_return endian() throws RecognitionException {
		SleighParser.endian_return retval = new SleighParser.endian_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_KEY_BIG=new RewriteRuleTokenStream(adaptor,"token KEY_BIG");
		RewriteRuleTokenStream stream_KEY_LITTLE=new RewriteRuleTokenStream(adaptor,"token KEY_LITTLE");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:47:2: (lc= KEY_BIG -> OP_BIG[$lc] |lc= KEY_LITTLE -> OP_LITTLE[$lc] )
			int alt2=2;
			int LA2_0 = input.LA(1);
			if ( (LA2_0==KEY_BIG) ) {
				alt2=1;
			}
			else if ( (LA2_0==KEY_LITTLE) ) {
				alt2=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 2, 0, input);
				throw nvae;
			}

			switch (alt2) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:47:4: lc= KEY_BIG
					{
					lc=(Token)match(input,KEY_BIG,FOLLOW_KEY_BIG_in_endian140); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_BIG.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 47:15: -> OP_BIG[$lc]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_BIG, lc));
					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:48:4: lc= KEY_LITTLE
					{
					lc=(Token)match(input,KEY_LITTLE,FOLLOW_KEY_LITTLE_in_endian152); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_LITTLE.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 48:18: -> OP_LITTLE[$lc]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_LITTLE, lc));
					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "endian"


	public static class definition_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "definition"
	// ghidra/sleigh/grammar/SleighParser.g:51:1: definition : ( aligndef | tokendef | contextdef | spacedef | varnodedef | bitrangedef | pcodeopdef | valueattach | nameattach | varattach ) SEMI !;
	public final SleighParser.definition_return definition() throws RecognitionException {
		SleighParser.definition_return retval = new SleighParser.definition_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token SEMI19=null;
		ParserRuleReturnScope aligndef9 =null;
		ParserRuleReturnScope tokendef10 =null;
		ParserRuleReturnScope contextdef11 =null;
		ParserRuleReturnScope spacedef12 =null;
		ParserRuleReturnScope varnodedef13 =null;
		ParserRuleReturnScope bitrangedef14 =null;
		ParserRuleReturnScope pcodeopdef15 =null;
		ParserRuleReturnScope valueattach16 =null;
		ParserRuleReturnScope nameattach17 =null;
		ParserRuleReturnScope varattach18 =null;

		CommonTree SEMI19_tree=null;

		try {
			// ghidra/sleigh/grammar/SleighParser.g:52:2: ( ( aligndef | tokendef | contextdef | spacedef | varnodedef | bitrangedef | pcodeopdef | valueattach | nameattach | varattach ) SEMI !)
			// ghidra/sleigh/grammar/SleighParser.g:52:4: ( aligndef | tokendef | contextdef | spacedef | varnodedef | bitrangedef | pcodeopdef | valueattach | nameattach | varattach ) SEMI !
			{
			root_0 = (CommonTree)adaptor.nil();


			// ghidra/sleigh/grammar/SleighParser.g:52:4: ( aligndef | tokendef | contextdef | spacedef | varnodedef | bitrangedef | pcodeopdef | valueattach | nameattach | varattach )
			int alt3=10;
			int LA3_0 = input.LA(1);
			if ( (LA3_0==KEY_DEFINE) ) {
				switch ( input.LA(2) ) {
				case KEY_ALIGNMENT:
					{
					int LA3_3 = input.LA(3);
					if ( (LA3_3==ASSIGN) ) {
						alt3=1;
					}
					else if ( (LA3_3==KEY_OFFSET) ) {
						alt3=5;
					}

					else {
						if (state.backtracking>0) {state.failed=true; return retval;}
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 3, 3, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_TOKEN:
					{
					int LA3_4 = input.LA(3);
					if ( ((LA3_4 >= IDENTIFIER && LA3_4 <= KEY_NOFLOW)||(LA3_4 >= KEY_PCODEOP && LA3_4 <= KEY_WORDSIZE)) ) {
						alt3=2;
					}
					else if ( (LA3_4==KEY_OFFSET) ) {
						int LA3_15 = input.LA(4);
						if ( (LA3_15==ASSIGN) ) {
							alt3=5;
						}
						else if ( (LA3_15==LPAREN) ) {
							alt3=2;
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 3, 15, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

					}

					else {
						if (state.backtracking>0) {state.failed=true; return retval;}
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 3, 4, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_CONTEXT:
					{
					int LA3_5 = input.LA(3);
					if ( ((LA3_5 >= IDENTIFIER && LA3_5 <= KEY_NOFLOW)||(LA3_5 >= KEY_PCODEOP && LA3_5 <= KEY_WORDSIZE)) ) {
						alt3=3;
					}
					else if ( (LA3_5==KEY_OFFSET) ) {
						int LA3_17 = input.LA(4);
						if ( (LA3_17==ASSIGN) ) {
							alt3=5;
						}
						else if ( ((LA3_17 >= IDENTIFIER && LA3_17 <= KEY_WORDSIZE)||LA3_17==SEMI) ) {
							alt3=3;
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 3, 17, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

					}

					else {
						if (state.backtracking>0) {state.failed=true; return retval;}
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 3, 5, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_SPACE:
					{
					int LA3_6 = input.LA(3);
					if ( ((LA3_6 >= IDENTIFIER && LA3_6 <= KEY_NOFLOW)||(LA3_6 >= KEY_PCODEOP && LA3_6 <= KEY_WORDSIZE)) ) {
						alt3=4;
					}
					else if ( (LA3_6==KEY_OFFSET) ) {
						int LA3_19 = input.LA(4);
						if ( (LA3_19==ASSIGN) ) {
							alt3=5;
						}
						else if ( (LA3_19==KEY_DEFAULT||LA3_19==KEY_SIZE||LA3_19==KEY_TYPE||LA3_19==KEY_WORDSIZE||LA3_19==SEMI) ) {
							alt3=4;
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 3, 19, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

					}

					else {
						if (state.backtracking>0) {state.failed=true; return retval;}
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 3, 6, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_BITRANGE:
					{
					int LA3_7 = input.LA(3);
					if ( ((LA3_7 >= IDENTIFIER && LA3_7 <= KEY_NOFLOW)||(LA3_7 >= KEY_PCODEOP && LA3_7 <= KEY_WORDSIZE)) ) {
						alt3=6;
					}
					else if ( (LA3_7==KEY_OFFSET) ) {
						int LA3_21 = input.LA(4);
						if ( (LA3_21==ASSIGN) ) {
							int LA3_24 = input.LA(5);
							if ( (LA3_24==BIN_INT||LA3_24==DEC_INT||LA3_24==HEX_INT) ) {
								alt3=5;
							}
							else if ( ((LA3_24 >= IDENTIFIER && LA3_24 <= KEY_WORDSIZE)) ) {
								alt3=6;
							}

							else {
								if (state.backtracking>0) {state.failed=true; return retval;}
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 3, 24, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 3, 21, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

					}

					else {
						if (state.backtracking>0) {state.failed=true; return retval;}
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 3, 7, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_PCODEOP:
					{
					int LA3_8 = input.LA(3);
					if ( ((LA3_8 >= IDENTIFIER && LA3_8 <= KEY_NOFLOW)||(LA3_8 >= KEY_PCODEOP && LA3_8 <= KEY_WORDSIZE)||LA3_8==LBRACKET||LA3_8==UNDERSCORE) ) {
						alt3=7;
					}
					else if ( (LA3_8==KEY_OFFSET) ) {
						int LA3_23 = input.LA(4);
						if ( (LA3_23==ASSIGN) ) {
							alt3=5;
						}
						else if ( (LA3_23==SEMI) ) {
							alt3=7;
						}

						else {
							if (state.backtracking>0) {state.failed=true; return retval;}
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 3, 23, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

					}

					else {
						if (state.backtracking>0) {state.failed=true; return retval;}
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 3, 8, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case IDENTIFIER:
				case KEY_ATTACH:
				case KEY_BIG:
				case KEY_BUILD:
				case KEY_CALL:
				case KEY_CROSSBUILD:
				case KEY_DEC:
				case KEY_DEFAULT:
				case KEY_DEFINE:
				case KEY_ENDIAN:
				case KEY_EXPORT:
				case KEY_GOTO:
				case KEY_HEX:
				case KEY_LITTLE:
				case KEY_LOCAL:
				case KEY_MACRO:
				case KEY_NAMES:
				case KEY_NOFLOW:
				case KEY_OFFSET:
				case KEY_RETURN:
				case KEY_SIGNED:
				case KEY_SIZE:
				case KEY_TYPE:
				case KEY_UNIMPL:
				case KEY_VALUES:
				case KEY_VARIABLES:
				case KEY_WORDSIZE:
					{
					alt3=5;
					}
					break;
				default:
					if (state.backtracking>0) {state.failed=true; return retval;}
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
			else if ( (LA3_0==KEY_ATTACH) ) {
				switch ( input.LA(2) ) {
				case KEY_VALUES:
					{
					alt3=8;
					}
					break;
				case KEY_NAMES:
					{
					alt3=9;
					}
					break;
				case KEY_VARIABLES:
					{
					alt3=10;
					}
					break;
				default:
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 3, 2, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 3, 0, input);
				throw nvae;
			}

			switch (alt3) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:52:5: aligndef
					{
					pushFollow(FOLLOW_aligndef_in_definition169);
					aligndef9=aligndef();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, aligndef9.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:53:4: tokendef
					{
					pushFollow(FOLLOW_tokendef_in_definition174);
					tokendef10=tokendef();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, tokendef10.getTree());

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighParser.g:54:4: contextdef
					{
					pushFollow(FOLLOW_contextdef_in_definition179);
					contextdef11=contextdef();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, contextdef11.getTree());

					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighParser.g:55:4: spacedef
					{
					pushFollow(FOLLOW_spacedef_in_definition184);
					spacedef12=spacedef();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, spacedef12.getTree());

					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighParser.g:56:4: varnodedef
					{
					pushFollow(FOLLOW_varnodedef_in_definition189);
					varnodedef13=varnodedef();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, varnodedef13.getTree());

					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighParser.g:57:4: bitrangedef
					{
					pushFollow(FOLLOW_bitrangedef_in_definition194);
					bitrangedef14=bitrangedef();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, bitrangedef14.getTree());

					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighParser.g:58:4: pcodeopdef
					{
					pushFollow(FOLLOW_pcodeopdef_in_definition199);
					pcodeopdef15=pcodeopdef();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pcodeopdef15.getTree());

					}
					break;
				case 8 :
					// ghidra/sleigh/grammar/SleighParser.g:59:4: valueattach
					{
					pushFollow(FOLLOW_valueattach_in_definition204);
					valueattach16=valueattach();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, valueattach16.getTree());

					}
					break;
				case 9 :
					// ghidra/sleigh/grammar/SleighParser.g:60:4: nameattach
					{
					pushFollow(FOLLOW_nameattach_in_definition209);
					nameattach17=nameattach();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, nameattach17.getTree());

					}
					break;
				case 10 :
					// ghidra/sleigh/grammar/SleighParser.g:61:4: varattach
					{
					pushFollow(FOLLOW_varattach_in_definition214);
					varattach18=varattach();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, varattach18.getTree());

					}
					break;

			}

			SEMI19=(Token)match(input,SEMI,FOLLOW_SEMI_in_definition217); if (state.failed) return retval;
			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "definition"


	public static class aligndef_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "aligndef"
	// ghidra/sleigh/grammar/SleighParser.g:64:1: aligndef : lc= KEY_DEFINE KEY_ALIGNMENT ASSIGN integer -> ^( OP_ALIGNMENT[$lc, \"define alignment\"] integer ) ;
	public final SleighParser.aligndef_return aligndef() throws RecognitionException {
		SleighParser.aligndef_return retval = new SleighParser.aligndef_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token KEY_ALIGNMENT20=null;
		Token ASSIGN21=null;
		ParserRuleReturnScope integer22 =null;

		CommonTree lc_tree=null;
		CommonTree KEY_ALIGNMENT20_tree=null;
		CommonTree ASSIGN21_tree=null;
		RewriteRuleTokenStream stream_KEY_ALIGNMENT=new RewriteRuleTokenStream(adaptor,"token KEY_ALIGNMENT");
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleTokenStream stream_KEY_DEFINE=new RewriteRuleTokenStream(adaptor,"token KEY_DEFINE");
		RewriteRuleSubtreeStream stream_integer=new RewriteRuleSubtreeStream(adaptor,"rule integer");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:65:2: (lc= KEY_DEFINE KEY_ALIGNMENT ASSIGN integer -> ^( OP_ALIGNMENT[$lc, \"define alignment\"] integer ) )
			// ghidra/sleigh/grammar/SleighParser.g:65:4: lc= KEY_DEFINE KEY_ALIGNMENT ASSIGN integer
			{
			lc=(Token)match(input,KEY_DEFINE,FOLLOW_KEY_DEFINE_in_aligndef231); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_DEFINE.add(lc);

			KEY_ALIGNMENT20=(Token)match(input,KEY_ALIGNMENT,FOLLOW_KEY_ALIGNMENT_in_aligndef233); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_ALIGNMENT.add(KEY_ALIGNMENT20);

			ASSIGN21=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_aligndef235); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_ASSIGN.add(ASSIGN21);

			pushFollow(FOLLOW_integer_in_aligndef237);
			integer22=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(integer22.getTree());
			// AST REWRITE
			// elements: integer
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 65:47: -> ^( OP_ALIGNMENT[$lc, \"define alignment\"] integer )
			{
				// ghidra/sleigh/grammar/SleighParser.g:65:50: ^( OP_ALIGNMENT[$lc, \"define alignment\"] integer )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_ALIGNMENT, lc, "define alignment"), root_1);
				adaptor.addChild(root_1, stream_integer.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "aligndef"


	public static class tokendef_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "tokendef"
	// ghidra/sleigh/grammar/SleighParser.g:68:1: tokendef : lc= KEY_DEFINE KEY_TOKEN identifier LPAREN integer rp= RPAREN fielddefs[$rp] -> ^( OP_TOKEN[$lc, \"define token\"] identifier integer fielddefs ) ;
	public final SleighParser.tokendef_return tokendef() throws RecognitionException {
		SleighParser.tokendef_return retval = new SleighParser.tokendef_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token rp=null;
		Token KEY_TOKEN23=null;
		Token LPAREN25=null;
		ParserRuleReturnScope identifier24 =null;
		ParserRuleReturnScope integer26 =null;
		ParserRuleReturnScope fielddefs27 =null;

		CommonTree lc_tree=null;
		CommonTree rp_tree=null;
		CommonTree KEY_TOKEN23_tree=null;
		CommonTree LPAREN25_tree=null;
		RewriteRuleTokenStream stream_KEY_TOKEN=new RewriteRuleTokenStream(adaptor,"token KEY_TOKEN");
		RewriteRuleTokenStream stream_LPAREN=new RewriteRuleTokenStream(adaptor,"token LPAREN");
		RewriteRuleTokenStream stream_RPAREN=new RewriteRuleTokenStream(adaptor,"token RPAREN");
		RewriteRuleTokenStream stream_KEY_DEFINE=new RewriteRuleTokenStream(adaptor,"token KEY_DEFINE");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_fielddefs=new RewriteRuleSubtreeStream(adaptor,"rule fielddefs");
		RewriteRuleSubtreeStream stream_integer=new RewriteRuleSubtreeStream(adaptor,"rule integer");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:69:2: (lc= KEY_DEFINE KEY_TOKEN identifier LPAREN integer rp= RPAREN fielddefs[$rp] -> ^( OP_TOKEN[$lc, \"define token\"] identifier integer fielddefs ) )
			// ghidra/sleigh/grammar/SleighParser.g:69:4: lc= KEY_DEFINE KEY_TOKEN identifier LPAREN integer rp= RPAREN fielddefs[$rp]
			{
			lc=(Token)match(input,KEY_DEFINE,FOLLOW_KEY_DEFINE_in_tokendef259); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_DEFINE.add(lc);

			KEY_TOKEN23=(Token)match(input,KEY_TOKEN,FOLLOW_KEY_TOKEN_in_tokendef261); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_TOKEN.add(KEY_TOKEN23);

			pushFollow(FOLLOW_identifier_in_tokendef263);
			identifier24=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifier.add(identifier24.getTree());
			LPAREN25=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_tokendef265); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_LPAREN.add(LPAREN25);

			pushFollow(FOLLOW_integer_in_tokendef267);
			integer26=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(integer26.getTree());
			rp=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_tokendef271); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_RPAREN.add(rp);

			pushFollow(FOLLOW_fielddefs_in_tokendef273);
			fielddefs27=fielddefs(rp);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_fielddefs.add(fielddefs27.getTree());
			// AST REWRITE
			// elements: integer, identifier, fielddefs
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 69:79: -> ^( OP_TOKEN[$lc, \"define token\"] identifier integer fielddefs )
			{
				// ghidra/sleigh/grammar/SleighParser.g:69:82: ^( OP_TOKEN[$lc, \"define token\"] identifier integer fielddefs )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_TOKEN, lc, "define token"), root_1);
				adaptor.addChild(root_1, stream_identifier.nextTree());
				adaptor.addChild(root_1, stream_integer.nextTree());
				adaptor.addChild(root_1, stream_fielddefs.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "tokendef"


	public static class fielddefs_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "fielddefs"
	// ghidra/sleigh/grammar/SleighParser.g:72:1: fielddefs[Token lc] : ( fielddef )* -> ^( OP_FIELDDEFS[lc, \"field definitions\"] ( fielddef )* ) ;
	public final SleighParser.fielddefs_return fielddefs(Token lc) throws RecognitionException {
		SleighParser.fielddefs_return retval = new SleighParser.fielddefs_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope fielddef28 =null;

		RewriteRuleSubtreeStream stream_fielddef=new RewriteRuleSubtreeStream(adaptor,"rule fielddef");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:73:2: ( ( fielddef )* -> ^( OP_FIELDDEFS[lc, \"field definitions\"] ( fielddef )* ) )
			// ghidra/sleigh/grammar/SleighParser.g:73:4: ( fielddef )*
			{
			// ghidra/sleigh/grammar/SleighParser.g:73:4: ( fielddef )*
			loop4:
			while (true) {
				int alt4=2;
				int LA4_0 = input.LA(1);
				if ( (LA4_0==IDENTIFIER) ) {
					alt4=1;
				}

				switch (alt4) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:73:4: fielddef
					{
					pushFollow(FOLLOW_fielddef_in_fielddefs299);
					fielddef28=fielddef();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_fielddef.add(fielddef28.getTree());
					}
					break;

				default :
					break loop4;
				}
			}

			// AST REWRITE
			// elements: fielddef
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 73:14: -> ^( OP_FIELDDEFS[lc, \"field definitions\"] ( fielddef )* )
			{
				// ghidra/sleigh/grammar/SleighParser.g:73:17: ^( OP_FIELDDEFS[lc, \"field definitions\"] ( fielddef )* )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FIELDDEFS, lc, "field definitions"), root_1);
				// ghidra/sleigh/grammar/SleighParser.g:73:57: ( fielddef )*
				while ( stream_fielddef.hasNext() ) {
					adaptor.addChild(root_1, stream_fielddef.nextTree());
				}
				stream_fielddef.reset();

				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "fielddefs"


	public static class fielddef_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "fielddef"
	// ghidra/sleigh/grammar/SleighParser.g:76:1: fielddef : strict_id lc= ASSIGN LPAREN s= integer COMMA e= integer rp= RPAREN fieldmods[$rp] -> ^( OP_FIELDDEF[$lc, \"field definition\"] strict_id $s $e fieldmods ) ;
	public final SleighParser.fielddef_return fielddef() throws RecognitionException {
		SleighParser.fielddef_return retval = new SleighParser.fielddef_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token rp=null;
		Token LPAREN30=null;
		Token COMMA31=null;
		ParserRuleReturnScope s =null;
		ParserRuleReturnScope e =null;
		ParserRuleReturnScope strict_id29 =null;
		ParserRuleReturnScope fieldmods32 =null;

		CommonTree lc_tree=null;
		CommonTree rp_tree=null;
		CommonTree LPAREN30_tree=null;
		CommonTree COMMA31_tree=null;
		RewriteRuleTokenStream stream_COMMA=new RewriteRuleTokenStream(adaptor,"token COMMA");
		RewriteRuleTokenStream stream_LPAREN=new RewriteRuleTokenStream(adaptor,"token LPAREN");
		RewriteRuleTokenStream stream_RPAREN=new RewriteRuleTokenStream(adaptor,"token RPAREN");
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleSubtreeStream stream_strict_id=new RewriteRuleSubtreeStream(adaptor,"rule strict_id");
		RewriteRuleSubtreeStream stream_integer=new RewriteRuleSubtreeStream(adaptor,"rule integer");
		RewriteRuleSubtreeStream stream_fieldmods=new RewriteRuleSubtreeStream(adaptor,"rule fieldmods");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:77:2: ( strict_id lc= ASSIGN LPAREN s= integer COMMA e= integer rp= RPAREN fieldmods[$rp] -> ^( OP_FIELDDEF[$lc, \"field definition\"] strict_id $s $e fieldmods ) )
			// ghidra/sleigh/grammar/SleighParser.g:77:4: strict_id lc= ASSIGN LPAREN s= integer COMMA e= integer rp= RPAREN fieldmods[$rp]
			{
			pushFollow(FOLLOW_strict_id_in_fielddef321);
			strict_id29=strict_id();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_strict_id.add(strict_id29.getTree());
			lc=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_fielddef325); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_ASSIGN.add(lc);

			LPAREN30=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_fielddef327); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_LPAREN.add(LPAREN30);

			pushFollow(FOLLOW_integer_in_fielddef331);
			s=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(s.getTree());
			COMMA31=(Token)match(input,COMMA,FOLLOW_COMMA_in_fielddef333); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_COMMA.add(COMMA31);

			pushFollow(FOLLOW_integer_in_fielddef337);
			e=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(e.getTree());
			rp=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_fielddef341); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_RPAREN.add(rp);

			pushFollow(FOLLOW_fieldmods_in_fielddef343);
			fieldmods32=fieldmods(rp);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_fieldmods.add(fieldmods32.getTree());
			// AST REWRITE
			// elements: s, fieldmods, strict_id, e
			// token labels: 
			// rule labels: s, e, retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_s=new RewriteRuleSubtreeStream(adaptor,"rule s",s!=null?s.getTree():null);
			RewriteRuleSubtreeStream stream_e=new RewriteRuleSubtreeStream(adaptor,"rule e",e!=null?e.getTree():null);
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 77:82: -> ^( OP_FIELDDEF[$lc, \"field definition\"] strict_id $s $e fieldmods )
			{
				// ghidra/sleigh/grammar/SleighParser.g:77:85: ^( OP_FIELDDEF[$lc, \"field definition\"] strict_id $s $e fieldmods )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FIELDDEF, lc, "field definition"), root_1);
				adaptor.addChild(root_1, stream_strict_id.nextTree());
				adaptor.addChild(root_1, stream_s.nextTree());
				adaptor.addChild(root_1, stream_e.nextTree());
				adaptor.addChild(root_1, stream_fieldmods.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "fielddef"


	public static class fieldmods_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "fieldmods"
	// ghidra/sleigh/grammar/SleighParser.g:80:1: fieldmods[Token it] : ( ( fieldmod )+ -> ^( OP_FIELD_MODS[it, \"field modifiers\"] ( fieldmod )+ ) | -> OP_NO_FIELD_MOD[it, \"<no field mod>\"] );
	public final SleighParser.fieldmods_return fieldmods(Token it) throws RecognitionException {
		SleighParser.fieldmods_return retval = new SleighParser.fieldmods_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope fieldmod33 =null;

		RewriteRuleSubtreeStream stream_fieldmod=new RewriteRuleSubtreeStream(adaptor,"rule fieldmod");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:81:2: ( ( fieldmod )+ -> ^( OP_FIELD_MODS[it, \"field modifiers\"] ( fieldmod )+ ) | -> OP_NO_FIELD_MOD[it, \"<no field mod>\"] )
			int alt6=2;
			int LA6_0 = input.LA(1);
			if ( (LA6_0==KEY_DEC||LA6_0==KEY_HEX||LA6_0==KEY_SIGNED) ) {
				alt6=1;
			}
			else if ( (LA6_0==IDENTIFIER||LA6_0==SEMI) ) {
				alt6=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 6, 0, input);
				throw nvae;
			}

			switch (alt6) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:81:4: ( fieldmod )+
					{
					// ghidra/sleigh/grammar/SleighParser.g:81:4: ( fieldmod )+
					int cnt5=0;
					loop5:
					while (true) {
						int alt5=2;
						int LA5_0 = input.LA(1);
						if ( (LA5_0==KEY_DEC||LA5_0==KEY_HEX||LA5_0==KEY_SIGNED) ) {
							alt5=1;
						}

						switch (alt5) {
						case 1 :
							// ghidra/sleigh/grammar/SleighParser.g:81:4: fieldmod
							{
							pushFollow(FOLLOW_fieldmod_in_fieldmods373);
							fieldmod33=fieldmod();
							state._fsp--;
							if (state.failed) return retval;
							if ( state.backtracking==0 ) stream_fieldmod.add(fieldmod33.getTree());
							}
							break;

						default :
							if ( cnt5 >= 1 ) break loop5;
							if (state.backtracking>0) {state.failed=true; return retval;}
							EarlyExitException eee = new EarlyExitException(5, input);
							throw eee;
						}
						cnt5++;
					}

					// AST REWRITE
					// elements: fieldmod
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 81:14: -> ^( OP_FIELD_MODS[it, \"field modifiers\"] ( fieldmod )+ )
					{
						// ghidra/sleigh/grammar/SleighParser.g:81:17: ^( OP_FIELD_MODS[it, \"field modifiers\"] ( fieldmod )+ )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FIELD_MODS, it, "field modifiers"), root_1);
						if ( !(stream_fieldmod.hasNext()) ) {
							throw new RewriteEarlyExitException();
						}
						while ( stream_fieldmod.hasNext() ) {
							adaptor.addChild(root_1, stream_fieldmod.nextTree());
						}
						stream_fieldmod.reset();

						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:82:4: 
					{
					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 82:4: -> OP_NO_FIELD_MOD[it, \"<no field mod>\"]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_NO_FIELD_MOD, it, "<no field mod>"));
					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "fieldmods"


	public static class fieldmod_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "fieldmod"
	// ghidra/sleigh/grammar/SleighParser.g:85:1: fieldmod : (lc= KEY_SIGNED -> OP_SIGNED[$lc] |lc= KEY_HEX -> OP_HEX[$lc] |lc= KEY_DEC -> OP_DEC[$lc] );
	public final SleighParser.fieldmod_return fieldmod() throws RecognitionException {
		SleighParser.fieldmod_return retval = new SleighParser.fieldmod_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_KEY_DEC=new RewriteRuleTokenStream(adaptor,"token KEY_DEC");
		RewriteRuleTokenStream stream_KEY_SIGNED=new RewriteRuleTokenStream(adaptor,"token KEY_SIGNED");
		RewriteRuleTokenStream stream_KEY_HEX=new RewriteRuleTokenStream(adaptor,"token KEY_HEX");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:86:5: (lc= KEY_SIGNED -> OP_SIGNED[$lc] |lc= KEY_HEX -> OP_HEX[$lc] |lc= KEY_DEC -> OP_DEC[$lc] )
			int alt7=3;
			switch ( input.LA(1) ) {
			case KEY_SIGNED:
				{
				alt7=1;
				}
				break;
			case KEY_HEX:
				{
				alt7=2;
				}
				break;
			case KEY_DEC:
				{
				alt7=3;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 7, 0, input);
				throw nvae;
			}
			switch (alt7) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:86:9: lc= KEY_SIGNED
					{
					lc=(Token)match(input,KEY_SIGNED,FOLLOW_KEY_SIGNED_in_fieldmod410); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_SIGNED.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 86:23: -> OP_SIGNED[$lc]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_SIGNED, lc));
					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:87:9: lc= KEY_HEX
					{
					lc=(Token)match(input,KEY_HEX,FOLLOW_KEY_HEX_in_fieldmod427); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_HEX.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 87:20: -> OP_HEX[$lc]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_HEX, lc));
					}


					retval.tree = root_0;
					}

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighParser.g:88:9: lc= KEY_DEC
					{
					lc=(Token)match(input,KEY_DEC,FOLLOW_KEY_DEC_in_fieldmod444); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_DEC.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 88:20: -> OP_DEC[$lc]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_DEC, lc));
					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "fieldmod"


	public static class contextfielddefs_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "contextfielddefs"
	// ghidra/sleigh/grammar/SleighParser.g:91:1: contextfielddefs[Token lc] : ( contextfielddef )* -> ^( OP_FIELDDEFS[lc, \"field definitions\"] ( contextfielddef )* ) ;
	public final SleighParser.contextfielddefs_return contextfielddefs(Token lc) throws RecognitionException {
		SleighParser.contextfielddefs_return retval = new SleighParser.contextfielddefs_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope contextfielddef34 =null;

		RewriteRuleSubtreeStream stream_contextfielddef=new RewriteRuleSubtreeStream(adaptor,"rule contextfielddef");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:92:2: ( ( contextfielddef )* -> ^( OP_FIELDDEFS[lc, \"field definitions\"] ( contextfielddef )* ) )
			// ghidra/sleigh/grammar/SleighParser.g:92:4: ( contextfielddef )*
			{
			// ghidra/sleigh/grammar/SleighParser.g:92:4: ( contextfielddef )*
			loop8:
			while (true) {
				int alt8=2;
				int LA8_0 = input.LA(1);
				if ( ((LA8_0 >= IDENTIFIER && LA8_0 <= KEY_WORDSIZE)) ) {
					alt8=1;
				}

				switch (alt8) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:92:4: contextfielddef
					{
					pushFollow(FOLLOW_contextfielddef_in_contextfielddefs464);
					contextfielddef34=contextfielddef();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_contextfielddef.add(contextfielddef34.getTree());
					}
					break;

				default :
					break loop8;
				}
			}

			// AST REWRITE
			// elements: contextfielddef
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 92:21: -> ^( OP_FIELDDEFS[lc, \"field definitions\"] ( contextfielddef )* )
			{
				// ghidra/sleigh/grammar/SleighParser.g:92:24: ^( OP_FIELDDEFS[lc, \"field definitions\"] ( contextfielddef )* )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FIELDDEFS, lc, "field definitions"), root_1);
				// ghidra/sleigh/grammar/SleighParser.g:92:64: ( contextfielddef )*
				while ( stream_contextfielddef.hasNext() ) {
					adaptor.addChild(root_1, stream_contextfielddef.nextTree());
				}
				stream_contextfielddef.reset();

				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "contextfielddefs"


	public static class contextfielddef_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "contextfielddef"
	// ghidra/sleigh/grammar/SleighParser.g:95:1: contextfielddef : identifier lc= ASSIGN LPAREN s= integer COMMA e= integer rp= RPAREN contextfieldmods[$rp] -> ^( OP_FIELDDEF[$lc, \"field definition\"] identifier $s $e contextfieldmods ) ;
	public final SleighParser.contextfielddef_return contextfielddef() throws RecognitionException {
		SleighParser.contextfielddef_return retval = new SleighParser.contextfielddef_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token rp=null;
		Token LPAREN36=null;
		Token COMMA37=null;
		ParserRuleReturnScope s =null;
		ParserRuleReturnScope e =null;
		ParserRuleReturnScope identifier35 =null;
		ParserRuleReturnScope contextfieldmods38 =null;

		CommonTree lc_tree=null;
		CommonTree rp_tree=null;
		CommonTree LPAREN36_tree=null;
		CommonTree COMMA37_tree=null;
		RewriteRuleTokenStream stream_COMMA=new RewriteRuleTokenStream(adaptor,"token COMMA");
		RewriteRuleTokenStream stream_LPAREN=new RewriteRuleTokenStream(adaptor,"token LPAREN");
		RewriteRuleTokenStream stream_RPAREN=new RewriteRuleTokenStream(adaptor,"token RPAREN");
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_contextfieldmods=new RewriteRuleSubtreeStream(adaptor,"rule contextfieldmods");
		RewriteRuleSubtreeStream stream_integer=new RewriteRuleSubtreeStream(adaptor,"rule integer");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:96:2: ( identifier lc= ASSIGN LPAREN s= integer COMMA e= integer rp= RPAREN contextfieldmods[$rp] -> ^( OP_FIELDDEF[$lc, \"field definition\"] identifier $s $e contextfieldmods ) )
			// ghidra/sleigh/grammar/SleighParser.g:96:4: identifier lc= ASSIGN LPAREN s= integer COMMA e= integer rp= RPAREN contextfieldmods[$rp]
			{
			pushFollow(FOLLOW_identifier_in_contextfielddef486);
			identifier35=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifier.add(identifier35.getTree());
			lc=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_contextfielddef490); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_ASSIGN.add(lc);

			LPAREN36=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_contextfielddef492); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_LPAREN.add(LPAREN36);

			pushFollow(FOLLOW_integer_in_contextfielddef496);
			s=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(s.getTree());
			COMMA37=(Token)match(input,COMMA,FOLLOW_COMMA_in_contextfielddef498); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_COMMA.add(COMMA37);

			pushFollow(FOLLOW_integer_in_contextfielddef502);
			e=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(e.getTree());
			rp=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_contextfielddef506); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_RPAREN.add(rp);

			pushFollow(FOLLOW_contextfieldmods_in_contextfielddef508);
			contextfieldmods38=contextfieldmods(rp);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_contextfieldmods.add(contextfieldmods38.getTree());
			// AST REWRITE
			// elements: e, identifier, contextfieldmods, s
			// token labels: 
			// rule labels: s, e, retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_s=new RewriteRuleSubtreeStream(adaptor,"rule s",s!=null?s.getTree():null);
			RewriteRuleSubtreeStream stream_e=new RewriteRuleSubtreeStream(adaptor,"rule e",e!=null?e.getTree():null);
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 96:90: -> ^( OP_FIELDDEF[$lc, \"field definition\"] identifier $s $e contextfieldmods )
			{
				// ghidra/sleigh/grammar/SleighParser.g:96:93: ^( OP_FIELDDEF[$lc, \"field definition\"] identifier $s $e contextfieldmods )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FIELDDEF, lc, "field definition"), root_1);
				adaptor.addChild(root_1, stream_identifier.nextTree());
				adaptor.addChild(root_1, stream_s.nextTree());
				adaptor.addChild(root_1, stream_e.nextTree());
				adaptor.addChild(root_1, stream_contextfieldmods.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "contextfielddef"


	public static class contextfieldmods_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "contextfieldmods"
	// ghidra/sleigh/grammar/SleighParser.g:99:1: contextfieldmods[Token it] : ( ( contextfieldmod )+ -> ^( OP_FIELD_MODS[it, \"context field modifiers\"] ( contextfieldmod )+ ) | -> OP_NO_FIELD_MOD[it, \"<no field mod>\"] );
	public final SleighParser.contextfieldmods_return contextfieldmods(Token it) throws RecognitionException {
		SleighParser.contextfieldmods_return retval = new SleighParser.contextfieldmods_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope contextfieldmod39 =null;

		RewriteRuleSubtreeStream stream_contextfieldmod=new RewriteRuleSubtreeStream(adaptor,"rule contextfieldmod");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:100:5: ( ( contextfieldmod )+ -> ^( OP_FIELD_MODS[it, \"context field modifiers\"] ( contextfieldmod )+ ) | -> OP_NO_FIELD_MOD[it, \"<no field mod>\"] )
			int alt10=2;
			switch ( input.LA(1) ) {
			case KEY_SIGNED:
				{
				int LA10_1 = input.LA(2);
				if ( ((LA10_1 >= IDENTIFIER && LA10_1 <= KEY_WORDSIZE)||LA10_1==SEMI) ) {
					alt10=1;
				}
				else if ( (LA10_1==ASSIGN) ) {
					alt10=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 10, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_NOFLOW:
				{
				int LA10_2 = input.LA(2);
				if ( ((LA10_2 >= IDENTIFIER && LA10_2 <= KEY_WORDSIZE)||LA10_2==SEMI) ) {
					alt10=1;
				}
				else if ( (LA10_2==ASSIGN) ) {
					alt10=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 10, 2, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_HEX:
				{
				int LA10_3 = input.LA(2);
				if ( ((LA10_3 >= IDENTIFIER && LA10_3 <= KEY_WORDSIZE)||LA10_3==SEMI) ) {
					alt10=1;
				}
				else if ( (LA10_3==ASSIGN) ) {
					alt10=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 10, 3, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEC:
				{
				int LA10_4 = input.LA(2);
				if ( ((LA10_4 >= IDENTIFIER && LA10_4 <= KEY_WORDSIZE)||LA10_4==SEMI) ) {
					alt10=1;
				}
				else if ( (LA10_4==ASSIGN) ) {
					alt10=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 10, 4, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case IDENTIFIER:
			case KEY_ALIGNMENT:
			case KEY_ATTACH:
			case KEY_BIG:
			case KEY_BITRANGE:
			case KEY_BUILD:
			case KEY_CALL:
			case KEY_CONTEXT:
			case KEY_CROSSBUILD:
			case KEY_DEFAULT:
			case KEY_DEFINE:
			case KEY_ENDIAN:
			case KEY_EXPORT:
			case KEY_GOTO:
			case KEY_LITTLE:
			case KEY_LOCAL:
			case KEY_MACRO:
			case KEY_NAMES:
			case KEY_OFFSET:
			case KEY_PCODEOP:
			case KEY_RETURN:
			case KEY_SIZE:
			case KEY_SPACE:
			case KEY_TOKEN:
			case KEY_TYPE:
			case KEY_UNIMPL:
			case KEY_VALUES:
			case KEY_VARIABLES:
			case KEY_WORDSIZE:
			case SEMI:
				{
				alt10=2;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 10, 0, input);
				throw nvae;
			}
			switch (alt10) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:100:9: ( contextfieldmod )+
					{
					// ghidra/sleigh/grammar/SleighParser.g:100:9: ( contextfieldmod )+
					int cnt9=0;
					loop9:
					while (true) {
						int alt9=2;
						switch ( input.LA(1) ) {
						case KEY_DEC:
							{
							int LA9_2 = input.LA(2);
							if ( ((LA9_2 >= IDENTIFIER && LA9_2 <= KEY_WORDSIZE)||LA9_2==SEMI) ) {
								alt9=1;
							}

							}
							break;
						case KEY_HEX:
							{
							int LA9_3 = input.LA(2);
							if ( ((LA9_3 >= IDENTIFIER && LA9_3 <= KEY_WORDSIZE)||LA9_3==SEMI) ) {
								alt9=1;
							}

							}
							break;
						case KEY_NOFLOW:
							{
							int LA9_4 = input.LA(2);
							if ( ((LA9_4 >= IDENTIFIER && LA9_4 <= KEY_WORDSIZE)||LA9_4==SEMI) ) {
								alt9=1;
							}

							}
							break;
						case KEY_SIGNED:
							{
							int LA9_5 = input.LA(2);
							if ( ((LA9_5 >= IDENTIFIER && LA9_5 <= KEY_WORDSIZE)||LA9_5==SEMI) ) {
								alt9=1;
							}

							}
							break;
						}
						switch (alt9) {
						case 1 :
							// ghidra/sleigh/grammar/SleighParser.g:100:9: contextfieldmod
							{
							pushFollow(FOLLOW_contextfieldmod_in_contextfieldmods543);
							contextfieldmod39=contextfieldmod();
							state._fsp--;
							if (state.failed) return retval;
							if ( state.backtracking==0 ) stream_contextfieldmod.add(contextfieldmod39.getTree());
							}
							break;

						default :
							if ( cnt9 >= 1 ) break loop9;
							if (state.backtracking>0) {state.failed=true; return retval;}
							EarlyExitException eee = new EarlyExitException(9, input);
							throw eee;
						}
						cnt9++;
					}

					// AST REWRITE
					// elements: contextfieldmod
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 100:26: -> ^( OP_FIELD_MODS[it, \"context field modifiers\"] ( contextfieldmod )+ )
					{
						// ghidra/sleigh/grammar/SleighParser.g:100:29: ^( OP_FIELD_MODS[it, \"context field modifiers\"] ( contextfieldmod )+ )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FIELD_MODS, it, "context field modifiers"), root_1);
						if ( !(stream_contextfieldmod.hasNext()) ) {
							throw new RewriteEarlyExitException();
						}
						while ( stream_contextfieldmod.hasNext() ) {
							adaptor.addChild(root_1, stream_contextfieldmod.nextTree());
						}
						stream_contextfieldmod.reset();

						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:101:9: 
					{
					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 101:9: -> OP_NO_FIELD_MOD[it, \"<no field mod>\"]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_NO_FIELD_MOD, it, "<no field mod>"));
					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "contextfieldmods"


	public static class contextfieldmod_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "contextfieldmod"
	// ghidra/sleigh/grammar/SleighParser.g:104:1: contextfieldmod : (lc= KEY_SIGNED -> OP_SIGNED[$lc] |lc= KEY_NOFLOW -> OP_NOFLOW[$lc] |lc= KEY_HEX -> OP_HEX[$lc] |lc= KEY_DEC -> OP_DEC[$lc] );
	public final SleighParser.contextfieldmod_return contextfieldmod() throws RecognitionException {
		SleighParser.contextfieldmod_return retval = new SleighParser.contextfieldmod_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_KEY_DEC=new RewriteRuleTokenStream(adaptor,"token KEY_DEC");
		RewriteRuleTokenStream stream_KEY_SIGNED=new RewriteRuleTokenStream(adaptor,"token KEY_SIGNED");
		RewriteRuleTokenStream stream_KEY_NOFLOW=new RewriteRuleTokenStream(adaptor,"token KEY_NOFLOW");
		RewriteRuleTokenStream stream_KEY_HEX=new RewriteRuleTokenStream(adaptor,"token KEY_HEX");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:105:5: (lc= KEY_SIGNED -> OP_SIGNED[$lc] |lc= KEY_NOFLOW -> OP_NOFLOW[$lc] |lc= KEY_HEX -> OP_HEX[$lc] |lc= KEY_DEC -> OP_DEC[$lc] )
			int alt11=4;
			switch ( input.LA(1) ) {
			case KEY_SIGNED:
				{
				alt11=1;
				}
				break;
			case KEY_NOFLOW:
				{
				alt11=2;
				}
				break;
			case KEY_HEX:
				{
				alt11=3;
				}
				break;
			case KEY_DEC:
				{
				alt11=4;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 11, 0, input);
				throw nvae;
			}
			switch (alt11) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:105:9: lc= KEY_SIGNED
					{
					lc=(Token)match(input,KEY_SIGNED,FOLLOW_KEY_SIGNED_in_contextfieldmod588); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_SIGNED.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 105:23: -> OP_SIGNED[$lc]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_SIGNED, lc));
					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:106:9: lc= KEY_NOFLOW
					{
					lc=(Token)match(input,KEY_NOFLOW,FOLLOW_KEY_NOFLOW_in_contextfieldmod605); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_NOFLOW.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 106:23: -> OP_NOFLOW[$lc]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_NOFLOW, lc));
					}


					retval.tree = root_0;
					}

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighParser.g:107:9: lc= KEY_HEX
					{
					lc=(Token)match(input,KEY_HEX,FOLLOW_KEY_HEX_in_contextfieldmod622); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_HEX.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 107:20: -> OP_HEX[$lc]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_HEX, lc));
					}


					retval.tree = root_0;
					}

					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighParser.g:108:9: lc= KEY_DEC
					{
					lc=(Token)match(input,KEY_DEC,FOLLOW_KEY_DEC_in_contextfieldmod639); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_DEC.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 108:20: -> OP_DEC[$lc]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_DEC, lc));
					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "contextfieldmod"


	public static class contextdef_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "contextdef"
	// ghidra/sleigh/grammar/SleighParser.g:111:1: contextdef : lc= KEY_DEFINE rp= KEY_CONTEXT identifier contextfielddefs[$rp] -> ^( OP_CONTEXT[$lc, \"define context\"] identifier contextfielddefs ) ;
	public final SleighParser.contextdef_return contextdef() throws RecognitionException {
		SleighParser.contextdef_return retval = new SleighParser.contextdef_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token rp=null;
		ParserRuleReturnScope identifier40 =null;
		ParserRuleReturnScope contextfielddefs41 =null;

		CommonTree lc_tree=null;
		CommonTree rp_tree=null;
		RewriteRuleTokenStream stream_KEY_CONTEXT=new RewriteRuleTokenStream(adaptor,"token KEY_CONTEXT");
		RewriteRuleTokenStream stream_KEY_DEFINE=new RewriteRuleTokenStream(adaptor,"token KEY_DEFINE");
		RewriteRuleSubtreeStream stream_contextfielddefs=new RewriteRuleSubtreeStream(adaptor,"rule contextfielddefs");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:112:2: (lc= KEY_DEFINE rp= KEY_CONTEXT identifier contextfielddefs[$rp] -> ^( OP_CONTEXT[$lc, \"define context\"] identifier contextfielddefs ) )
			// ghidra/sleigh/grammar/SleighParser.g:112:4: lc= KEY_DEFINE rp= KEY_CONTEXT identifier contextfielddefs[$rp]
			{
			lc=(Token)match(input,KEY_DEFINE,FOLLOW_KEY_DEFINE_in_contextdef660); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_DEFINE.add(lc);

			rp=(Token)match(input,KEY_CONTEXT,FOLLOW_KEY_CONTEXT_in_contextdef664); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_CONTEXT.add(rp);

			pushFollow(FOLLOW_identifier_in_contextdef666);
			identifier40=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifier.add(identifier40.getTree());
			pushFollow(FOLLOW_contextfielddefs_in_contextdef668);
			contextfielddefs41=contextfielddefs(rp);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_contextfielddefs.add(contextfielddefs41.getTree());
			// AST REWRITE
			// elements: identifier, contextfielddefs
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 112:66: -> ^( OP_CONTEXT[$lc, \"define context\"] identifier contextfielddefs )
			{
				// ghidra/sleigh/grammar/SleighParser.g:112:69: ^( OP_CONTEXT[$lc, \"define context\"] identifier contextfielddefs )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_CONTEXT, lc, "define context"), root_1);
				adaptor.addChild(root_1, stream_identifier.nextTree());
				adaptor.addChild(root_1, stream_contextfielddefs.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "contextdef"


	public static class spacedef_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "spacedef"
	// ghidra/sleigh/grammar/SleighParser.g:115:1: spacedef : lc= KEY_DEFINE KEY_SPACE identifier spacemods[$lc] -> ^( OP_SPACE[$lc, \"define space\"] identifier spacemods ) ;
	public final SleighParser.spacedef_return spacedef() throws RecognitionException {
		SleighParser.spacedef_return retval = new SleighParser.spacedef_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token KEY_SPACE42=null;
		ParserRuleReturnScope identifier43 =null;
		ParserRuleReturnScope spacemods44 =null;

		CommonTree lc_tree=null;
		CommonTree KEY_SPACE42_tree=null;
		RewriteRuleTokenStream stream_KEY_SPACE=new RewriteRuleTokenStream(adaptor,"token KEY_SPACE");
		RewriteRuleTokenStream stream_KEY_DEFINE=new RewriteRuleTokenStream(adaptor,"token KEY_DEFINE");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_spacemods=new RewriteRuleSubtreeStream(adaptor,"rule spacemods");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:116:2: (lc= KEY_DEFINE KEY_SPACE identifier spacemods[$lc] -> ^( OP_SPACE[$lc, \"define space\"] identifier spacemods ) )
			// ghidra/sleigh/grammar/SleighParser.g:116:4: lc= KEY_DEFINE KEY_SPACE identifier spacemods[$lc]
			{
			lc=(Token)match(input,KEY_DEFINE,FOLLOW_KEY_DEFINE_in_spacedef693); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_DEFINE.add(lc);

			KEY_SPACE42=(Token)match(input,KEY_SPACE,FOLLOW_KEY_SPACE_in_spacedef695); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_SPACE.add(KEY_SPACE42);

			pushFollow(FOLLOW_identifier_in_spacedef697);
			identifier43=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifier.add(identifier43.getTree());
			pushFollow(FOLLOW_spacemods_in_spacedef699);
			spacemods44=spacemods(lc);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_spacemods.add(spacemods44.getTree());
			// AST REWRITE
			// elements: spacemods, identifier
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 116:54: -> ^( OP_SPACE[$lc, \"define space\"] identifier spacemods )
			{
				// ghidra/sleigh/grammar/SleighParser.g:116:57: ^( OP_SPACE[$lc, \"define space\"] identifier spacemods )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SPACE, lc, "define space"), root_1);
				adaptor.addChild(root_1, stream_identifier.nextTree());
				adaptor.addChild(root_1, stream_spacemods.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "spacedef"


	public static class spacemods_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "spacemods"
	// ghidra/sleigh/grammar/SleighParser.g:119:1: spacemods[Token lc] : ( spacemod )* -> ^( OP_SPACEMODS[$lc, \"space modifier\"] ( spacemod )* ) ;
	public final SleighParser.spacemods_return spacemods(Token lc) throws RecognitionException {
		SleighParser.spacemods_return retval = new SleighParser.spacemods_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope spacemod45 =null;

		RewriteRuleSubtreeStream stream_spacemod=new RewriteRuleSubtreeStream(adaptor,"rule spacemod");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:120:2: ( ( spacemod )* -> ^( OP_SPACEMODS[$lc, \"space modifier\"] ( spacemod )* ) )
			// ghidra/sleigh/grammar/SleighParser.g:120:4: ( spacemod )*
			{
			// ghidra/sleigh/grammar/SleighParser.g:120:4: ( spacemod )*
			loop12:
			while (true) {
				int alt12=2;
				int LA12_0 = input.LA(1);
				if ( (LA12_0==KEY_DEFAULT||LA12_0==KEY_SIZE||LA12_0==KEY_TYPE||LA12_0==KEY_WORDSIZE) ) {
					alt12=1;
				}

				switch (alt12) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:120:4: spacemod
					{
					pushFollow(FOLLOW_spacemod_in_spacemods723);
					spacemod45=spacemod();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_spacemod.add(spacemod45.getTree());
					}
					break;

				default :
					break loop12;
				}
			}

			// AST REWRITE
			// elements: spacemod
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 120:14: -> ^( OP_SPACEMODS[$lc, \"space modifier\"] ( spacemod )* )
			{
				// ghidra/sleigh/grammar/SleighParser.g:120:17: ^( OP_SPACEMODS[$lc, \"space modifier\"] ( spacemod )* )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SPACEMODS, lc, "space modifier"), root_1);
				// ghidra/sleigh/grammar/SleighParser.g:120:55: ( spacemod )*
				while ( stream_spacemod.hasNext() ) {
					adaptor.addChild(root_1, stream_spacemod.nextTree());
				}
				stream_spacemod.reset();

				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "spacemods"


	public static class spacemod_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "spacemod"
	// ghidra/sleigh/grammar/SleighParser.g:123:1: spacemod : ( typemod | sizemod | wordsizemod |lc= KEY_DEFAULT -> OP_DEFAULT[$lc] );
	public final SleighParser.spacemod_return spacemod() throws RecognitionException {
		SleighParser.spacemod_return retval = new SleighParser.spacemod_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		ParserRuleReturnScope typemod46 =null;
		ParserRuleReturnScope sizemod47 =null;
		ParserRuleReturnScope wordsizemod48 =null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_KEY_DEFAULT=new RewriteRuleTokenStream(adaptor,"token KEY_DEFAULT");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:124:2: ( typemod | sizemod | wordsizemod |lc= KEY_DEFAULT -> OP_DEFAULT[$lc] )
			int alt13=4;
			switch ( input.LA(1) ) {
			case KEY_TYPE:
				{
				alt13=1;
				}
				break;
			case KEY_SIZE:
				{
				alt13=2;
				}
				break;
			case KEY_WORDSIZE:
				{
				alt13=3;
				}
				break;
			case KEY_DEFAULT:
				{
				alt13=4;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 13, 0, input);
				throw nvae;
			}
			switch (alt13) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:124:4: typemod
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_typemod_in_spacemod745);
					typemod46=typemod();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, typemod46.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:125:4: sizemod
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_sizemod_in_spacemod750);
					sizemod47=sizemod();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, sizemod47.getTree());

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighParser.g:126:4: wordsizemod
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_wordsizemod_in_spacemod755);
					wordsizemod48=wordsizemod();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, wordsizemod48.getTree());

					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighParser.g:127:4: lc= KEY_DEFAULT
					{
					lc=(Token)match(input,KEY_DEFAULT,FOLLOW_KEY_DEFAULT_in_spacemod762); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_DEFAULT.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 127:19: -> OP_DEFAULT[$lc]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_DEFAULT, lc));
					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "spacemod"


	public static class typemod_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "typemod"
	// ghidra/sleigh/grammar/SleighParser.g:130:1: typemod : lc= KEY_TYPE ASSIGN type -> ^( OP_TYPE[$lc] type ) ;
	public final SleighParser.typemod_return typemod() throws RecognitionException {
		SleighParser.typemod_return retval = new SleighParser.typemod_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token ASSIGN49=null;
		ParserRuleReturnScope type50 =null;

		CommonTree lc_tree=null;
		CommonTree ASSIGN49_tree=null;
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleTokenStream stream_KEY_TYPE=new RewriteRuleTokenStream(adaptor,"token KEY_TYPE");
		RewriteRuleSubtreeStream stream_type=new RewriteRuleSubtreeStream(adaptor,"rule type");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:131:2: (lc= KEY_TYPE ASSIGN type -> ^( OP_TYPE[$lc] type ) )
			// ghidra/sleigh/grammar/SleighParser.g:131:4: lc= KEY_TYPE ASSIGN type
			{
			lc=(Token)match(input,KEY_TYPE,FOLLOW_KEY_TYPE_in_typemod780); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_TYPE.add(lc);

			ASSIGN49=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_typemod782); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_ASSIGN.add(ASSIGN49);

			pushFollow(FOLLOW_type_in_typemod784);
			type50=type();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_type.add(type50.getTree());
			// AST REWRITE
			// elements: type
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 131:28: -> ^( OP_TYPE[$lc] type )
			{
				// ghidra/sleigh/grammar/SleighParser.g:131:31: ^( OP_TYPE[$lc] type )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_TYPE, lc), root_1);
				adaptor.addChild(root_1, stream_type.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "typemod"


	public static class type_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "type"
	// ghidra/sleigh/grammar/SleighParser.g:134:1: type : identifier ;
	public final SleighParser.type_return type() throws RecognitionException {
		SleighParser.type_return retval = new SleighParser.type_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope identifier51 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:135:2: ( identifier )
			// ghidra/sleigh/grammar/SleighParser.g:135:4: identifier
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_identifier_in_type804);
			identifier51=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, identifier51.getTree());

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "type"


	public static class sizemod_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "sizemod"
	// ghidra/sleigh/grammar/SleighParser.g:138:1: sizemod : lc= KEY_SIZE ASSIGN integer -> ^( OP_SIZE[$lc] integer ) ;
	public final SleighParser.sizemod_return sizemod() throws RecognitionException {
		SleighParser.sizemod_return retval = new SleighParser.sizemod_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token ASSIGN52=null;
		ParserRuleReturnScope integer53 =null;

		CommonTree lc_tree=null;
		CommonTree ASSIGN52_tree=null;
		RewriteRuleTokenStream stream_KEY_SIZE=new RewriteRuleTokenStream(adaptor,"token KEY_SIZE");
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleSubtreeStream stream_integer=new RewriteRuleSubtreeStream(adaptor,"rule integer");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:139:2: (lc= KEY_SIZE ASSIGN integer -> ^( OP_SIZE[$lc] integer ) )
			// ghidra/sleigh/grammar/SleighParser.g:139:4: lc= KEY_SIZE ASSIGN integer
			{
			lc=(Token)match(input,KEY_SIZE,FOLLOW_KEY_SIZE_in_sizemod817); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_SIZE.add(lc);

			ASSIGN52=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_sizemod819); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_ASSIGN.add(ASSIGN52);

			pushFollow(FOLLOW_integer_in_sizemod821);
			integer53=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(integer53.getTree());
			// AST REWRITE
			// elements: integer
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 139:31: -> ^( OP_SIZE[$lc] integer )
			{
				// ghidra/sleigh/grammar/SleighParser.g:139:34: ^( OP_SIZE[$lc] integer )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SIZE, lc), root_1);
				adaptor.addChild(root_1, stream_integer.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "sizemod"


	public static class wordsizemod_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "wordsizemod"
	// ghidra/sleigh/grammar/SleighParser.g:142:1: wordsizemod : lc= KEY_WORDSIZE ASSIGN integer -> ^( OP_WORDSIZE[$lc] integer ) ;
	public final SleighParser.wordsizemod_return wordsizemod() throws RecognitionException {
		SleighParser.wordsizemod_return retval = new SleighParser.wordsizemod_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token ASSIGN54=null;
		ParserRuleReturnScope integer55 =null;

		CommonTree lc_tree=null;
		CommonTree ASSIGN54_tree=null;
		RewriteRuleTokenStream stream_KEY_WORDSIZE=new RewriteRuleTokenStream(adaptor,"token KEY_WORDSIZE");
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleSubtreeStream stream_integer=new RewriteRuleSubtreeStream(adaptor,"rule integer");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:143:2: (lc= KEY_WORDSIZE ASSIGN integer -> ^( OP_WORDSIZE[$lc] integer ) )
			// ghidra/sleigh/grammar/SleighParser.g:143:4: lc= KEY_WORDSIZE ASSIGN integer
			{
			lc=(Token)match(input,KEY_WORDSIZE,FOLLOW_KEY_WORDSIZE_in_wordsizemod843); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_WORDSIZE.add(lc);

			ASSIGN54=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_wordsizemod845); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_ASSIGN.add(ASSIGN54);

			pushFollow(FOLLOW_integer_in_wordsizemod847);
			integer55=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(integer55.getTree());
			// AST REWRITE
			// elements: integer
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 143:35: -> ^( OP_WORDSIZE[$lc] integer )
			{
				// ghidra/sleigh/grammar/SleighParser.g:143:38: ^( OP_WORDSIZE[$lc] integer )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_WORDSIZE, lc), root_1);
				adaptor.addChild(root_1, stream_integer.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "wordsizemod"


	public static class varnodedef_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "varnodedef"
	// ghidra/sleigh/grammar/SleighParser.g:146:1: varnodedef : lc= KEY_DEFINE identifier KEY_OFFSET ASSIGN offset= integer KEY_SIZE rb= ASSIGN size= integer identifierlist[$rb] -> ^( OP_VARNODE[$lc, \"define varnode\"] identifier $offset $size identifierlist ) ;
	public final SleighParser.varnodedef_return varnodedef() throws RecognitionException {
		SleighParser.varnodedef_return retval = new SleighParser.varnodedef_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token rb=null;
		Token KEY_OFFSET57=null;
		Token ASSIGN58=null;
		Token KEY_SIZE59=null;
		ParserRuleReturnScope offset =null;
		ParserRuleReturnScope size =null;
		ParserRuleReturnScope identifier56 =null;
		ParserRuleReturnScope identifierlist60 =null;

		CommonTree lc_tree=null;
		CommonTree rb_tree=null;
		CommonTree KEY_OFFSET57_tree=null;
		CommonTree ASSIGN58_tree=null;
		CommonTree KEY_SIZE59_tree=null;
		RewriteRuleTokenStream stream_KEY_SIZE=new RewriteRuleTokenStream(adaptor,"token KEY_SIZE");
		RewriteRuleTokenStream stream_KEY_OFFSET=new RewriteRuleTokenStream(adaptor,"token KEY_OFFSET");
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleTokenStream stream_KEY_DEFINE=new RewriteRuleTokenStream(adaptor,"token KEY_DEFINE");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_identifierlist=new RewriteRuleSubtreeStream(adaptor,"rule identifierlist");
		RewriteRuleSubtreeStream stream_integer=new RewriteRuleSubtreeStream(adaptor,"rule integer");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:147:2: (lc= KEY_DEFINE identifier KEY_OFFSET ASSIGN offset= integer KEY_SIZE rb= ASSIGN size= integer identifierlist[$rb] -> ^( OP_VARNODE[$lc, \"define varnode\"] identifier $offset $size identifierlist ) )
			// ghidra/sleigh/grammar/SleighParser.g:147:4: lc= KEY_DEFINE identifier KEY_OFFSET ASSIGN offset= integer KEY_SIZE rb= ASSIGN size= integer identifierlist[$rb]
			{
			lc=(Token)match(input,KEY_DEFINE,FOLLOW_KEY_DEFINE_in_varnodedef869); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_DEFINE.add(lc);

			pushFollow(FOLLOW_identifier_in_varnodedef871);
			identifier56=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifier.add(identifier56.getTree());
			KEY_OFFSET57=(Token)match(input,KEY_OFFSET,FOLLOW_KEY_OFFSET_in_varnodedef873); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_OFFSET.add(KEY_OFFSET57);

			ASSIGN58=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_varnodedef875); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_ASSIGN.add(ASSIGN58);

			pushFollow(FOLLOW_integer_in_varnodedef879);
			offset=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(offset.getTree());
			KEY_SIZE59=(Token)match(input,KEY_SIZE,FOLLOW_KEY_SIZE_in_varnodedef881); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_SIZE.add(KEY_SIZE59);

			rb=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_varnodedef885); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_ASSIGN.add(rb);

			pushFollow(FOLLOW_integer_in_varnodedef889);
			size=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(size.getTree());
			pushFollow(FOLLOW_identifierlist_in_varnodedef891);
			identifierlist60=identifierlist(rb);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifierlist.add(identifierlist60.getTree());
			// AST REWRITE
			// elements: identifier, offset, size, identifierlist
			// token labels: 
			// rule labels: offset, size, retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_offset=new RewriteRuleSubtreeStream(adaptor,"rule offset",offset!=null?offset.getTree():null);
			RewriteRuleSubtreeStream stream_size=new RewriteRuleSubtreeStream(adaptor,"rule size",size!=null?size.getTree():null);
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 148:3: -> ^( OP_VARNODE[$lc, \"define varnode\"] identifier $offset $size identifierlist )
			{
				// ghidra/sleigh/grammar/SleighParser.g:148:6: ^( OP_VARNODE[$lc, \"define varnode\"] identifier $offset $size identifierlist )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_VARNODE, lc, "define varnode"), root_1);
				adaptor.addChild(root_1, stream_identifier.nextTree());
				adaptor.addChild(root_1, stream_offset.nextTree());
				adaptor.addChild(root_1, stream_size.nextTree());
				adaptor.addChild(root_1, stream_identifierlist.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "varnodedef"


	public static class bitrangedef_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "bitrangedef"
	// ghidra/sleigh/grammar/SleighParser.g:151:1: bitrangedef : lc= KEY_DEFINE KEY_BITRANGE bitranges -> ^( OP_BITRANGES[$lc, \"define bitrange\"] bitranges ) ;
	public final SleighParser.bitrangedef_return bitrangedef() throws RecognitionException {
		SleighParser.bitrangedef_return retval = new SleighParser.bitrangedef_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token KEY_BITRANGE61=null;
		ParserRuleReturnScope bitranges62 =null;

		CommonTree lc_tree=null;
		CommonTree KEY_BITRANGE61_tree=null;
		RewriteRuleTokenStream stream_KEY_BITRANGE=new RewriteRuleTokenStream(adaptor,"token KEY_BITRANGE");
		RewriteRuleTokenStream stream_KEY_DEFINE=new RewriteRuleTokenStream(adaptor,"token KEY_DEFINE");
		RewriteRuleSubtreeStream stream_bitranges=new RewriteRuleSubtreeStream(adaptor,"rule bitranges");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:152:2: (lc= KEY_DEFINE KEY_BITRANGE bitranges -> ^( OP_BITRANGES[$lc, \"define bitrange\"] bitranges ) )
			// ghidra/sleigh/grammar/SleighParser.g:152:4: lc= KEY_DEFINE KEY_BITRANGE bitranges
			{
			lc=(Token)match(input,KEY_DEFINE,FOLLOW_KEY_DEFINE_in_bitrangedef924); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_DEFINE.add(lc);

			KEY_BITRANGE61=(Token)match(input,KEY_BITRANGE,FOLLOW_KEY_BITRANGE_in_bitrangedef926); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_BITRANGE.add(KEY_BITRANGE61);

			pushFollow(FOLLOW_bitranges_in_bitrangedef928);
			bitranges62=bitranges();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_bitranges.add(bitranges62.getTree());
			// AST REWRITE
			// elements: bitranges
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 152:41: -> ^( OP_BITRANGES[$lc, \"define bitrange\"] bitranges )
			{
				// ghidra/sleigh/grammar/SleighParser.g:152:44: ^( OP_BITRANGES[$lc, \"define bitrange\"] bitranges )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_BITRANGES, lc, "define bitrange"), root_1);
				adaptor.addChild(root_1, stream_bitranges.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "bitrangedef"


	public static class bitranges_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "bitranges"
	// ghidra/sleigh/grammar/SleighParser.g:155:1: bitranges : ( bitrange )+ ;
	public final SleighParser.bitranges_return bitranges() throws RecognitionException {
		SleighParser.bitranges_return retval = new SleighParser.bitranges_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope bitrange63 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:156:2: ( ( bitrange )+ )
			// ghidra/sleigh/grammar/SleighParser.g:156:4: ( bitrange )+
			{
			root_0 = (CommonTree)adaptor.nil();


			// ghidra/sleigh/grammar/SleighParser.g:156:4: ( bitrange )+
			int cnt14=0;
			loop14:
			while (true) {
				int alt14=2;
				int LA14_0 = input.LA(1);
				if ( ((LA14_0 >= IDENTIFIER && LA14_0 <= KEY_WORDSIZE)) ) {
					alt14=1;
				}

				switch (alt14) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:156:4: bitrange
					{
					pushFollow(FOLLOW_bitrange_in_bitranges948);
					bitrange63=bitrange();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, bitrange63.getTree());

					}
					break;

				default :
					if ( cnt14 >= 1 ) break loop14;
					if (state.backtracking>0) {state.failed=true; return retval;}
					EarlyExitException eee = new EarlyExitException(14, input);
					throw eee;
				}
				cnt14++;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "bitranges"


	public static class bitrange_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "bitrange"
	// ghidra/sleigh/grammar/SleighParser.g:159:1: bitrange : a= identifier lc= ASSIGN b= identifier LBRACKET i= integer COMMA j= integer RBRACKET -> ^( OP_BITRANGE[$lc, \"bitrange definition\"] $a $b $i $j) ;
	public final SleighParser.bitrange_return bitrange() throws RecognitionException {
		SleighParser.bitrange_return retval = new SleighParser.bitrange_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token LBRACKET64=null;
		Token COMMA65=null;
		Token RBRACKET66=null;
		ParserRuleReturnScope a =null;
		ParserRuleReturnScope b =null;
		ParserRuleReturnScope i =null;
		ParserRuleReturnScope j =null;

		CommonTree lc_tree=null;
		CommonTree LBRACKET64_tree=null;
		CommonTree COMMA65_tree=null;
		CommonTree RBRACKET66_tree=null;
		RewriteRuleTokenStream stream_COMMA=new RewriteRuleTokenStream(adaptor,"token COMMA");
		RewriteRuleTokenStream stream_LBRACKET=new RewriteRuleTokenStream(adaptor,"token LBRACKET");
		RewriteRuleTokenStream stream_RBRACKET=new RewriteRuleTokenStream(adaptor,"token RBRACKET");
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_integer=new RewriteRuleSubtreeStream(adaptor,"rule integer");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:160:2: (a= identifier lc= ASSIGN b= identifier LBRACKET i= integer COMMA j= integer RBRACKET -> ^( OP_BITRANGE[$lc, \"bitrange definition\"] $a $b $i $j) )
			// ghidra/sleigh/grammar/SleighParser.g:160:4: a= identifier lc= ASSIGN b= identifier LBRACKET i= integer COMMA j= integer RBRACKET
			{
			pushFollow(FOLLOW_identifier_in_bitrange962);
			a=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifier.add(a.getTree());
			lc=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_bitrange966); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_ASSIGN.add(lc);

			pushFollow(FOLLOW_identifier_in_bitrange970);
			b=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifier.add(b.getTree());
			LBRACKET64=(Token)match(input,LBRACKET,FOLLOW_LBRACKET_in_bitrange972); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_LBRACKET.add(LBRACKET64);

			pushFollow(FOLLOW_integer_in_bitrange976);
			i=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(i.getTree());
			COMMA65=(Token)match(input,COMMA,FOLLOW_COMMA_in_bitrange978); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_COMMA.add(COMMA65);

			pushFollow(FOLLOW_integer_in_bitrange982);
			j=integer();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_integer.add(j.getTree());
			RBRACKET66=(Token)match(input,RBRACKET,FOLLOW_RBRACKET_in_bitrange984); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_RBRACKET.add(RBRACKET66);

			// AST REWRITE
			// elements: j, b, i, a
			// token labels: 
			// rule labels: a, b, i, j, retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_a=new RewriteRuleSubtreeStream(adaptor,"rule a",a!=null?a.getTree():null);
			RewriteRuleSubtreeStream stream_b=new RewriteRuleSubtreeStream(adaptor,"rule b",b!=null?b.getTree():null);
			RewriteRuleSubtreeStream stream_i=new RewriteRuleSubtreeStream(adaptor,"rule i",i!=null?i.getTree():null);
			RewriteRuleSubtreeStream stream_j=new RewriteRuleSubtreeStream(adaptor,"rule j",j!=null?j.getTree():null);
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 160:84: -> ^( OP_BITRANGE[$lc, \"bitrange definition\"] $a $b $i $j)
			{
				// ghidra/sleigh/grammar/SleighParser.g:160:87: ^( OP_BITRANGE[$lc, \"bitrange definition\"] $a $b $i $j)
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_BITRANGE, lc, "bitrange definition"), root_1);
				adaptor.addChild(root_1, stream_a.nextTree());
				adaptor.addChild(root_1, stream_b.nextTree());
				adaptor.addChild(root_1, stream_i.nextTree());
				adaptor.addChild(root_1, stream_j.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "bitrange"


	public static class pcodeopdef_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pcodeopdef"
	// ghidra/sleigh/grammar/SleighParser.g:163:1: pcodeopdef : lc= KEY_DEFINE rb= KEY_PCODEOP identifierlist[$rb] -> ^( OP_PCODEOP[$lc, \"define pcodeop\"] identifierlist ) ;
	public final SleighParser.pcodeopdef_return pcodeopdef() throws RecognitionException {
		SleighParser.pcodeopdef_return retval = new SleighParser.pcodeopdef_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token rb=null;
		ParserRuleReturnScope identifierlist67 =null;

		CommonTree lc_tree=null;
		CommonTree rb_tree=null;
		RewriteRuleTokenStream stream_KEY_PCODEOP=new RewriteRuleTokenStream(adaptor,"token KEY_PCODEOP");
		RewriteRuleTokenStream stream_KEY_DEFINE=new RewriteRuleTokenStream(adaptor,"token KEY_DEFINE");
		RewriteRuleSubtreeStream stream_identifierlist=new RewriteRuleSubtreeStream(adaptor,"rule identifierlist");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:164:2: (lc= KEY_DEFINE rb= KEY_PCODEOP identifierlist[$rb] -> ^( OP_PCODEOP[$lc, \"define pcodeop\"] identifierlist ) )
			// ghidra/sleigh/grammar/SleighParser.g:164:4: lc= KEY_DEFINE rb= KEY_PCODEOP identifierlist[$rb]
			{
			lc=(Token)match(input,KEY_DEFINE,FOLLOW_KEY_DEFINE_in_pcodeopdef1016); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_DEFINE.add(lc);

			rb=(Token)match(input,KEY_PCODEOP,FOLLOW_KEY_PCODEOP_in_pcodeopdef1020); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_PCODEOP.add(rb);

			pushFollow(FOLLOW_identifierlist_in_pcodeopdef1022);
			identifierlist67=identifierlist(rb);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifierlist.add(identifierlist67.getTree());
			// AST REWRITE
			// elements: identifierlist
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 164:53: -> ^( OP_PCODEOP[$lc, \"define pcodeop\"] identifierlist )
			{
				// ghidra/sleigh/grammar/SleighParser.g:164:56: ^( OP_PCODEOP[$lc, \"define pcodeop\"] identifierlist )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_PCODEOP, lc, "define pcodeop"), root_1);
				adaptor.addChild(root_1, stream_identifierlist.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pcodeopdef"


	public static class valueattach_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "valueattach"
	// ghidra/sleigh/grammar/SleighParser.g:167:1: valueattach : lc= KEY_ATTACH rp= KEY_VALUES identifierlist[$rp] intblist[$rp] -> ^( OP_VALUES[$lc, \"attach values\"] identifierlist intblist ) ;
	public final SleighParser.valueattach_return valueattach() throws RecognitionException {
		SleighParser.valueattach_return retval = new SleighParser.valueattach_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token rp=null;
		ParserRuleReturnScope identifierlist68 =null;
		ParserRuleReturnScope intblist69 =null;

		CommonTree lc_tree=null;
		CommonTree rp_tree=null;
		RewriteRuleTokenStream stream_KEY_ATTACH=new RewriteRuleTokenStream(adaptor,"token KEY_ATTACH");
		RewriteRuleTokenStream stream_KEY_VALUES=new RewriteRuleTokenStream(adaptor,"token KEY_VALUES");
		RewriteRuleSubtreeStream stream_intblist=new RewriteRuleSubtreeStream(adaptor,"rule intblist");
		RewriteRuleSubtreeStream stream_identifierlist=new RewriteRuleSubtreeStream(adaptor,"rule identifierlist");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:168:2: (lc= KEY_ATTACH rp= KEY_VALUES identifierlist[$rp] intblist[$rp] -> ^( OP_VALUES[$lc, \"attach values\"] identifierlist intblist ) )
			// ghidra/sleigh/grammar/SleighParser.g:168:4: lc= KEY_ATTACH rp= KEY_VALUES identifierlist[$rp] intblist[$rp]
			{
			lc=(Token)match(input,KEY_ATTACH,FOLLOW_KEY_ATTACH_in_valueattach1045); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_ATTACH.add(lc);

			rp=(Token)match(input,KEY_VALUES,FOLLOW_KEY_VALUES_in_valueattach1049); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_VALUES.add(rp);

			pushFollow(FOLLOW_identifierlist_in_valueattach1051);
			identifierlist68=identifierlist(rp);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifierlist.add(identifierlist68.getTree());
			pushFollow(FOLLOW_intblist_in_valueattach1054);
			intblist69=intblist(rp);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_intblist.add(intblist69.getTree());
			// AST REWRITE
			// elements: identifierlist, intblist
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 168:66: -> ^( OP_VALUES[$lc, \"attach values\"] identifierlist intblist )
			{
				// ghidra/sleigh/grammar/SleighParser.g:168:69: ^( OP_VALUES[$lc, \"attach values\"] identifierlist intblist )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_VALUES, lc, "attach values"), root_1);
				adaptor.addChild(root_1, stream_identifierlist.nextTree());
				adaptor.addChild(root_1, stream_intblist.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "valueattach"


	public static class nameattach_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "nameattach"
	// ghidra/sleigh/grammar/SleighParser.g:171:1: nameattach : lc= KEY_ATTACH rp= KEY_NAMES a= identifierlist[$rp] b= stringoridentlist[$rp] -> ^( OP_NAMES[$lc, \"attach names\"] $a $b) ;
	public final SleighParser.nameattach_return nameattach() throws RecognitionException {
		SleighParser.nameattach_return retval = new SleighParser.nameattach_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token rp=null;
		ParserRuleReturnScope a =null;
		ParserRuleReturnScope b =null;

		CommonTree lc_tree=null;
		CommonTree rp_tree=null;
		RewriteRuleTokenStream stream_KEY_ATTACH=new RewriteRuleTokenStream(adaptor,"token KEY_ATTACH");
		RewriteRuleTokenStream stream_KEY_NAMES=new RewriteRuleTokenStream(adaptor,"token KEY_NAMES");
		RewriteRuleSubtreeStream stream_identifierlist=new RewriteRuleSubtreeStream(adaptor,"rule identifierlist");
		RewriteRuleSubtreeStream stream_stringoridentlist=new RewriteRuleSubtreeStream(adaptor,"rule stringoridentlist");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:172:2: (lc= KEY_ATTACH rp= KEY_NAMES a= identifierlist[$rp] b= stringoridentlist[$rp] -> ^( OP_NAMES[$lc, \"attach names\"] $a $b) )
			// ghidra/sleigh/grammar/SleighParser.g:172:4: lc= KEY_ATTACH rp= KEY_NAMES a= identifierlist[$rp] b= stringoridentlist[$rp]
			{
			lc=(Token)match(input,KEY_ATTACH,FOLLOW_KEY_ATTACH_in_nameattach1079); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_ATTACH.add(lc);

			rp=(Token)match(input,KEY_NAMES,FOLLOW_KEY_NAMES_in_nameattach1083); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_NAMES.add(rp);

			pushFollow(FOLLOW_identifierlist_in_nameattach1087);
			a=identifierlist(rp);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifierlist.add(a.getTree());
			pushFollow(FOLLOW_stringoridentlist_in_nameattach1092);
			b=stringoridentlist(rp);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_stringoridentlist.add(b.getTree());
			// AST REWRITE
			// elements: b, a
			// token labels: 
			// rule labels: a, b, retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_a=new RewriteRuleSubtreeStream(adaptor,"rule a",a!=null?a.getTree():null);
			RewriteRuleSubtreeStream stream_b=new RewriteRuleSubtreeStream(adaptor,"rule b",b!=null?b.getTree():null);
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 172:78: -> ^( OP_NAMES[$lc, \"attach names\"] $a $b)
			{
				// ghidra/sleigh/grammar/SleighParser.g:172:81: ^( OP_NAMES[$lc, \"attach names\"] $a $b)
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_NAMES, lc, "attach names"), root_1);
				adaptor.addChild(root_1, stream_a.nextTree());
				adaptor.addChild(root_1, stream_b.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "nameattach"


	public static class varattach_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "varattach"
	// ghidra/sleigh/grammar/SleighParser.g:175:1: varattach : lc= KEY_ATTACH rp= KEY_VARIABLES a= identifierlist[$rp] b= identifierlist[$rp] -> ^( OP_VARIABLES[$lc, \"attach variables\"] $a $b) ;
	public final SleighParser.varattach_return varattach() throws RecognitionException {
		SleighParser.varattach_return retval = new SleighParser.varattach_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token rp=null;
		ParserRuleReturnScope a =null;
		ParserRuleReturnScope b =null;

		CommonTree lc_tree=null;
		CommonTree rp_tree=null;
		RewriteRuleTokenStream stream_KEY_VARIABLES=new RewriteRuleTokenStream(adaptor,"token KEY_VARIABLES");
		RewriteRuleTokenStream stream_KEY_ATTACH=new RewriteRuleTokenStream(adaptor,"token KEY_ATTACH");
		RewriteRuleSubtreeStream stream_identifierlist=new RewriteRuleSubtreeStream(adaptor,"rule identifierlist");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:176:2: (lc= KEY_ATTACH rp= KEY_VARIABLES a= identifierlist[$rp] b= identifierlist[$rp] -> ^( OP_VARIABLES[$lc, \"attach variables\"] $a $b) )
			// ghidra/sleigh/grammar/SleighParser.g:176:4: lc= KEY_ATTACH rp= KEY_VARIABLES a= identifierlist[$rp] b= identifierlist[$rp]
			{
			lc=(Token)match(input,KEY_ATTACH,FOLLOW_KEY_ATTACH_in_varattach1119); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_ATTACH.add(lc);

			rp=(Token)match(input,KEY_VARIABLES,FOLLOW_KEY_VARIABLES_in_varattach1123); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_VARIABLES.add(rp);

			pushFollow(FOLLOW_identifierlist_in_varattach1127);
			a=identifierlist(rp);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifierlist.add(a.getTree());
			pushFollow(FOLLOW_identifierlist_in_varattach1132);
			b=identifierlist(rp);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifierlist.add(b.getTree());
			// AST REWRITE
			// elements: a, b
			// token labels: 
			// rule labels: a, b, retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_a=new RewriteRuleSubtreeStream(adaptor,"rule a",a!=null?a.getTree():null);
			RewriteRuleSubtreeStream stream_b=new RewriteRuleSubtreeStream(adaptor,"rule b",b!=null?b.getTree():null);
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 176:79: -> ^( OP_VARIABLES[$lc, \"attach variables\"] $a $b)
			{
				// ghidra/sleigh/grammar/SleighParser.g:176:82: ^( OP_VARIABLES[$lc, \"attach variables\"] $a $b)
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_VARIABLES, lc, "attach variables"), root_1);
				adaptor.addChild(root_1, stream_a.nextTree());
				adaptor.addChild(root_1, stream_b.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "varattach"


	public static class identifierlist_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "identifierlist"
	// ghidra/sleigh/grammar/SleighParser.g:179:1: identifierlist[Token lc] : ( LBRACKET ( id_or_wild )+ RBRACKET -> ^( OP_IDENTIFIER_LIST[$lc, \"identifier list\"] ( id_or_wild )+ ) | id_or_wild -> ^( OP_IDENTIFIER_LIST[$lc, \"identifier list\"] id_or_wild ) );
	public final SleighParser.identifierlist_return identifierlist(Token lc) throws RecognitionException {
		SleighParser.identifierlist_return retval = new SleighParser.identifierlist_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token LBRACKET70=null;
		Token RBRACKET72=null;
		ParserRuleReturnScope id_or_wild71 =null;
		ParserRuleReturnScope id_or_wild73 =null;

		CommonTree LBRACKET70_tree=null;
		CommonTree RBRACKET72_tree=null;
		RewriteRuleTokenStream stream_LBRACKET=new RewriteRuleTokenStream(adaptor,"token LBRACKET");
		RewriteRuleTokenStream stream_RBRACKET=new RewriteRuleTokenStream(adaptor,"token RBRACKET");
		RewriteRuleSubtreeStream stream_id_or_wild=new RewriteRuleSubtreeStream(adaptor,"rule id_or_wild");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:180:2: ( LBRACKET ( id_or_wild )+ RBRACKET -> ^( OP_IDENTIFIER_LIST[$lc, \"identifier list\"] ( id_or_wild )+ ) | id_or_wild -> ^( OP_IDENTIFIER_LIST[$lc, \"identifier list\"] id_or_wild ) )
			int alt16=2;
			int LA16_0 = input.LA(1);
			if ( (LA16_0==LBRACKET) ) {
				alt16=1;
			}
			else if ( ((LA16_0 >= IDENTIFIER && LA16_0 <= KEY_WORDSIZE)||LA16_0==UNDERSCORE) ) {
				alt16=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 16, 0, input);
				throw nvae;
			}

			switch (alt16) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:180:4: LBRACKET ( id_or_wild )+ RBRACKET
					{
					LBRACKET70=(Token)match(input,LBRACKET,FOLLOW_LBRACKET_in_identifierlist1158); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LBRACKET.add(LBRACKET70);

					// ghidra/sleigh/grammar/SleighParser.g:180:13: ( id_or_wild )+
					int cnt15=0;
					loop15:
					while (true) {
						int alt15=2;
						int LA15_0 = input.LA(1);
						if ( ((LA15_0 >= IDENTIFIER && LA15_0 <= KEY_WORDSIZE)||LA15_0==UNDERSCORE) ) {
							alt15=1;
						}

						switch (alt15) {
						case 1 :
							// ghidra/sleigh/grammar/SleighParser.g:180:13: id_or_wild
							{
							pushFollow(FOLLOW_id_or_wild_in_identifierlist1160);
							id_or_wild71=id_or_wild();
							state._fsp--;
							if (state.failed) return retval;
							if ( state.backtracking==0 ) stream_id_or_wild.add(id_or_wild71.getTree());
							}
							break;

						default :
							if ( cnt15 >= 1 ) break loop15;
							if (state.backtracking>0) {state.failed=true; return retval;}
							EarlyExitException eee = new EarlyExitException(15, input);
							throw eee;
						}
						cnt15++;
					}

					RBRACKET72=(Token)match(input,RBRACKET,FOLLOW_RBRACKET_in_identifierlist1163); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_RBRACKET.add(RBRACKET72);

					// AST REWRITE
					// elements: id_or_wild
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 180:34: -> ^( OP_IDENTIFIER_LIST[$lc, \"identifier list\"] ( id_or_wild )+ )
					{
						// ghidra/sleigh/grammar/SleighParser.g:180:37: ^( OP_IDENTIFIER_LIST[$lc, \"identifier list\"] ( id_or_wild )+ )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER_LIST, lc, "identifier list"), root_1);
						if ( !(stream_id_or_wild.hasNext()) ) {
							throw new RewriteEarlyExitException();
						}
						while ( stream_id_or_wild.hasNext() ) {
							adaptor.addChild(root_1, stream_id_or_wild.nextTree());
						}
						stream_id_or_wild.reset();

						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:181:4: id_or_wild
					{
					pushFollow(FOLLOW_id_or_wild_in_identifierlist1178);
					id_or_wild73=id_or_wild();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_id_or_wild.add(id_or_wild73.getTree());
					// AST REWRITE
					// elements: id_or_wild
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 181:15: -> ^( OP_IDENTIFIER_LIST[$lc, \"identifier list\"] id_or_wild )
					{
						// ghidra/sleigh/grammar/SleighParser.g:181:18: ^( OP_IDENTIFIER_LIST[$lc, \"identifier list\"] id_or_wild )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER_LIST, lc, "identifier list"), root_1);
						adaptor.addChild(root_1, stream_id_or_wild.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "identifierlist"


	public static class stringoridentlist_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "stringoridentlist"
	// ghidra/sleigh/grammar/SleighParser.g:184:1: stringoridentlist[Token lc] : ( LBRACKET ( stringorident )+ RBRACKET -> ^( OP_STRING_OR_IDENT_LIST[$lc, \"string or identifier list\"] ( stringorident )+ ) | stringorident -> ^( OP_STRING_OR_IDENT_LIST[$lc, \"string or identifier list\"] stringorident ) );
	public final SleighParser.stringoridentlist_return stringoridentlist(Token lc) throws RecognitionException {
		SleighParser.stringoridentlist_return retval = new SleighParser.stringoridentlist_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token LBRACKET74=null;
		Token RBRACKET76=null;
		ParserRuleReturnScope stringorident75 =null;
		ParserRuleReturnScope stringorident77 =null;

		CommonTree LBRACKET74_tree=null;
		CommonTree RBRACKET76_tree=null;
		RewriteRuleTokenStream stream_LBRACKET=new RewriteRuleTokenStream(adaptor,"token LBRACKET");
		RewriteRuleTokenStream stream_RBRACKET=new RewriteRuleTokenStream(adaptor,"token RBRACKET");
		RewriteRuleSubtreeStream stream_stringorident=new RewriteRuleSubtreeStream(adaptor,"rule stringorident");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:185:2: ( LBRACKET ( stringorident )+ RBRACKET -> ^( OP_STRING_OR_IDENT_LIST[$lc, \"string or identifier list\"] ( stringorident )+ ) | stringorident -> ^( OP_STRING_OR_IDENT_LIST[$lc, \"string or identifier list\"] stringorident ) )
			int alt18=2;
			int LA18_0 = input.LA(1);
			if ( (LA18_0==LBRACKET) ) {
				alt18=1;
			}
			else if ( ((LA18_0 >= IDENTIFIER && LA18_0 <= KEY_WORDSIZE)||LA18_0==QSTRING||LA18_0==UNDERSCORE) ) {
				alt18=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 18, 0, input);
				throw nvae;
			}

			switch (alt18) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:185:4: LBRACKET ( stringorident )+ RBRACKET
					{
					LBRACKET74=(Token)match(input,LBRACKET,FOLLOW_LBRACKET_in_stringoridentlist1199); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LBRACKET.add(LBRACKET74);

					// ghidra/sleigh/grammar/SleighParser.g:185:13: ( stringorident )+
					int cnt17=0;
					loop17:
					while (true) {
						int alt17=2;
						int LA17_0 = input.LA(1);
						if ( ((LA17_0 >= IDENTIFIER && LA17_0 <= KEY_WORDSIZE)||LA17_0==QSTRING||LA17_0==UNDERSCORE) ) {
							alt17=1;
						}

						switch (alt17) {
						case 1 :
							// ghidra/sleigh/grammar/SleighParser.g:185:13: stringorident
							{
							pushFollow(FOLLOW_stringorident_in_stringoridentlist1201);
							stringorident75=stringorident();
							state._fsp--;
							if (state.failed) return retval;
							if ( state.backtracking==0 ) stream_stringorident.add(stringorident75.getTree());
							}
							break;

						default :
							if ( cnt17 >= 1 ) break loop17;
							if (state.backtracking>0) {state.failed=true; return retval;}
							EarlyExitException eee = new EarlyExitException(17, input);
							throw eee;
						}
						cnt17++;
					}

					RBRACKET76=(Token)match(input,RBRACKET,FOLLOW_RBRACKET_in_stringoridentlist1204); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_RBRACKET.add(RBRACKET76);

					// AST REWRITE
					// elements: stringorident
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 185:37: -> ^( OP_STRING_OR_IDENT_LIST[$lc, \"string or identifier list\"] ( stringorident )+ )
					{
						// ghidra/sleigh/grammar/SleighParser.g:185:40: ^( OP_STRING_OR_IDENT_LIST[$lc, \"string or identifier list\"] ( stringorident )+ )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING_OR_IDENT_LIST, lc, "string or identifier list"), root_1);
						if ( !(stream_stringorident.hasNext()) ) {
							throw new RewriteEarlyExitException();
						}
						while ( stream_stringorident.hasNext() ) {
							adaptor.addChild(root_1, stream_stringorident.nextTree());
						}
						stream_stringorident.reset();

						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:186:4: stringorident
					{
					pushFollow(FOLLOW_stringorident_in_stringoridentlist1219);
					stringorident77=stringorident();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_stringorident.add(stringorident77.getTree());
					// AST REWRITE
					// elements: stringorident
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 186:18: -> ^( OP_STRING_OR_IDENT_LIST[$lc, \"string or identifier list\"] stringorident )
					{
						// ghidra/sleigh/grammar/SleighParser.g:186:21: ^( OP_STRING_OR_IDENT_LIST[$lc, \"string or identifier list\"] stringorident )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING_OR_IDENT_LIST, lc, "string or identifier list"), root_1);
						adaptor.addChild(root_1, stream_stringorident.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "stringoridentlist"


	public static class stringorident_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "stringorident"
	// ghidra/sleigh/grammar/SleighParser.g:189:1: stringorident : ( id_or_wild | qstring );
	public final SleighParser.stringorident_return stringorident() throws RecognitionException {
		SleighParser.stringorident_return retval = new SleighParser.stringorident_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope id_or_wild78 =null;
		ParserRuleReturnScope qstring79 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:190:2: ( id_or_wild | qstring )
			int alt19=2;
			int LA19_0 = input.LA(1);
			if ( ((LA19_0 >= IDENTIFIER && LA19_0 <= KEY_WORDSIZE)||LA19_0==UNDERSCORE) ) {
				alt19=1;
			}
			else if ( (LA19_0==QSTRING) ) {
				alt19=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 19, 0, input);
				throw nvae;
			}

			switch (alt19) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:190:4: id_or_wild
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_id_or_wild_in_stringorident1239);
					id_or_wild78=id_or_wild();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, id_or_wild78.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:191:4: qstring
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_qstring_in_stringorident1244);
					qstring79=qstring();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, qstring79.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "stringorident"


	public static class intblist_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "intblist"
	// ghidra/sleigh/grammar/SleighParser.g:194:1: intblist[Token lc] : ( LBRACKET ( intbpart )+ RBRACKET -> ^( OP_INTBLIST[$lc, \"integer or wildcard list\"] ( intbpart )+ ) | neginteger -> ^( OP_INTBLIST[$lc, \"integer or wildcard list\"] neginteger ) );
	public final SleighParser.intblist_return intblist(Token lc) throws RecognitionException {
		SleighParser.intblist_return retval = new SleighParser.intblist_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token LBRACKET80=null;
		Token RBRACKET82=null;
		ParserRuleReturnScope intbpart81 =null;
		ParserRuleReturnScope neginteger83 =null;

		CommonTree LBRACKET80_tree=null;
		CommonTree RBRACKET82_tree=null;
		RewriteRuleTokenStream stream_LBRACKET=new RewriteRuleTokenStream(adaptor,"token LBRACKET");
		RewriteRuleTokenStream stream_RBRACKET=new RewriteRuleTokenStream(adaptor,"token RBRACKET");
		RewriteRuleSubtreeStream stream_intbpart=new RewriteRuleSubtreeStream(adaptor,"rule intbpart");
		RewriteRuleSubtreeStream stream_neginteger=new RewriteRuleSubtreeStream(adaptor,"rule neginteger");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:195:2: ( LBRACKET ( intbpart )+ RBRACKET -> ^( OP_INTBLIST[$lc, \"integer or wildcard list\"] ( intbpart )+ ) | neginteger -> ^( OP_INTBLIST[$lc, \"integer or wildcard list\"] neginteger ) )
			int alt21=2;
			int LA21_0 = input.LA(1);
			if ( (LA21_0==LBRACKET) ) {
				alt21=1;
			}
			else if ( (LA21_0==BIN_INT||LA21_0==DEC_INT||LA21_0==HEX_INT||LA21_0==MINUS) ) {
				alt21=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 21, 0, input);
				throw nvae;
			}

			switch (alt21) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:195:4: LBRACKET ( intbpart )+ RBRACKET
					{
					LBRACKET80=(Token)match(input,LBRACKET,FOLLOW_LBRACKET_in_intblist1256); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LBRACKET.add(LBRACKET80);

					// ghidra/sleigh/grammar/SleighParser.g:195:13: ( intbpart )+
					int cnt20=0;
					loop20:
					while (true) {
						int alt20=2;
						int LA20_0 = input.LA(1);
						if ( (LA20_0==BIN_INT||LA20_0==DEC_INT||LA20_0==HEX_INT||LA20_0==MINUS||LA20_0==UNDERSCORE) ) {
							alt20=1;
						}

						switch (alt20) {
						case 1 :
							// ghidra/sleigh/grammar/SleighParser.g:195:13: intbpart
							{
							pushFollow(FOLLOW_intbpart_in_intblist1258);
							intbpart81=intbpart();
							state._fsp--;
							if (state.failed) return retval;
							if ( state.backtracking==0 ) stream_intbpart.add(intbpart81.getTree());
							}
							break;

						default :
							if ( cnt20 >= 1 ) break loop20;
							if (state.backtracking>0) {state.failed=true; return retval;}
							EarlyExitException eee = new EarlyExitException(20, input);
							throw eee;
						}
						cnt20++;
					}

					RBRACKET82=(Token)match(input,RBRACKET,FOLLOW_RBRACKET_in_intblist1261); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_RBRACKET.add(RBRACKET82);

					// AST REWRITE
					// elements: intbpart
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 195:32: -> ^( OP_INTBLIST[$lc, \"integer or wildcard list\"] ( intbpart )+ )
					{
						// ghidra/sleigh/grammar/SleighParser.g:195:35: ^( OP_INTBLIST[$lc, \"integer or wildcard list\"] ( intbpart )+ )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_INTBLIST, lc, "integer or wildcard list"), root_1);
						if ( !(stream_intbpart.hasNext()) ) {
							throw new RewriteEarlyExitException();
						}
						while ( stream_intbpart.hasNext() ) {
							adaptor.addChild(root_1, stream_intbpart.nextTree());
						}
						stream_intbpart.reset();

						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:196:4: neginteger
					{
					pushFollow(FOLLOW_neginteger_in_intblist1276);
					neginteger83=neginteger();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_neginteger.add(neginteger83.getTree());
					// AST REWRITE
					// elements: neginteger
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 196:15: -> ^( OP_INTBLIST[$lc, \"integer or wildcard list\"] neginteger )
					{
						// ghidra/sleigh/grammar/SleighParser.g:196:18: ^( OP_INTBLIST[$lc, \"integer or wildcard list\"] neginteger )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_INTBLIST, lc, "integer or wildcard list"), root_1);
						adaptor.addChild(root_1, stream_neginteger.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "intblist"


	public static class intbpart_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "intbpart"
	// ghidra/sleigh/grammar/SleighParser.g:199:1: intbpart : ( neginteger |lc= UNDERSCORE -> OP_WILDCARD[$lc] );
	public final SleighParser.intbpart_return intbpart() throws RecognitionException {
		SleighParser.intbpart_return retval = new SleighParser.intbpart_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		ParserRuleReturnScope neginteger84 =null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_UNDERSCORE=new RewriteRuleTokenStream(adaptor,"token UNDERSCORE");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:200:2: ( neginteger |lc= UNDERSCORE -> OP_WILDCARD[$lc] )
			int alt22=2;
			int LA22_0 = input.LA(1);
			if ( (LA22_0==BIN_INT||LA22_0==DEC_INT||LA22_0==HEX_INT||LA22_0==MINUS) ) {
				alt22=1;
			}
			else if ( (LA22_0==UNDERSCORE) ) {
				alt22=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 22, 0, input);
				throw nvae;
			}

			switch (alt22) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:200:4: neginteger
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_neginteger_in_intbpart1296);
					neginteger84=neginteger();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, neginteger84.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:201:4: lc= UNDERSCORE
					{
					lc=(Token)match(input,UNDERSCORE,FOLLOW_UNDERSCORE_in_intbpart1303); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_UNDERSCORE.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 201:18: -> OP_WILDCARD[$lc]
					{
						adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_WILDCARD, lc));
					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "intbpart"


	public static class neginteger_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "neginteger"
	// ghidra/sleigh/grammar/SleighParser.g:204:1: neginteger : ( integer |lc= MINUS integer -> ^( OP_NEGATE[$lc] integer ) );
	public final SleighParser.neginteger_return neginteger() throws RecognitionException {
		SleighParser.neginteger_return retval = new SleighParser.neginteger_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		ParserRuleReturnScope integer85 =null;
		ParserRuleReturnScope integer86 =null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_MINUS=new RewriteRuleTokenStream(adaptor,"token MINUS");
		RewriteRuleSubtreeStream stream_integer=new RewriteRuleSubtreeStream(adaptor,"rule integer");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:205:2: ( integer |lc= MINUS integer -> ^( OP_NEGATE[$lc] integer ) )
			int alt23=2;
			int LA23_0 = input.LA(1);
			if ( (LA23_0==BIN_INT||LA23_0==DEC_INT||LA23_0==HEX_INT) ) {
				alt23=1;
			}
			else if ( (LA23_0==MINUS) ) {
				alt23=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 23, 0, input);
				throw nvae;
			}

			switch (alt23) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:205:4: integer
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_integer_in_neginteger1319);
					integer85=integer();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, integer85.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:206:4: lc= MINUS integer
					{
					lc=(Token)match(input,MINUS,FOLLOW_MINUS_in_neginteger1326); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_MINUS.add(lc);

					pushFollow(FOLLOW_integer_in_neginteger1328);
					integer86=integer();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_integer.add(integer86.getTree());
					// AST REWRITE
					// elements: integer
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 206:21: -> ^( OP_NEGATE[$lc] integer )
					{
						// ghidra/sleigh/grammar/SleighParser.g:206:24: ^( OP_NEGATE[$lc] integer )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_NEGATE, lc), root_1);
						adaptor.addChild(root_1, stream_integer.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "neginteger"


	public static class constructorlike_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "constructorlike"
	// ghidra/sleigh/grammar/SleighParser.g:209:1: constructorlike : ( macrodef | withblock | constructor );
	public final SleighParser.constructorlike_return constructorlike() throws RecognitionException {
		SleighParser.constructorlike_return retval = new SleighParser.constructorlike_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope macrodef87 =null;
		ParserRuleReturnScope withblock88 =null;
		ParserRuleReturnScope constructor89 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:210:2: ( macrodef | withblock | constructor )
			int alt24=3;
			switch ( input.LA(1) ) {
			case KEY_MACRO:
				{
				int LA24_1 = input.LA(2);
				if ( ((LA24_1 >= IDENTIFIER && LA24_1 <= KEY_WORDSIZE)) ) {
					alt24=1;
				}
				else if ( (LA24_1==COLON) ) {
					alt24=3;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 24, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case RES_WITH:
				{
				alt24=2;
				}
				break;
			case COLON:
			case IDENTIFIER:
			case KEY_ALIGNMENT:
			case KEY_ATTACH:
			case KEY_BIG:
			case KEY_BITRANGE:
			case KEY_BUILD:
			case KEY_CALL:
			case KEY_CONTEXT:
			case KEY_CROSSBUILD:
			case KEY_DEC:
			case KEY_DEFAULT:
			case KEY_DEFINE:
			case KEY_ENDIAN:
			case KEY_EXPORT:
			case KEY_GOTO:
			case KEY_HEX:
			case KEY_LITTLE:
			case KEY_LOCAL:
			case KEY_NAMES:
			case KEY_NOFLOW:
			case KEY_OFFSET:
			case KEY_PCODEOP:
			case KEY_RETURN:
			case KEY_SIGNED:
			case KEY_SIZE:
			case KEY_SPACE:
			case KEY_TOKEN:
			case KEY_TYPE:
			case KEY_UNIMPL:
			case KEY_VALUES:
			case KEY_VARIABLES:
			case KEY_WORDSIZE:
				{
				alt24=3;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 24, 0, input);
				throw nvae;
			}
			switch (alt24) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:210:4: macrodef
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_macrodef_in_constructorlike1348);
					macrodef87=macrodef();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, macrodef87.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:211:4: withblock
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_withblock_in_constructorlike1353);
					withblock88=withblock();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, withblock88.getTree());

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighParser.g:212:4: constructor
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_constructor_in_constructorlike1358);
					constructor89=constructor();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, constructor89.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "constructorlike"


	public static class macrodef_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "macrodef"
	// ghidra/sleigh/grammar/SleighParser.g:215:1: macrodef : lc= KEY_MACRO identifier lp= LPAREN arguments[$lp] RPAREN semanticbody -> ^( OP_MACRO[$lc, \"macro\"] identifier arguments semanticbody ) ;
	public final SleighParser.macrodef_return macrodef() throws RecognitionException {
		SleighParser.macrodef_return retval = new SleighParser.macrodef_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token lp=null;
		Token RPAREN92=null;
		ParserRuleReturnScope identifier90 =null;
		ParserRuleReturnScope arguments91 =null;
		ParserRuleReturnScope semanticbody93 =null;

		CommonTree lc_tree=null;
		CommonTree lp_tree=null;
		CommonTree RPAREN92_tree=null;
		RewriteRuleTokenStream stream_LPAREN=new RewriteRuleTokenStream(adaptor,"token LPAREN");
		RewriteRuleTokenStream stream_RPAREN=new RewriteRuleTokenStream(adaptor,"token RPAREN");
		RewriteRuleTokenStream stream_KEY_MACRO=new RewriteRuleTokenStream(adaptor,"token KEY_MACRO");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_semanticbody=new RewriteRuleSubtreeStream(adaptor,"rule semanticbody");
		RewriteRuleSubtreeStream stream_arguments=new RewriteRuleSubtreeStream(adaptor,"rule arguments");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:216:2: (lc= KEY_MACRO identifier lp= LPAREN arguments[$lp] RPAREN semanticbody -> ^( OP_MACRO[$lc, \"macro\"] identifier arguments semanticbody ) )
			// ghidra/sleigh/grammar/SleighParser.g:216:4: lc= KEY_MACRO identifier lp= LPAREN arguments[$lp] RPAREN semanticbody
			{
			lc=(Token)match(input,KEY_MACRO,FOLLOW_KEY_MACRO_in_macrodef1371); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_KEY_MACRO.add(lc);

			pushFollow(FOLLOW_identifier_in_macrodef1373);
			identifier90=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifier.add(identifier90.getTree());
			lp=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_macrodef1377); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_LPAREN.add(lp);

			pushFollow(FOLLOW_arguments_in_macrodef1379);
			arguments91=arguments(lp);
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_arguments.add(arguments91.getTree());
			RPAREN92=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_macrodef1382); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_RPAREN.add(RPAREN92);

			pushFollow(FOLLOW_semanticbody_in_macrodef1384);
			semanticbody93=semanticbody();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_semanticbody.add(semanticbody93.getTree());
			// AST REWRITE
			// elements: semanticbody, arguments, identifier
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 216:73: -> ^( OP_MACRO[$lc, \"macro\"] identifier arguments semanticbody )
			{
				// ghidra/sleigh/grammar/SleighParser.g:216:76: ^( OP_MACRO[$lc, \"macro\"] identifier arguments semanticbody )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_MACRO, lc, "macro"), root_1);
				adaptor.addChild(root_1, stream_identifier.nextTree());
				adaptor.addChild(root_1, stream_arguments.nextTree());
				adaptor.addChild(root_1, stream_semanticbody.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "macrodef"


	public static class arguments_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "arguments"
	// ghidra/sleigh/grammar/SleighParser.g:219:1: arguments[Token lc] : ( oplist -> ^( OP_ARGUMENTS[$lc, \"arguments\"] oplist ) | -> ^( OP_EMPTY_LIST[$lc, \"no arguments\"] ) );
	public final SleighParser.arguments_return arguments(Token lc) throws RecognitionException {
		SleighParser.arguments_return retval = new SleighParser.arguments_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope oplist94 =null;

		RewriteRuleSubtreeStream stream_oplist=new RewriteRuleSubtreeStream(adaptor,"rule oplist");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:220:2: ( oplist -> ^( OP_ARGUMENTS[$lc, \"arguments\"] oplist ) | -> ^( OP_EMPTY_LIST[$lc, \"no arguments\"] ) )
			int alt25=2;
			int LA25_0 = input.LA(1);
			if ( ((LA25_0 >= IDENTIFIER && LA25_0 <= KEY_WORDSIZE)) ) {
				alt25=1;
			}
			else if ( (LA25_0==RPAREN) ) {
				alt25=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 25, 0, input);
				throw nvae;
			}

			switch (alt25) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:220:4: oplist
					{
					pushFollow(FOLLOW_oplist_in_arguments1409);
					oplist94=oplist();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_oplist.add(oplist94.getTree());
					// AST REWRITE
					// elements: oplist
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 220:11: -> ^( OP_ARGUMENTS[$lc, \"arguments\"] oplist )
					{
						// ghidra/sleigh/grammar/SleighParser.g:220:14: ^( OP_ARGUMENTS[$lc, \"arguments\"] oplist )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_ARGUMENTS, lc, "arguments"), root_1);
						adaptor.addChild(root_1, stream_oplist.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:221:4: 
					{
					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 221:4: -> ^( OP_EMPTY_LIST[$lc, \"no arguments\"] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:221:7: ^( OP_EMPTY_LIST[$lc, \"no arguments\"] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_EMPTY_LIST, lc, "no arguments"), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "arguments"


	public static class oplist_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "oplist"
	// ghidra/sleigh/grammar/SleighParser.g:224:1: oplist : identifier ( COMMA ! identifier )* ;
	public final SleighParser.oplist_return oplist() throws RecognitionException {
		SleighParser.oplist_return retval = new SleighParser.oplist_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token COMMA96=null;
		ParserRuleReturnScope identifier95 =null;
		ParserRuleReturnScope identifier97 =null;

		CommonTree COMMA96_tree=null;

		try {
			// ghidra/sleigh/grammar/SleighParser.g:225:2: ( identifier ( COMMA ! identifier )* )
			// ghidra/sleigh/grammar/SleighParser.g:225:4: identifier ( COMMA ! identifier )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_identifier_in_oplist1439);
			identifier95=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, identifier95.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:225:15: ( COMMA ! identifier )*
			loop26:
			while (true) {
				int alt26=2;
				int LA26_0 = input.LA(1);
				if ( (LA26_0==COMMA) ) {
					alt26=1;
				}

				switch (alt26) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:225:16: COMMA ! identifier
					{
					COMMA96=(Token)match(input,COMMA,FOLLOW_COMMA_in_oplist1442); if (state.failed) return retval;
					pushFollow(FOLLOW_identifier_in_oplist1445);
					identifier97=identifier();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, identifier97.getTree());

					}
					break;

				default :
					break loop26;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "oplist"


	public static class withblock_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "withblock"
	// ghidra/sleigh/grammar/SleighParser.g:228:1: withblock : lc= RES_WITH id_or_nil COLON bitpat_or_nil contextblock LBRACE constructorlikelist RBRACE -> ^( OP_WITH[$lc, \"with\"] id_or_nil bitpat_or_nil contextblock constructorlikelist ) ;
	public final SleighParser.withblock_return withblock() throws RecognitionException {
		SleighParser.withblock_return retval = new SleighParser.withblock_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token COLON99=null;
		Token LBRACE102=null;
		Token RBRACE104=null;
		ParserRuleReturnScope id_or_nil98 =null;
		ParserRuleReturnScope bitpat_or_nil100 =null;
		ParserRuleReturnScope contextblock101 =null;
		ParserRuleReturnScope constructorlikelist103 =null;

		CommonTree lc_tree=null;
		CommonTree COLON99_tree=null;
		CommonTree LBRACE102_tree=null;
		CommonTree RBRACE104_tree=null;
		RewriteRuleTokenStream stream_RBRACE=new RewriteRuleTokenStream(adaptor,"token RBRACE");
		RewriteRuleTokenStream stream_RES_WITH=new RewriteRuleTokenStream(adaptor,"token RES_WITH");
		RewriteRuleTokenStream stream_COLON=new RewriteRuleTokenStream(adaptor,"token COLON");
		RewriteRuleTokenStream stream_LBRACE=new RewriteRuleTokenStream(adaptor,"token LBRACE");
		RewriteRuleSubtreeStream stream_bitpat_or_nil=new RewriteRuleSubtreeStream(adaptor,"rule bitpat_or_nil");
		RewriteRuleSubtreeStream stream_contextblock=new RewriteRuleSubtreeStream(adaptor,"rule contextblock");
		RewriteRuleSubtreeStream stream_constructorlikelist=new RewriteRuleSubtreeStream(adaptor,"rule constructorlikelist");
		RewriteRuleSubtreeStream stream_id_or_nil=new RewriteRuleSubtreeStream(adaptor,"rule id_or_nil");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:229:2: (lc= RES_WITH id_or_nil COLON bitpat_or_nil contextblock LBRACE constructorlikelist RBRACE -> ^( OP_WITH[$lc, \"with\"] id_or_nil bitpat_or_nil contextblock constructorlikelist ) )
			// ghidra/sleigh/grammar/SleighParser.g:229:4: lc= RES_WITH id_or_nil COLON bitpat_or_nil contextblock LBRACE constructorlikelist RBRACE
			{
			lc=(Token)match(input,RES_WITH,FOLLOW_RES_WITH_in_withblock1460); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_RES_WITH.add(lc);

			pushFollow(FOLLOW_id_or_nil_in_withblock1462);
			id_or_nil98=id_or_nil();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_id_or_nil.add(id_or_nil98.getTree());
			COLON99=(Token)match(input,COLON,FOLLOW_COLON_in_withblock1464); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_COLON.add(COLON99);

			pushFollow(FOLLOW_bitpat_or_nil_in_withblock1466);
			bitpat_or_nil100=bitpat_or_nil();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_bitpat_or_nil.add(bitpat_or_nil100.getTree());
			pushFollow(FOLLOW_contextblock_in_withblock1468);
			contextblock101=contextblock();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_contextblock.add(contextblock101.getTree());
			LBRACE102=(Token)match(input,LBRACE,FOLLOW_LBRACE_in_withblock1470); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_LBRACE.add(LBRACE102);

			pushFollow(FOLLOW_constructorlikelist_in_withblock1472);
			constructorlikelist103=constructorlikelist();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_constructorlikelist.add(constructorlikelist103.getTree());
			RBRACE104=(Token)match(input,RBRACE,FOLLOW_RBRACE_in_withblock1474); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_RBRACE.add(RBRACE104);

			// AST REWRITE
			// elements: bitpat_or_nil, contextblock, id_or_nil, constructorlikelist
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 230:4: -> ^( OP_WITH[$lc, \"with\"] id_or_nil bitpat_or_nil contextblock constructorlikelist )
			{
				// ghidra/sleigh/grammar/SleighParser.g:230:7: ^( OP_WITH[$lc, \"with\"] id_or_nil bitpat_or_nil contextblock constructorlikelist )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_WITH, lc, "with"), root_1);
				adaptor.addChild(root_1, stream_id_or_nil.nextTree());
				adaptor.addChild(root_1, stream_bitpat_or_nil.nextTree());
				adaptor.addChild(root_1, stream_contextblock.nextTree());
				adaptor.addChild(root_1, stream_constructorlikelist.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "withblock"


	public static class id_or_nil_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "id_or_nil"
	// ghidra/sleigh/grammar/SleighParser.g:233:1: id_or_nil : ( identifier | -> ^( OP_NIL ) );
	public final SleighParser.id_or_nil_return id_or_nil() throws RecognitionException {
		SleighParser.id_or_nil_return retval = new SleighParser.id_or_nil_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope identifier105 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:234:2: ( identifier | -> ^( OP_NIL ) )
			int alt27=2;
			int LA27_0 = input.LA(1);
			if ( ((LA27_0 >= IDENTIFIER && LA27_0 <= KEY_WORDSIZE)) ) {
				alt27=1;
			}
			else if ( (LA27_0==COLON) ) {
				alt27=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 27, 0, input);
				throw nvae;
			}

			switch (alt27) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:234:4: identifier
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_identifier_in_id_or_nil1503);
					identifier105=identifier();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, identifier105.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:235:4: 
					{
					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 235:4: -> ^( OP_NIL )
					{
						// ghidra/sleigh/grammar/SleighParser.g:235:7: ^( OP_NIL )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_NIL, "OP_NIL"), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "id_or_nil"


	public static class bitpat_or_nil_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "bitpat_or_nil"
	// ghidra/sleigh/grammar/SleighParser.g:238:1: bitpat_or_nil : ( bitpattern | -> ^( OP_NIL ) );
	public final SleighParser.bitpat_or_nil_return bitpat_or_nil() throws RecognitionException {
		SleighParser.bitpat_or_nil_return retval = new SleighParser.bitpat_or_nil_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope bitpattern106 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:239:2: ( bitpattern | -> ^( OP_NIL ) )
			int alt28=2;
			int LA28_0 = input.LA(1);
			if ( (LA28_0==ELLIPSIS||(LA28_0 >= IDENTIFIER && LA28_0 <= KEY_WORDSIZE)||LA28_0==LPAREN) ) {
				alt28=1;
			}
			else if ( ((LA28_0 >= LBRACE && LA28_0 <= LBRACKET)) ) {
				alt28=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 28, 0, input);
				throw nvae;
			}

			switch (alt28) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:239:4: bitpattern
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_bitpattern_in_bitpat_or_nil1523);
					bitpattern106=bitpattern();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, bitpattern106.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:240:4: 
					{
					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 240:4: -> ^( OP_NIL )
					{
						// ghidra/sleigh/grammar/SleighParser.g:240:7: ^( OP_NIL )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_NIL, "OP_NIL"), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "bitpat_or_nil"


	public static class def_or_conslike_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "def_or_conslike"
	// ghidra/sleigh/grammar/SleighParser.g:243:1: def_or_conslike : ( definition | constructorlike );
	public final SleighParser.def_or_conslike_return def_or_conslike() throws RecognitionException {
		SleighParser.def_or_conslike_return retval = new SleighParser.def_or_conslike_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope definition107 =null;
		ParserRuleReturnScope constructorlike108 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:244:2: ( definition | constructorlike )
			int alt29=2;
			switch ( input.LA(1) ) {
			case KEY_DEFINE:
				{
				int LA29_1 = input.LA(2);
				if ( ((LA29_1 >= IDENTIFIER && LA29_1 <= KEY_WORDSIZE)) ) {
					alt29=1;
				}
				else if ( (LA29_1==COLON) ) {
					alt29=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 29, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ATTACH:
				{
				int LA29_2 = input.LA(2);
				if ( (LA29_2==KEY_NAMES||(LA29_2 >= KEY_VALUES && LA29_2 <= KEY_VARIABLES)) ) {
					alt29=1;
				}
				else if ( (LA29_2==COLON) ) {
					alt29=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 29, 2, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case COLON:
			case IDENTIFIER:
			case KEY_ALIGNMENT:
			case KEY_BIG:
			case KEY_BITRANGE:
			case KEY_BUILD:
			case KEY_CALL:
			case KEY_CONTEXT:
			case KEY_CROSSBUILD:
			case KEY_DEC:
			case KEY_DEFAULT:
			case KEY_ENDIAN:
			case KEY_EXPORT:
			case KEY_GOTO:
			case KEY_HEX:
			case KEY_LITTLE:
			case KEY_LOCAL:
			case KEY_MACRO:
			case KEY_NAMES:
			case KEY_NOFLOW:
			case KEY_OFFSET:
			case KEY_PCODEOP:
			case KEY_RETURN:
			case KEY_SIGNED:
			case KEY_SIZE:
			case KEY_SPACE:
			case KEY_TOKEN:
			case KEY_TYPE:
			case KEY_UNIMPL:
			case KEY_VALUES:
			case KEY_VARIABLES:
			case KEY_WORDSIZE:
			case RES_WITH:
				{
				alt29=2;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 29, 0, input);
				throw nvae;
			}
			switch (alt29) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:244:4: definition
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_definition_in_def_or_conslike1543);
					definition107=definition();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, definition107.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:245:4: constructorlike
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_constructorlike_in_def_or_conslike1548);
					constructorlike108=constructorlike();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, constructorlike108.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "def_or_conslike"


	public static class constructorlikelist_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "constructorlikelist"
	// ghidra/sleigh/grammar/SleighParser.g:248:1: constructorlikelist : ( def_or_conslike )* -> ^( OP_CTLIST ( def_or_conslike )* ) ;
	public final SleighParser.constructorlikelist_return constructorlikelist() throws RecognitionException {
		SleighParser.constructorlikelist_return retval = new SleighParser.constructorlikelist_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope def_or_conslike109 =null;

		RewriteRuleSubtreeStream stream_def_or_conslike=new RewriteRuleSubtreeStream(adaptor,"rule def_or_conslike");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:249:2: ( ( def_or_conslike )* -> ^( OP_CTLIST ( def_or_conslike )* ) )
			// ghidra/sleigh/grammar/SleighParser.g:249:4: ( def_or_conslike )*
			{
			// ghidra/sleigh/grammar/SleighParser.g:249:4: ( def_or_conslike )*
			loop30:
			while (true) {
				int alt30=2;
				int LA30_0 = input.LA(1);
				if ( (LA30_0==COLON||(LA30_0 >= IDENTIFIER && LA30_0 <= KEY_WORDSIZE)||LA30_0==RES_WITH) ) {
					alt30=1;
				}

				switch (alt30) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:249:4: def_or_conslike
					{
					pushFollow(FOLLOW_def_or_conslike_in_constructorlikelist1559);
					def_or_conslike109=def_or_conslike();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_def_or_conslike.add(def_or_conslike109.getTree());
					}
					break;

				default :
					break loop30;
				}
			}

			// AST REWRITE
			// elements: def_or_conslike
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 249:21: -> ^( OP_CTLIST ( def_or_conslike )* )
			{
				// ghidra/sleigh/grammar/SleighParser.g:249:24: ^( OP_CTLIST ( def_or_conslike )* )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_CTLIST, "OP_CTLIST"), root_1);
				// ghidra/sleigh/grammar/SleighParser.g:249:36: ( def_or_conslike )*
				while ( stream_def_or_conslike.hasNext() ) {
					adaptor.addChild(root_1, stream_def_or_conslike.nextTree());
				}
				stream_def_or_conslike.reset();

				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "constructorlikelist"


	public static class constructor_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "constructor"
	// ghidra/sleigh/grammar/SleighParser.g:252:1: constructor : ctorstart bitpattern contextblock ctorsemantic -> ^( OP_CONSTRUCTOR ctorstart bitpattern contextblock ctorsemantic ) ;
	public final SleighParser.constructor_return constructor() throws RecognitionException {
		SleighParser.constructor_return retval = new SleighParser.constructor_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope ctorstart110 =null;
		ParserRuleReturnScope bitpattern111 =null;
		ParserRuleReturnScope contextblock112 =null;
		ParserRuleReturnScope ctorsemantic113 =null;

		RewriteRuleSubtreeStream stream_bitpattern=new RewriteRuleSubtreeStream(adaptor,"rule bitpattern");
		RewriteRuleSubtreeStream stream_ctorsemantic=new RewriteRuleSubtreeStream(adaptor,"rule ctorsemantic");
		RewriteRuleSubtreeStream stream_contextblock=new RewriteRuleSubtreeStream(adaptor,"rule contextblock");
		RewriteRuleSubtreeStream stream_ctorstart=new RewriteRuleSubtreeStream(adaptor,"rule ctorstart");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:253:2: ( ctorstart bitpattern contextblock ctorsemantic -> ^( OP_CONSTRUCTOR ctorstart bitpattern contextblock ctorsemantic ) )
			// ghidra/sleigh/grammar/SleighParser.g:253:4: ctorstart bitpattern contextblock ctorsemantic
			{
			pushFollow(FOLLOW_ctorstart_in_constructor1581);
			ctorstart110=ctorstart();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_ctorstart.add(ctorstart110.getTree());
			pushFollow(FOLLOW_bitpattern_in_constructor1583);
			bitpattern111=bitpattern();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_bitpattern.add(bitpattern111.getTree());
			pushFollow(FOLLOW_contextblock_in_constructor1585);
			contextblock112=contextblock();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_contextblock.add(contextblock112.getTree());
			pushFollow(FOLLOW_ctorsemantic_in_constructor1587);
			ctorsemantic113=ctorsemantic();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_ctorsemantic.add(ctorsemantic113.getTree());
			// AST REWRITE
			// elements: contextblock, ctorstart, ctorsemantic, bitpattern
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 253:51: -> ^( OP_CONSTRUCTOR ctorstart bitpattern contextblock ctorsemantic )
			{
				// ghidra/sleigh/grammar/SleighParser.g:253:54: ^( OP_CONSTRUCTOR ctorstart bitpattern contextblock ctorsemantic )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_CONSTRUCTOR, "OP_CONSTRUCTOR"), root_1);
				adaptor.addChild(root_1, stream_ctorstart.nextTree());
				adaptor.addChild(root_1, stream_bitpattern.nextTree());
				adaptor.addChild(root_1, stream_contextblock.nextTree());
				adaptor.addChild(root_1, stream_ctorsemantic.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "constructor"


	public static class ctorsemantic_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "ctorsemantic"
	// ghidra/sleigh/grammar/SleighParser.g:256:1: ctorsemantic : ( semanticbody -> ^( OP_PCODE semanticbody ) |lc= KEY_UNIMPL -> ^( OP_PCODE[$lc] OP_UNIMPL[$lc] ) );
	public final SleighParser.ctorsemantic_return ctorsemantic() throws RecognitionException {
		SleighParser.ctorsemantic_return retval = new SleighParser.ctorsemantic_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		ParserRuleReturnScope semanticbody114 =null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_KEY_UNIMPL=new RewriteRuleTokenStream(adaptor,"token KEY_UNIMPL");
		RewriteRuleSubtreeStream stream_semanticbody=new RewriteRuleSubtreeStream(adaptor,"rule semanticbody");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:257:2: ( semanticbody -> ^( OP_PCODE semanticbody ) |lc= KEY_UNIMPL -> ^( OP_PCODE[$lc] OP_UNIMPL[$lc] ) )
			int alt31=2;
			int LA31_0 = input.LA(1);
			if ( (LA31_0==LBRACE) ) {
				alt31=1;
			}
			else if ( (LA31_0==KEY_UNIMPL) ) {
				alt31=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 31, 0, input);
				throw nvae;
			}

			switch (alt31) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:257:4: semanticbody
					{
					pushFollow(FOLLOW_semanticbody_in_ctorsemantic1612);
					semanticbody114=semanticbody();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_semanticbody.add(semanticbody114.getTree());
					// AST REWRITE
					// elements: semanticbody
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 257:17: -> ^( OP_PCODE semanticbody )
					{
						// ghidra/sleigh/grammar/SleighParser.g:257:20: ^( OP_PCODE semanticbody )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_PCODE, "OP_PCODE"), root_1);
						adaptor.addChild(root_1, stream_semanticbody.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:258:4: lc= KEY_UNIMPL
					{
					lc=(Token)match(input,KEY_UNIMPL,FOLLOW_KEY_UNIMPL_in_ctorsemantic1627); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_UNIMPL.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 258:18: -> ^( OP_PCODE[$lc] OP_UNIMPL[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:258:21: ^( OP_PCODE[$lc] OP_UNIMPL[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_PCODE, lc), root_1);
						adaptor.addChild(root_1, (CommonTree)adaptor.create(OP_UNIMPL, lc));
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "ctorsemantic"


	public static class bitpattern_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "bitpattern"
	// ghidra/sleigh/grammar/SleighParser.g:261:1: bitpattern : pequation -> ^( OP_BIT_PATTERN pequation ) ;
	public final SleighParser.bitpattern_return bitpattern() throws RecognitionException {
		SleighParser.bitpattern_return retval = new SleighParser.bitpattern_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pequation115 =null;

		RewriteRuleSubtreeStream stream_pequation=new RewriteRuleSubtreeStream(adaptor,"rule pequation");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:262:2: ( pequation -> ^( OP_BIT_PATTERN pequation ) )
			// ghidra/sleigh/grammar/SleighParser.g:262:4: pequation
			{
			pushFollow(FOLLOW_pequation_in_bitpattern1648);
			pequation115=pequation();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_pequation.add(pequation115.getTree());
			// AST REWRITE
			// elements: pequation
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 262:14: -> ^( OP_BIT_PATTERN pequation )
			{
				// ghidra/sleigh/grammar/SleighParser.g:262:17: ^( OP_BIT_PATTERN pequation )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_BIT_PATTERN, "OP_BIT_PATTERN"), root_1);
				adaptor.addChild(root_1, stream_pequation.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "bitpattern"


	public static class ctorstart_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "ctorstart"
	// ghidra/sleigh/grammar/SleighParser.g:265:1: ctorstart : ( identifier display -> ^( OP_SUBTABLE identifier display ) | display -> ^( OP_TABLE display ) );
	public final SleighParser.ctorstart_return ctorstart() throws RecognitionException {
		SleighParser.ctorstart_return retval = new SleighParser.ctorstart_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope identifier116 =null;
		ParserRuleReturnScope display117 =null;
		ParserRuleReturnScope display118 =null;

		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_display=new RewriteRuleSubtreeStream(adaptor,"rule display");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:266:2: ( identifier display -> ^( OP_SUBTABLE identifier display ) | display -> ^( OP_TABLE display ) )
			int alt32=2;
			int LA32_0 = input.LA(1);
			if ( ((LA32_0 >= IDENTIFIER && LA32_0 <= KEY_WORDSIZE)) ) {
				alt32=1;
			}
			else if ( (LA32_0==COLON) ) {
				alt32=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 32, 0, input);
				throw nvae;
			}

			switch (alt32) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:266:4: identifier display
					{
					pushFollow(FOLLOW_identifier_in_ctorstart1667);
					identifier116=identifier();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_identifier.add(identifier116.getTree());
					pushFollow(FOLLOW_display_in_ctorstart1669);
					display117=display();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_display.add(display117.getTree());
					// AST REWRITE
					// elements: identifier, display
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 266:23: -> ^( OP_SUBTABLE identifier display )
					{
						// ghidra/sleigh/grammar/SleighParser.g:266:26: ^( OP_SUBTABLE identifier display )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SUBTABLE, "OP_SUBTABLE"), root_1);
						adaptor.addChild(root_1, stream_identifier.nextTree());
						adaptor.addChild(root_1, stream_display.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:267:4: display
					{
					pushFollow(FOLLOW_display_in_ctorstart1684);
					display118=display();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_display.add(display118.getTree());
					// AST REWRITE
					// elements: display
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 267:12: -> ^( OP_TABLE display )
					{
						// ghidra/sleigh/grammar/SleighParser.g:267:15: ^( OP_TABLE display )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_TABLE, "OP_TABLE"), root_1);
						adaptor.addChild(root_1, stream_display.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "ctorstart"


	public static class contextblock_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "contextblock"
	// ghidra/sleigh/grammar/SleighParser.g:270:1: contextblock : (lc= LBRACKET ctxstmts RBRACKET -> ^( OP_CONTEXT_BLOCK[$lc, \"[...]\"] ctxstmts ) | -> ^( OP_NO_CONTEXT_BLOCK ) );
	public final SleighParser.contextblock_return contextblock() throws RecognitionException {
		SleighParser.contextblock_return retval = new SleighParser.contextblock_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token RBRACKET120=null;
		ParserRuleReturnScope ctxstmts119 =null;

		CommonTree lc_tree=null;
		CommonTree RBRACKET120_tree=null;
		RewriteRuleTokenStream stream_LBRACKET=new RewriteRuleTokenStream(adaptor,"token LBRACKET");
		RewriteRuleTokenStream stream_RBRACKET=new RewriteRuleTokenStream(adaptor,"token RBRACKET");
		RewriteRuleSubtreeStream stream_ctxstmts=new RewriteRuleSubtreeStream(adaptor,"rule ctxstmts");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:271:2: (lc= LBRACKET ctxstmts RBRACKET -> ^( OP_CONTEXT_BLOCK[$lc, \"[...]\"] ctxstmts ) | -> ^( OP_NO_CONTEXT_BLOCK ) )
			int alt33=2;
			int LA33_0 = input.LA(1);
			if ( (LA33_0==LBRACKET) ) {
				alt33=1;
			}
			else if ( (LA33_0==KEY_UNIMPL||LA33_0==LBRACE) ) {
				alt33=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 33, 0, input);
				throw nvae;
			}

			switch (alt33) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:271:4: lc= LBRACKET ctxstmts RBRACKET
					{
					lc=(Token)match(input,LBRACKET,FOLLOW_LBRACKET_in_contextblock1705); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LBRACKET.add(lc);

					pushFollow(FOLLOW_ctxstmts_in_contextblock1707);
					ctxstmts119=ctxstmts();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_ctxstmts.add(ctxstmts119.getTree());
					RBRACKET120=(Token)match(input,RBRACKET,FOLLOW_RBRACKET_in_contextblock1709); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_RBRACKET.add(RBRACKET120);

					// AST REWRITE
					// elements: ctxstmts
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 271:34: -> ^( OP_CONTEXT_BLOCK[$lc, \"[...]\"] ctxstmts )
					{
						// ghidra/sleigh/grammar/SleighParser.g:271:37: ^( OP_CONTEXT_BLOCK[$lc, \"[...]\"] ctxstmts )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_CONTEXT_BLOCK, lc, "[...]"), root_1);
						adaptor.addChild(root_1, stream_ctxstmts.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:272:4: 
					{
					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 272:4: -> ^( OP_NO_CONTEXT_BLOCK )
					{
						// ghidra/sleigh/grammar/SleighParser.g:272:7: ^( OP_NO_CONTEXT_BLOCK )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_NO_CONTEXT_BLOCK, "OP_NO_CONTEXT_BLOCK"), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "contextblock"


	public static class ctxstmts_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "ctxstmts"
	// ghidra/sleigh/grammar/SleighParser.g:275:1: ctxstmts : ( ctxstmt )* ;
	public final SleighParser.ctxstmts_return ctxstmts() throws RecognitionException {
		SleighParser.ctxstmts_return retval = new SleighParser.ctxstmts_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope ctxstmt121 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:276:2: ( ( ctxstmt )* )
			// ghidra/sleigh/grammar/SleighParser.g:276:4: ( ctxstmt )*
			{
			root_0 = (CommonTree)adaptor.nil();


			// ghidra/sleigh/grammar/SleighParser.g:276:4: ( ctxstmt )*
			loop34:
			while (true) {
				int alt34=2;
				int LA34_0 = input.LA(1);
				if ( ((LA34_0 >= IDENTIFIER && LA34_0 <= KEY_WORDSIZE)) ) {
					alt34=1;
				}

				switch (alt34) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:276:4: ctxstmt
					{
					pushFollow(FOLLOW_ctxstmt_in_ctxstmts1738);
					ctxstmt121=ctxstmt();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, ctxstmt121.getTree());

					}
					break;

				default :
					break loop34;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "ctxstmts"


	public static class ctxstmt_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "ctxstmt"
	// ghidra/sleigh/grammar/SleighParser.g:279:1: ctxstmt : ( ctxassign SEMI !| pfuncall SEMI !);
	public final SleighParser.ctxstmt_return ctxstmt() throws RecognitionException {
		SleighParser.ctxstmt_return retval = new SleighParser.ctxstmt_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token SEMI123=null;
		Token SEMI125=null;
		ParserRuleReturnScope ctxassign122 =null;
		ParserRuleReturnScope pfuncall124 =null;

		CommonTree SEMI123_tree=null;
		CommonTree SEMI125_tree=null;

		try {
			// ghidra/sleigh/grammar/SleighParser.g:280:2: ( ctxassign SEMI !| pfuncall SEMI !)
			int alt35=2;
			switch ( input.LA(1) ) {
			case IDENTIFIER:
				{
				int LA35_1 = input.LA(2);
				if ( (LA35_1==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_1==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ALIGNMENT:
				{
				int LA35_2 = input.LA(2);
				if ( (LA35_2==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_2==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 2, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ATTACH:
				{
				int LA35_3 = input.LA(2);
				if ( (LA35_3==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_3==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 3, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BIG:
				{
				int LA35_4 = input.LA(2);
				if ( (LA35_4==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_4==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 4, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BITRANGE:
				{
				int LA35_5 = input.LA(2);
				if ( (LA35_5==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_5==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 5, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BUILD:
				{
				int LA35_6 = input.LA(2);
				if ( (LA35_6==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_6==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 6, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CALL:
				{
				int LA35_7 = input.LA(2);
				if ( (LA35_7==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_7==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 7, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CONTEXT:
				{
				int LA35_8 = input.LA(2);
				if ( (LA35_8==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_8==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 8, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CROSSBUILD:
				{
				int LA35_9 = input.LA(2);
				if ( (LA35_9==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_9==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 9, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEC:
				{
				int LA35_10 = input.LA(2);
				if ( (LA35_10==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_10==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 10, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEFAULT:
				{
				int LA35_11 = input.LA(2);
				if ( (LA35_11==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_11==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 11, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEFINE:
				{
				int LA35_12 = input.LA(2);
				if ( (LA35_12==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_12==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 12, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ENDIAN:
				{
				int LA35_13 = input.LA(2);
				if ( (LA35_13==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_13==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 13, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_EXPORT:
				{
				int LA35_14 = input.LA(2);
				if ( (LA35_14==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_14==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 14, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_GOTO:
				{
				int LA35_15 = input.LA(2);
				if ( (LA35_15==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_15==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 15, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_HEX:
				{
				int LA35_16 = input.LA(2);
				if ( (LA35_16==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_16==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 16, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_LITTLE:
				{
				int LA35_17 = input.LA(2);
				if ( (LA35_17==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_17==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 17, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_LOCAL:
				{
				int LA35_18 = input.LA(2);
				if ( (LA35_18==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_18==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 18, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_MACRO:
				{
				int LA35_19 = input.LA(2);
				if ( (LA35_19==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_19==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 19, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_NAMES:
				{
				int LA35_20 = input.LA(2);
				if ( (LA35_20==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_20==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 20, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_NOFLOW:
				{
				int LA35_21 = input.LA(2);
				if ( (LA35_21==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_21==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 21, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_OFFSET:
				{
				int LA35_22 = input.LA(2);
				if ( (LA35_22==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_22==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 22, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_PCODEOP:
				{
				int LA35_23 = input.LA(2);
				if ( (LA35_23==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_23==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 23, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_RETURN:
				{
				int LA35_24 = input.LA(2);
				if ( (LA35_24==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_24==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 24, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SIGNED:
				{
				int LA35_25 = input.LA(2);
				if ( (LA35_25==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_25==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 25, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SIZE:
				{
				int LA35_26 = input.LA(2);
				if ( (LA35_26==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_26==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 26, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SPACE:
				{
				int LA35_27 = input.LA(2);
				if ( (LA35_27==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_27==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 27, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_TOKEN:
				{
				int LA35_28 = input.LA(2);
				if ( (LA35_28==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_28==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 28, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_TYPE:
				{
				int LA35_29 = input.LA(2);
				if ( (LA35_29==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_29==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 29, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_UNIMPL:
				{
				int LA35_30 = input.LA(2);
				if ( (LA35_30==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_30==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 30, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_VALUES:
				{
				int LA35_31 = input.LA(2);
				if ( (LA35_31==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_31==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 31, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_VARIABLES:
				{
				int LA35_32 = input.LA(2);
				if ( (LA35_32==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_32==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 32, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_WORDSIZE:
				{
				int LA35_33 = input.LA(2);
				if ( (LA35_33==ASSIGN) ) {
					alt35=1;
				}
				else if ( (LA35_33==LPAREN) ) {
					alt35=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 35, 33, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 35, 0, input);
				throw nvae;
			}
			switch (alt35) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:280:4: ctxassign SEMI !
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_ctxassign_in_ctxstmt1750);
					ctxassign122=ctxassign();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, ctxassign122.getTree());

					SEMI123=(Token)match(input,SEMI,FOLLOW_SEMI_in_ctxstmt1752); if (state.failed) return retval;
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:281:4: pfuncall SEMI !
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_pfuncall_in_ctxstmt1758);
					pfuncall124=pfuncall();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pfuncall124.getTree());

					SEMI125=(Token)match(input,SEMI,FOLLOW_SEMI_in_ctxstmt1760); if (state.failed) return retval;
					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "ctxstmt"


	public static class ctxassign_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "ctxassign"
	// ghidra/sleigh/grammar/SleighParser.g:284:1: ctxassign : ctxlval lc= ASSIGN pexpression -> ^( OP_ASSIGN[$lc] ctxlval pexpression ) ;
	public final SleighParser.ctxassign_return ctxassign() throws RecognitionException {
		SleighParser.ctxassign_return retval = new SleighParser.ctxassign_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		ParserRuleReturnScope ctxlval126 =null;
		ParserRuleReturnScope pexpression127 =null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleSubtreeStream stream_pexpression=new RewriteRuleSubtreeStream(adaptor,"rule pexpression");
		RewriteRuleSubtreeStream stream_ctxlval=new RewriteRuleSubtreeStream(adaptor,"rule ctxlval");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:285:2: ( ctxlval lc= ASSIGN pexpression -> ^( OP_ASSIGN[$lc] ctxlval pexpression ) )
			// ghidra/sleigh/grammar/SleighParser.g:285:4: ctxlval lc= ASSIGN pexpression
			{
			pushFollow(FOLLOW_ctxlval_in_ctxassign1772);
			ctxlval126=ctxlval();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_ctxlval.add(ctxlval126.getTree());
			lc=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_ctxassign1776); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_ASSIGN.add(lc);

			pushFollow(FOLLOW_pexpression_in_ctxassign1778);
			pexpression127=pexpression();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_pexpression.add(pexpression127.getTree());
			// AST REWRITE
			// elements: pexpression, ctxlval
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 285:34: -> ^( OP_ASSIGN[$lc] ctxlval pexpression )
			{
				// ghidra/sleigh/grammar/SleighParser.g:285:37: ^( OP_ASSIGN[$lc] ctxlval pexpression )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_ASSIGN, lc), root_1);
				adaptor.addChild(root_1, stream_ctxlval.nextTree());
				adaptor.addChild(root_1, stream_pexpression.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "ctxassign"


	public static class ctxlval_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "ctxlval"
	// ghidra/sleigh/grammar/SleighParser.g:288:1: ctxlval : identifier ;
	public final SleighParser.ctxlval_return ctxlval() throws RecognitionException {
		SleighParser.ctxlval_return retval = new SleighParser.ctxlval_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope identifier128 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:289:2: ( identifier )
			// ghidra/sleigh/grammar/SleighParser.g:289:4: identifier
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_identifier_in_ctxlval1800);
			identifier128=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, identifier128.getTree());

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "ctxlval"


	public static class pfuncall_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pfuncall"
	// ghidra/sleigh/grammar/SleighParser.g:292:1: pfuncall : pexpression_apply ;
	public final SleighParser.pfuncall_return pfuncall() throws RecognitionException {
		SleighParser.pfuncall_return retval = new SleighParser.pfuncall_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression_apply129 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:293:2: ( pexpression_apply )
			// ghidra/sleigh/grammar/SleighParser.g:293:4: pexpression_apply
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression_apply_in_pfuncall1811);
			pexpression_apply129=pexpression_apply();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_apply129.getTree());

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pfuncall"


	public static class pequation_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pequation"
	// ghidra/sleigh/grammar/SleighParser.g:296:1: pequation : pequation_or ;
	public final SleighParser.pequation_return pequation() throws RecognitionException {
		SleighParser.pequation_return retval = new SleighParser.pequation_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pequation_or130 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:297:2: ( pequation_or )
			// ghidra/sleigh/grammar/SleighParser.g:297:4: pequation_or
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pequation_or_in_pequation1822);
			pequation_or130=pequation_or();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pequation_or130.getTree());

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pequation"


	public static class pequation_or_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pequation_or"
	// ghidra/sleigh/grammar/SleighParser.g:300:1: pequation_or : pequation_seq ( pequation_or_op ^ pequation_seq )* ;
	public final SleighParser.pequation_or_return pequation_or() throws RecognitionException {
		SleighParser.pequation_or_return retval = new SleighParser.pequation_or_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pequation_seq131 =null;
		ParserRuleReturnScope pequation_or_op132 =null;
		ParserRuleReturnScope pequation_seq133 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:301:2: ( pequation_seq ( pequation_or_op ^ pequation_seq )* )
			// ghidra/sleigh/grammar/SleighParser.g:301:4: pequation_seq ( pequation_or_op ^ pequation_seq )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pequation_seq_in_pequation_or1833);
			pequation_seq131=pequation_seq();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pequation_seq131.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:301:18: ( pequation_or_op ^ pequation_seq )*
			loop36:
			while (true) {
				int alt36=2;
				int LA36_0 = input.LA(1);
				if ( (LA36_0==PIPE) ) {
					alt36=1;
				}

				switch (alt36) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:301:20: pequation_or_op ^ pequation_seq
					{
					pushFollow(FOLLOW_pequation_or_op_in_pequation_or1837);
					pequation_or_op132=pequation_or_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pequation_or_op132.getTree(), root_0);
					pushFollow(FOLLOW_pequation_seq_in_pequation_or1840);
					pequation_seq133=pequation_seq();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pequation_seq133.getTree());

					}
					break;

				default :
					break loop36;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pequation_or"


	public static class pequation_or_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pequation_or_op"
	// ghidra/sleigh/grammar/SleighParser.g:304:1: pequation_or_op : lc= PIPE -> ^( OP_BOOL_OR[$lc] ) ;
	public final SleighParser.pequation_or_op_return pequation_or_op() throws RecognitionException {
		SleighParser.pequation_or_op_return retval = new SleighParser.pequation_or_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_PIPE=new RewriteRuleTokenStream(adaptor,"token PIPE");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:305:2: (lc= PIPE -> ^( OP_BOOL_OR[$lc] ) )
			// ghidra/sleigh/grammar/SleighParser.g:305:4: lc= PIPE
			{
			lc=(Token)match(input,PIPE,FOLLOW_PIPE_in_pequation_or_op1856); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_PIPE.add(lc);

			// AST REWRITE
			// elements: 
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 305:12: -> ^( OP_BOOL_OR[$lc] )
			{
				// ghidra/sleigh/grammar/SleighParser.g:305:15: ^( OP_BOOL_OR[$lc] )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_BOOL_OR, lc), root_1);
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pequation_or_op"


	public static class pequation_seq_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pequation_seq"
	// ghidra/sleigh/grammar/SleighParser.g:308:1: pequation_seq : pequation_and ( pequation_seq_op ^ pequation_and )* ;
	public final SleighParser.pequation_seq_return pequation_seq() throws RecognitionException {
		SleighParser.pequation_seq_return retval = new SleighParser.pequation_seq_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pequation_and134 =null;
		ParserRuleReturnScope pequation_seq_op135 =null;
		ParserRuleReturnScope pequation_and136 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:309:2: ( pequation_and ( pequation_seq_op ^ pequation_and )* )
			// ghidra/sleigh/grammar/SleighParser.g:309:4: pequation_and ( pequation_seq_op ^ pequation_and )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pequation_and_in_pequation_seq1874);
			pequation_and134=pequation_and();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pequation_and134.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:309:18: ( pequation_seq_op ^ pequation_and )*
			loop37:
			while (true) {
				int alt37=2;
				int LA37_0 = input.LA(1);
				if ( (LA37_0==SEMI) ) {
					alt37=1;
				}

				switch (alt37) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:309:20: pequation_seq_op ^ pequation_and
					{
					pushFollow(FOLLOW_pequation_seq_op_in_pequation_seq1878);
					pequation_seq_op135=pequation_seq_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pequation_seq_op135.getTree(), root_0);
					pushFollow(FOLLOW_pequation_and_in_pequation_seq1881);
					pequation_and136=pequation_and();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pequation_and136.getTree());

					}
					break;

				default :
					break loop37;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pequation_seq"


	public static class pequation_seq_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pequation_seq_op"
	// ghidra/sleigh/grammar/SleighParser.g:312:1: pequation_seq_op : lc= SEMI -> ^( OP_SEQUENCE[$lc] ) ;
	public final SleighParser.pequation_seq_op_return pequation_seq_op() throws RecognitionException {
		SleighParser.pequation_seq_op_return retval = new SleighParser.pequation_seq_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_SEMI=new RewriteRuleTokenStream(adaptor,"token SEMI");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:313:2: (lc= SEMI -> ^( OP_SEQUENCE[$lc] ) )
			// ghidra/sleigh/grammar/SleighParser.g:313:4: lc= SEMI
			{
			lc=(Token)match(input,SEMI,FOLLOW_SEMI_in_pequation_seq_op1897); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_SEMI.add(lc);

			// AST REWRITE
			// elements: 
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 313:12: -> ^( OP_SEQUENCE[$lc] )
			{
				// ghidra/sleigh/grammar/SleighParser.g:313:15: ^( OP_SEQUENCE[$lc] )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SEQUENCE, lc), root_1);
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pequation_seq_op"


	public static class pequation_and_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pequation_and"
	// ghidra/sleigh/grammar/SleighParser.g:316:1: pequation_and : pequation_ellipsis ( pequation_and_op ^ pequation_ellipsis )* ;
	public final SleighParser.pequation_and_return pequation_and() throws RecognitionException {
		SleighParser.pequation_and_return retval = new SleighParser.pequation_and_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pequation_ellipsis137 =null;
		ParserRuleReturnScope pequation_and_op138 =null;
		ParserRuleReturnScope pequation_ellipsis139 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:317:2: ( pequation_ellipsis ( pequation_and_op ^ pequation_ellipsis )* )
			// ghidra/sleigh/grammar/SleighParser.g:317:4: pequation_ellipsis ( pequation_and_op ^ pequation_ellipsis )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pequation_ellipsis_in_pequation_and1915);
			pequation_ellipsis137=pequation_ellipsis();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pequation_ellipsis137.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:317:23: ( pequation_and_op ^ pequation_ellipsis )*
			loop38:
			while (true) {
				int alt38=2;
				int LA38_0 = input.LA(1);
				if ( (LA38_0==AMPERSAND) ) {
					alt38=1;
				}

				switch (alt38) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:317:25: pequation_and_op ^ pequation_ellipsis
					{
					pushFollow(FOLLOW_pequation_and_op_in_pequation_and1919);
					pequation_and_op138=pequation_and_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pequation_and_op138.getTree(), root_0);
					pushFollow(FOLLOW_pequation_ellipsis_in_pequation_and1922);
					pequation_ellipsis139=pequation_ellipsis();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pequation_ellipsis139.getTree());

					}
					break;

				default :
					break loop38;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pequation_and"


	public static class pequation_and_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pequation_and_op"
	// ghidra/sleigh/grammar/SleighParser.g:320:1: pequation_and_op : lc= AMPERSAND -> ^( OP_BOOL_AND[$lc] ) ;
	public final SleighParser.pequation_and_op_return pequation_and_op() throws RecognitionException {
		SleighParser.pequation_and_op_return retval = new SleighParser.pequation_and_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_AMPERSAND=new RewriteRuleTokenStream(adaptor,"token AMPERSAND");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:321:2: (lc= AMPERSAND -> ^( OP_BOOL_AND[$lc] ) )
			// ghidra/sleigh/grammar/SleighParser.g:321:4: lc= AMPERSAND
			{
			lc=(Token)match(input,AMPERSAND,FOLLOW_AMPERSAND_in_pequation_and_op1938); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_AMPERSAND.add(lc);

			// AST REWRITE
			// elements: 
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 321:17: -> ^( OP_BOOL_AND[$lc] )
			{
				// ghidra/sleigh/grammar/SleighParser.g:321:20: ^( OP_BOOL_AND[$lc] )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_BOOL_AND, lc), root_1);
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pequation_and_op"


	public static class pequation_ellipsis_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pequation_ellipsis"
	// ghidra/sleigh/grammar/SleighParser.g:324:1: pequation_ellipsis : (lc= ELLIPSIS pequation_ellipsis_right -> ^( OP_ELLIPSIS[$lc] pequation_ellipsis_right ) | pequation_ellipsis_right );
	public final SleighParser.pequation_ellipsis_return pequation_ellipsis() throws RecognitionException {
		SleighParser.pequation_ellipsis_return retval = new SleighParser.pequation_ellipsis_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		ParserRuleReturnScope pequation_ellipsis_right140 =null;
		ParserRuleReturnScope pequation_ellipsis_right141 =null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_ELLIPSIS=new RewriteRuleTokenStream(adaptor,"token ELLIPSIS");
		RewriteRuleSubtreeStream stream_pequation_ellipsis_right=new RewriteRuleSubtreeStream(adaptor,"rule pequation_ellipsis_right");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:325:2: (lc= ELLIPSIS pequation_ellipsis_right -> ^( OP_ELLIPSIS[$lc] pequation_ellipsis_right ) | pequation_ellipsis_right )
			int alt39=2;
			int LA39_0 = input.LA(1);
			if ( (LA39_0==ELLIPSIS) ) {
				alt39=1;
			}
			else if ( ((LA39_0 >= IDENTIFIER && LA39_0 <= KEY_WORDSIZE)||LA39_0==LPAREN) ) {
				alt39=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 39, 0, input);
				throw nvae;
			}

			switch (alt39) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:325:4: lc= ELLIPSIS pequation_ellipsis_right
					{
					lc=(Token)match(input,ELLIPSIS,FOLLOW_ELLIPSIS_in_pequation_ellipsis1958); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_ELLIPSIS.add(lc);

					pushFollow(FOLLOW_pequation_ellipsis_right_in_pequation_ellipsis1960);
					pequation_ellipsis_right140=pequation_ellipsis_right();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_pequation_ellipsis_right.add(pequation_ellipsis_right140.getTree());
					// AST REWRITE
					// elements: pequation_ellipsis_right
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 325:41: -> ^( OP_ELLIPSIS[$lc] pequation_ellipsis_right )
					{
						// ghidra/sleigh/grammar/SleighParser.g:325:44: ^( OP_ELLIPSIS[$lc] pequation_ellipsis_right )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_ELLIPSIS, lc), root_1);
						adaptor.addChild(root_1, stream_pequation_ellipsis_right.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:326:4: pequation_ellipsis_right
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_pequation_ellipsis_right_in_pequation_ellipsis1974);
					pequation_ellipsis_right141=pequation_ellipsis_right();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pequation_ellipsis_right141.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pequation_ellipsis"


	public static class pequation_ellipsis_right_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pequation_ellipsis_right"
	// ghidra/sleigh/grammar/SleighParser.g:329:1: pequation_ellipsis_right : ( ( pequation_atomic ELLIPSIS )=> pequation_atomic lc= ELLIPSIS -> ^( OP_ELLIPSIS_RIGHT[$lc] pequation_atomic ) | pequation_atomic );
	public final SleighParser.pequation_ellipsis_right_return pequation_ellipsis_right() throws RecognitionException {
		SleighParser.pequation_ellipsis_right_return retval = new SleighParser.pequation_ellipsis_right_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		ParserRuleReturnScope pequation_atomic142 =null;
		ParserRuleReturnScope pequation_atomic143 =null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_ELLIPSIS=new RewriteRuleTokenStream(adaptor,"token ELLIPSIS");
		RewriteRuleSubtreeStream stream_pequation_atomic=new RewriteRuleSubtreeStream(adaptor,"rule pequation_atomic");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:330:2: ( ( pequation_atomic ELLIPSIS )=> pequation_atomic lc= ELLIPSIS -> ^( OP_ELLIPSIS_RIGHT[$lc] pequation_atomic ) | pequation_atomic )
			int alt40=2;
			switch ( input.LA(1) ) {
			case IDENTIFIER:
				{
				int LA40_1 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_ALIGNMENT:
				{
				int LA40_2 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_ATTACH:
				{
				int LA40_3 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_BIG:
				{
				int LA40_4 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_BITRANGE:
				{
				int LA40_5 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_BUILD:
				{
				int LA40_6 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_CALL:
				{
				int LA40_7 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_CONTEXT:
				{
				int LA40_8 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_CROSSBUILD:
				{
				int LA40_9 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_DEC:
				{
				int LA40_10 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_DEFAULT:
				{
				int LA40_11 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_DEFINE:
				{
				int LA40_12 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_ENDIAN:
				{
				int LA40_13 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_EXPORT:
				{
				int LA40_14 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_GOTO:
				{
				int LA40_15 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_HEX:
				{
				int LA40_16 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_LITTLE:
				{
				int LA40_17 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_LOCAL:
				{
				int LA40_18 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_MACRO:
				{
				int LA40_19 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_NAMES:
				{
				int LA40_20 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_NOFLOW:
				{
				int LA40_21 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_OFFSET:
				{
				int LA40_22 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_PCODEOP:
				{
				int LA40_23 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_RETURN:
				{
				int LA40_24 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_SIGNED:
				{
				int LA40_25 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_SIZE:
				{
				int LA40_26 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_SPACE:
				{
				int LA40_27 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_TOKEN:
				{
				int LA40_28 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_TYPE:
				{
				int LA40_29 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_UNIMPL:
				{
				int LA40_30 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_VALUES:
				{
				int LA40_31 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_VARIABLES:
				{
				int LA40_32 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case KEY_WORDSIZE:
				{
				int LA40_33 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			case LPAREN:
				{
				int LA40_34 = input.LA(2);
				if ( (synpred1_SleighParser()) ) {
					alt40=1;
				}
				else if ( (true) ) {
					alt40=2;
				}

				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 40, 0, input);
				throw nvae;
			}
			switch (alt40) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:330:4: ( pequation_atomic ELLIPSIS )=> pequation_atomic lc= ELLIPSIS
					{
					pushFollow(FOLLOW_pequation_atomic_in_pequation_ellipsis_right1992);
					pequation_atomic142=pequation_atomic();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_pequation_atomic.add(pequation_atomic142.getTree());
					lc=(Token)match(input,ELLIPSIS,FOLLOW_ELLIPSIS_in_pequation_ellipsis_right1996); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_ELLIPSIS.add(lc);

					// AST REWRITE
					// elements: pequation_atomic
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 330:63: -> ^( OP_ELLIPSIS_RIGHT[$lc] pequation_atomic )
					{
						// ghidra/sleigh/grammar/SleighParser.g:330:66: ^( OP_ELLIPSIS_RIGHT[$lc] pequation_atomic )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_ELLIPSIS_RIGHT, lc), root_1);
						adaptor.addChild(root_1, stream_pequation_atomic.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:331:4: pequation_atomic
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_pequation_atomic_in_pequation_ellipsis_right2010);
					pequation_atomic143=pequation_atomic();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pequation_atomic143.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pequation_ellipsis_right"


	public static class pequation_atomic_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pequation_atomic"
	// ghidra/sleigh/grammar/SleighParser.g:334:1: pequation_atomic : ( constraint |lc= LPAREN pequation RPAREN -> ^( OP_PARENTHESIZED[$lc,\"(...)\"] pequation ) );
	public final SleighParser.pequation_atomic_return pequation_atomic() throws RecognitionException {
		SleighParser.pequation_atomic_return retval = new SleighParser.pequation_atomic_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token RPAREN146=null;
		ParserRuleReturnScope constraint144 =null;
		ParserRuleReturnScope pequation145 =null;

		CommonTree lc_tree=null;
		CommonTree RPAREN146_tree=null;
		RewriteRuleTokenStream stream_LPAREN=new RewriteRuleTokenStream(adaptor,"token LPAREN");
		RewriteRuleTokenStream stream_RPAREN=new RewriteRuleTokenStream(adaptor,"token RPAREN");
		RewriteRuleSubtreeStream stream_pequation=new RewriteRuleSubtreeStream(adaptor,"rule pequation");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:335:2: ( constraint |lc= LPAREN pequation RPAREN -> ^( OP_PARENTHESIZED[$lc,\"(...)\"] pequation ) )
			int alt41=2;
			int LA41_0 = input.LA(1);
			if ( ((LA41_0 >= IDENTIFIER && LA41_0 <= KEY_WORDSIZE)) ) {
				alt41=1;
			}
			else if ( (LA41_0==LPAREN) ) {
				alt41=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 41, 0, input);
				throw nvae;
			}

			switch (alt41) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:335:4: constraint
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_constraint_in_pequation_atomic2022);
					constraint144=constraint();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, constraint144.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:336:4: lc= LPAREN pequation RPAREN
					{
					lc=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_pequation_atomic2029); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LPAREN.add(lc);

					pushFollow(FOLLOW_pequation_in_pequation_atomic2031);
					pequation145=pequation();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_pequation.add(pequation145.getTree());
					RPAREN146=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_pequation_atomic2033); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_RPAREN.add(RPAREN146);

					// AST REWRITE
					// elements: pequation
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 336:31: -> ^( OP_PARENTHESIZED[$lc,\"(...)\"] pequation )
					{
						// ghidra/sleigh/grammar/SleighParser.g:336:34: ^( OP_PARENTHESIZED[$lc,\"(...)\"] pequation )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_PARENTHESIZED, lc, "(...)"), root_1);
						adaptor.addChild(root_1, stream_pequation.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pequation_atomic"


	public static class constraint_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "constraint"
	// ghidra/sleigh/grammar/SleighParser.g:339:1: constraint : identifier ( constraint_op ^ pexpression2 )? ;
	public final SleighParser.constraint_return constraint() throws RecognitionException {
		SleighParser.constraint_return retval = new SleighParser.constraint_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope identifier147 =null;
		ParserRuleReturnScope constraint_op148 =null;
		ParserRuleReturnScope pexpression2149 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:340:2: ( identifier ( constraint_op ^ pexpression2 )? )
			// ghidra/sleigh/grammar/SleighParser.g:340:4: identifier ( constraint_op ^ pexpression2 )?
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_identifier_in_constraint2053);
			identifier147=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, identifier147.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:340:15: ( constraint_op ^ pexpression2 )?
			int alt42=2;
			int LA42_0 = input.LA(1);
			if ( (LA42_0==ASSIGN||(LA42_0 >= GREAT && LA42_0 <= GREATEQUAL)||(LA42_0 >= LESS && LA42_0 <= LESSEQUAL)||LA42_0==NOTEQUAL) ) {
				alt42=1;
			}
			switch (alt42) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:340:16: constraint_op ^ pexpression2
					{
					pushFollow(FOLLOW_constraint_op_in_constraint2056);
					constraint_op148=constraint_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(constraint_op148.getTree(), root_0);
					pushFollow(FOLLOW_pexpression2_in_constraint2059);
					pexpression2149=pexpression2();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2149.getTree());

					}
					break;

			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "constraint"


	public static class constraint_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "constraint_op"
	// ghidra/sleigh/grammar/SleighParser.g:343:1: constraint_op : (lc= ASSIGN -> ^( OP_EQUAL[$lc] ) |lc= NOTEQUAL -> ^( OP_NOTEQUAL[$lc] ) |lc= LESS -> ^( OP_LESS[$lc] ) |lc= LESSEQUAL -> ^( OP_LESSEQUAL[$lc] ) |lc= GREAT -> ^( OP_GREAT[$lc] ) |lc= GREATEQUAL -> ^( OP_GREATEQUAL[$lc] ) );
	public final SleighParser.constraint_op_return constraint_op() throws RecognitionException {
		SleighParser.constraint_op_return retval = new SleighParser.constraint_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_NOTEQUAL=new RewriteRuleTokenStream(adaptor,"token NOTEQUAL");
		RewriteRuleTokenStream stream_LESSEQUAL=new RewriteRuleTokenStream(adaptor,"token LESSEQUAL");
		RewriteRuleTokenStream stream_GREAT=new RewriteRuleTokenStream(adaptor,"token GREAT");
		RewriteRuleTokenStream stream_LESS=new RewriteRuleTokenStream(adaptor,"token LESS");
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleTokenStream stream_GREATEQUAL=new RewriteRuleTokenStream(adaptor,"token GREATEQUAL");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:344:2: (lc= ASSIGN -> ^( OP_EQUAL[$lc] ) |lc= NOTEQUAL -> ^( OP_NOTEQUAL[$lc] ) |lc= LESS -> ^( OP_LESS[$lc] ) |lc= LESSEQUAL -> ^( OP_LESSEQUAL[$lc] ) |lc= GREAT -> ^( OP_GREAT[$lc] ) |lc= GREATEQUAL -> ^( OP_GREATEQUAL[$lc] ) )
			int alt43=6;
			switch ( input.LA(1) ) {
			case ASSIGN:
				{
				alt43=1;
				}
				break;
			case NOTEQUAL:
				{
				alt43=2;
				}
				break;
			case LESS:
				{
				alt43=3;
				}
				break;
			case LESSEQUAL:
				{
				alt43=4;
				}
				break;
			case GREAT:
				{
				alt43=5;
				}
				break;
			case GREATEQUAL:
				{
				alt43=6;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 43, 0, input);
				throw nvae;
			}
			switch (alt43) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:344:4: lc= ASSIGN
					{
					lc=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_constraint_op2074); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_ASSIGN.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 344:14: -> ^( OP_EQUAL[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:344:17: ^( OP_EQUAL[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_EQUAL, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:345:4: lc= NOTEQUAL
					{
					lc=(Token)match(input,NOTEQUAL,FOLLOW_NOTEQUAL_in_constraint_op2088); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_NOTEQUAL.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 345:16: -> ^( OP_NOTEQUAL[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:345:19: ^( OP_NOTEQUAL[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_NOTEQUAL, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighParser.g:346:4: lc= LESS
					{
					lc=(Token)match(input,LESS,FOLLOW_LESS_in_constraint_op2102); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LESS.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 346:12: -> ^( OP_LESS[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:346:15: ^( OP_LESS[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_LESS, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighParser.g:347:4: lc= LESSEQUAL
					{
					lc=(Token)match(input,LESSEQUAL,FOLLOW_LESSEQUAL_in_constraint_op2116); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LESSEQUAL.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 347:17: -> ^( OP_LESSEQUAL[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:347:20: ^( OP_LESSEQUAL[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_LESSEQUAL, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighParser.g:348:4: lc= GREAT
					{
					lc=(Token)match(input,GREAT,FOLLOW_GREAT_in_constraint_op2130); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_GREAT.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 348:13: -> ^( OP_GREAT[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:348:16: ^( OP_GREAT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_GREAT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighParser.g:349:4: lc= GREATEQUAL
					{
					lc=(Token)match(input,GREATEQUAL,FOLLOW_GREATEQUAL_in_constraint_op2144); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_GREATEQUAL.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 349:18: -> ^( OP_GREATEQUAL[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:349:21: ^( OP_GREATEQUAL[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_GREATEQUAL, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "constraint_op"


	public static class pexpression_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression"
	// ghidra/sleigh/grammar/SleighParser.g:352:1: pexpression : pexpression_or ;
	public final SleighParser.pexpression_return pexpression() throws RecognitionException {
		SleighParser.pexpression_return retval = new SleighParser.pexpression_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression_or150 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:353:2: ( pexpression_or )
			// ghidra/sleigh/grammar/SleighParser.g:353:4: pexpression_or
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression_or_in_pexpression2162);
			pexpression_or150=pexpression_or();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_or150.getTree());

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression"


	public static class pexpression_or_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_or"
	// ghidra/sleigh/grammar/SleighParser.g:356:1: pexpression_or : pexpression_xor ( pexpression_or_op ^ pexpression_xor )* ;
	public final SleighParser.pexpression_or_return pexpression_or() throws RecognitionException {
		SleighParser.pexpression_or_return retval = new SleighParser.pexpression_or_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression_xor151 =null;
		ParserRuleReturnScope pexpression_or_op152 =null;
		ParserRuleReturnScope pexpression_xor153 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:357:2: ( pexpression_xor ( pexpression_or_op ^ pexpression_xor )* )
			// ghidra/sleigh/grammar/SleighParser.g:357:4: pexpression_xor ( pexpression_or_op ^ pexpression_xor )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression_xor_in_pexpression_or2173);
			pexpression_xor151=pexpression_xor();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_xor151.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:357:20: ( pexpression_or_op ^ pexpression_xor )*
			loop44:
			while (true) {
				int alt44=2;
				int LA44_0 = input.LA(1);
				if ( (LA44_0==PIPE||LA44_0==SPEC_OR) ) {
					alt44=1;
				}

				switch (alt44) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:357:21: pexpression_or_op ^ pexpression_xor
					{
					pushFollow(FOLLOW_pexpression_or_op_in_pexpression_or2176);
					pexpression_or_op152=pexpression_or_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression_or_op152.getTree(), root_0);
					pushFollow(FOLLOW_pexpression_xor_in_pexpression_or2179);
					pexpression_xor153=pexpression_xor();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_xor153.getTree());

					}
					break;

				default :
					break loop44;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_or"


	public static class pexpression_or_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_or_op"
	// ghidra/sleigh/grammar/SleighParser.g:360:1: pexpression_or_op : (lc= PIPE -> ^( OP_OR[$lc] ) |lc= SPEC_OR -> ^( OP_OR[$lc] ) );
	public final SleighParser.pexpression_or_op_return pexpression_or_op() throws RecognitionException {
		SleighParser.pexpression_or_op_return retval = new SleighParser.pexpression_or_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_SPEC_OR=new RewriteRuleTokenStream(adaptor,"token SPEC_OR");
		RewriteRuleTokenStream stream_PIPE=new RewriteRuleTokenStream(adaptor,"token PIPE");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:361:2: (lc= PIPE -> ^( OP_OR[$lc] ) |lc= SPEC_OR -> ^( OP_OR[$lc] ) )
			int alt45=2;
			int LA45_0 = input.LA(1);
			if ( (LA45_0==PIPE) ) {
				alt45=1;
			}
			else if ( (LA45_0==SPEC_OR) ) {
				alt45=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 45, 0, input);
				throw nvae;
			}

			switch (alt45) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:361:4: lc= PIPE
					{
					lc=(Token)match(input,PIPE,FOLLOW_PIPE_in_pexpression_or_op2194); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_PIPE.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 361:12: -> ^( OP_OR[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:361:15: ^( OP_OR[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_OR, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:362:4: lc= SPEC_OR
					{
					lc=(Token)match(input,SPEC_OR,FOLLOW_SPEC_OR_in_pexpression_or_op2208); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_SPEC_OR.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 362:15: -> ^( OP_OR[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:362:18: ^( OP_OR[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_OR, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_or_op"


	public static class pexpression_xor_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_xor"
	// ghidra/sleigh/grammar/SleighParser.g:365:1: pexpression_xor : pexpression_and ( pexpression_xor_op ^ pexpression_and )* ;
	public final SleighParser.pexpression_xor_return pexpression_xor() throws RecognitionException {
		SleighParser.pexpression_xor_return retval = new SleighParser.pexpression_xor_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression_and154 =null;
		ParserRuleReturnScope pexpression_xor_op155 =null;
		ParserRuleReturnScope pexpression_and156 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:366:2: ( pexpression_and ( pexpression_xor_op ^ pexpression_and )* )
			// ghidra/sleigh/grammar/SleighParser.g:366:4: pexpression_and ( pexpression_xor_op ^ pexpression_and )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression_and_in_pexpression_xor2226);
			pexpression_and154=pexpression_and();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_and154.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:366:20: ( pexpression_xor_op ^ pexpression_and )*
			loop46:
			while (true) {
				int alt46=2;
				int LA46_0 = input.LA(1);
				if ( (LA46_0==CARET||LA46_0==SPEC_XOR) ) {
					alt46=1;
				}

				switch (alt46) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:366:21: pexpression_xor_op ^ pexpression_and
					{
					pushFollow(FOLLOW_pexpression_xor_op_in_pexpression_xor2229);
					pexpression_xor_op155=pexpression_xor_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression_xor_op155.getTree(), root_0);
					pushFollow(FOLLOW_pexpression_and_in_pexpression_xor2232);
					pexpression_and156=pexpression_and();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_and156.getTree());

					}
					break;

				default :
					break loop46;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_xor"


	public static class pexpression_xor_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_xor_op"
	// ghidra/sleigh/grammar/SleighParser.g:369:1: pexpression_xor_op : (lc= CARET -> ^( OP_XOR[$lc] ) |lc= SPEC_XOR -> ^( OP_XOR[$lc] ) );
	public final SleighParser.pexpression_xor_op_return pexpression_xor_op() throws RecognitionException {
		SleighParser.pexpression_xor_op_return retval = new SleighParser.pexpression_xor_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_SPEC_XOR=new RewriteRuleTokenStream(adaptor,"token SPEC_XOR");
		RewriteRuleTokenStream stream_CARET=new RewriteRuleTokenStream(adaptor,"token CARET");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:370:2: (lc= CARET -> ^( OP_XOR[$lc] ) |lc= SPEC_XOR -> ^( OP_XOR[$lc] ) )
			int alt47=2;
			int LA47_0 = input.LA(1);
			if ( (LA47_0==CARET) ) {
				alt47=1;
			}
			else if ( (LA47_0==SPEC_XOR) ) {
				alt47=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 47, 0, input);
				throw nvae;
			}

			switch (alt47) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:370:4: lc= CARET
					{
					lc=(Token)match(input,CARET,FOLLOW_CARET_in_pexpression_xor_op2247); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_CARET.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 370:13: -> ^( OP_XOR[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:370:16: ^( OP_XOR[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_XOR, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:371:4: lc= SPEC_XOR
					{
					lc=(Token)match(input,SPEC_XOR,FOLLOW_SPEC_XOR_in_pexpression_xor_op2261); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_SPEC_XOR.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 371:16: -> ^( OP_XOR[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:371:19: ^( OP_XOR[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_XOR, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_xor_op"


	public static class pexpression_and_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_and"
	// ghidra/sleigh/grammar/SleighParser.g:374:1: pexpression_and : pexpression_shift ( pexpression_and_op ^ pexpression_shift )* ;
	public final SleighParser.pexpression_and_return pexpression_and() throws RecognitionException {
		SleighParser.pexpression_and_return retval = new SleighParser.pexpression_and_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression_shift157 =null;
		ParserRuleReturnScope pexpression_and_op158 =null;
		ParserRuleReturnScope pexpression_shift159 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:375:2: ( pexpression_shift ( pexpression_and_op ^ pexpression_shift )* )
			// ghidra/sleigh/grammar/SleighParser.g:375:4: pexpression_shift ( pexpression_and_op ^ pexpression_shift )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression_shift_in_pexpression_and2279);
			pexpression_shift157=pexpression_shift();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_shift157.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:375:22: ( pexpression_and_op ^ pexpression_shift )*
			loop48:
			while (true) {
				int alt48=2;
				int LA48_0 = input.LA(1);
				if ( (LA48_0==AMPERSAND||LA48_0==SPEC_AND) ) {
					alt48=1;
				}

				switch (alt48) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:375:23: pexpression_and_op ^ pexpression_shift
					{
					pushFollow(FOLLOW_pexpression_and_op_in_pexpression_and2282);
					pexpression_and_op158=pexpression_and_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression_and_op158.getTree(), root_0);
					pushFollow(FOLLOW_pexpression_shift_in_pexpression_and2285);
					pexpression_shift159=pexpression_shift();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_shift159.getTree());

					}
					break;

				default :
					break loop48;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_and"


	public static class pexpression_and_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_and_op"
	// ghidra/sleigh/grammar/SleighParser.g:378:1: pexpression_and_op : (lc= AMPERSAND -> ^( OP_AND[$lc] ) |lc= SPEC_AND -> ^( OP_AND[$lc] ) );
	public final SleighParser.pexpression_and_op_return pexpression_and_op() throws RecognitionException {
		SleighParser.pexpression_and_op_return retval = new SleighParser.pexpression_and_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_AMPERSAND=new RewriteRuleTokenStream(adaptor,"token AMPERSAND");
		RewriteRuleTokenStream stream_SPEC_AND=new RewriteRuleTokenStream(adaptor,"token SPEC_AND");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:379:2: (lc= AMPERSAND -> ^( OP_AND[$lc] ) |lc= SPEC_AND -> ^( OP_AND[$lc] ) )
			int alt49=2;
			int LA49_0 = input.LA(1);
			if ( (LA49_0==AMPERSAND) ) {
				alt49=1;
			}
			else if ( (LA49_0==SPEC_AND) ) {
				alt49=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 49, 0, input);
				throw nvae;
			}

			switch (alt49) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:379:4: lc= AMPERSAND
					{
					lc=(Token)match(input,AMPERSAND,FOLLOW_AMPERSAND_in_pexpression_and_op2300); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_AMPERSAND.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 379:17: -> ^( OP_AND[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:379:20: ^( OP_AND[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_AND, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:380:4: lc= SPEC_AND
					{
					lc=(Token)match(input,SPEC_AND,FOLLOW_SPEC_AND_in_pexpression_and_op2314); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_SPEC_AND.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 380:16: -> ^( OP_AND[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:380:19: ^( OP_AND[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_AND, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_and_op"


	public static class pexpression_shift_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_shift"
	// ghidra/sleigh/grammar/SleighParser.g:383:1: pexpression_shift : pexpression_add ( pexpression_shift_op ^ pexpression_add )* ;
	public final SleighParser.pexpression_shift_return pexpression_shift() throws RecognitionException {
		SleighParser.pexpression_shift_return retval = new SleighParser.pexpression_shift_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression_add160 =null;
		ParserRuleReturnScope pexpression_shift_op161 =null;
		ParserRuleReturnScope pexpression_add162 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:384:2: ( pexpression_add ( pexpression_shift_op ^ pexpression_add )* )
			// ghidra/sleigh/grammar/SleighParser.g:384:4: pexpression_add ( pexpression_shift_op ^ pexpression_add )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression_add_in_pexpression_shift2332);
			pexpression_add160=pexpression_add();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_add160.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:384:20: ( pexpression_shift_op ^ pexpression_add )*
			loop50:
			while (true) {
				int alt50=2;
				int LA50_0 = input.LA(1);
				if ( (LA50_0==LEFT||LA50_0==RIGHT) ) {
					alt50=1;
				}

				switch (alt50) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:384:21: pexpression_shift_op ^ pexpression_add
					{
					pushFollow(FOLLOW_pexpression_shift_op_in_pexpression_shift2335);
					pexpression_shift_op161=pexpression_shift_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression_shift_op161.getTree(), root_0);
					pushFollow(FOLLOW_pexpression_add_in_pexpression_shift2338);
					pexpression_add162=pexpression_add();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_add162.getTree());

					}
					break;

				default :
					break loop50;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_shift"


	public static class pexpression_shift_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_shift_op"
	// ghidra/sleigh/grammar/SleighParser.g:387:1: pexpression_shift_op : (lc= LEFT -> ^( OP_LEFT[$lc] ) |lc= RIGHT -> ^( OP_RIGHT[$lc] ) );
	public final SleighParser.pexpression_shift_op_return pexpression_shift_op() throws RecognitionException {
		SleighParser.pexpression_shift_op_return retval = new SleighParser.pexpression_shift_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_LEFT=new RewriteRuleTokenStream(adaptor,"token LEFT");
		RewriteRuleTokenStream stream_RIGHT=new RewriteRuleTokenStream(adaptor,"token RIGHT");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:388:2: (lc= LEFT -> ^( OP_LEFT[$lc] ) |lc= RIGHT -> ^( OP_RIGHT[$lc] ) )
			int alt51=2;
			int LA51_0 = input.LA(1);
			if ( (LA51_0==LEFT) ) {
				alt51=1;
			}
			else if ( (LA51_0==RIGHT) ) {
				alt51=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 51, 0, input);
				throw nvae;
			}

			switch (alt51) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:388:4: lc= LEFT
					{
					lc=(Token)match(input,LEFT,FOLLOW_LEFT_in_pexpression_shift_op2353); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LEFT.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 388:12: -> ^( OP_LEFT[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:388:15: ^( OP_LEFT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_LEFT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:389:4: lc= RIGHT
					{
					lc=(Token)match(input,RIGHT,FOLLOW_RIGHT_in_pexpression_shift_op2367); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_RIGHT.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 389:13: -> ^( OP_RIGHT[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:389:16: ^( OP_RIGHT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_RIGHT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_shift_op"


	public static class pexpression_add_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_add"
	// ghidra/sleigh/grammar/SleighParser.g:392:1: pexpression_add : pexpression_mult ( pexpression_add_op ^ pexpression_mult )* ;
	public final SleighParser.pexpression_add_return pexpression_add() throws RecognitionException {
		SleighParser.pexpression_add_return retval = new SleighParser.pexpression_add_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression_mult163 =null;
		ParserRuleReturnScope pexpression_add_op164 =null;
		ParserRuleReturnScope pexpression_mult165 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:393:2: ( pexpression_mult ( pexpression_add_op ^ pexpression_mult )* )
			// ghidra/sleigh/grammar/SleighParser.g:393:4: pexpression_mult ( pexpression_add_op ^ pexpression_mult )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression_mult_in_pexpression_add2385);
			pexpression_mult163=pexpression_mult();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_mult163.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:393:21: ( pexpression_add_op ^ pexpression_mult )*
			loop52:
			while (true) {
				int alt52=2;
				int LA52_0 = input.LA(1);
				if ( (LA52_0==MINUS||LA52_0==PLUS) ) {
					alt52=1;
				}

				switch (alt52) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:393:22: pexpression_add_op ^ pexpression_mult
					{
					pushFollow(FOLLOW_pexpression_add_op_in_pexpression_add2388);
					pexpression_add_op164=pexpression_add_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression_add_op164.getTree(), root_0);
					pushFollow(FOLLOW_pexpression_mult_in_pexpression_add2391);
					pexpression_mult165=pexpression_mult();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_mult165.getTree());

					}
					break;

				default :
					break loop52;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_add"


	public static class pexpression_add_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_add_op"
	// ghidra/sleigh/grammar/SleighParser.g:396:1: pexpression_add_op : (lc= PLUS -> ^( OP_ADD[$lc] ) |lc= MINUS -> ^( OP_SUB[$lc] ) );
	public final SleighParser.pexpression_add_op_return pexpression_add_op() throws RecognitionException {
		SleighParser.pexpression_add_op_return retval = new SleighParser.pexpression_add_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_PLUS=new RewriteRuleTokenStream(adaptor,"token PLUS");
		RewriteRuleTokenStream stream_MINUS=new RewriteRuleTokenStream(adaptor,"token MINUS");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:397:2: (lc= PLUS -> ^( OP_ADD[$lc] ) |lc= MINUS -> ^( OP_SUB[$lc] ) )
			int alt53=2;
			int LA53_0 = input.LA(1);
			if ( (LA53_0==PLUS) ) {
				alt53=1;
			}
			else if ( (LA53_0==MINUS) ) {
				alt53=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 53, 0, input);
				throw nvae;
			}

			switch (alt53) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:397:4: lc= PLUS
					{
					lc=(Token)match(input,PLUS,FOLLOW_PLUS_in_pexpression_add_op2406); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_PLUS.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 397:12: -> ^( OP_ADD[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:397:15: ^( OP_ADD[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_ADD, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:398:4: lc= MINUS
					{
					lc=(Token)match(input,MINUS,FOLLOW_MINUS_in_pexpression_add_op2420); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_MINUS.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 398:13: -> ^( OP_SUB[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:398:16: ^( OP_SUB[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SUB, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_add_op"


	public static class pexpression_mult_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_mult"
	// ghidra/sleigh/grammar/SleighParser.g:401:1: pexpression_mult : pexpression_unary ( pexpression_mult_op ^ pexpression_unary )* ;
	public final SleighParser.pexpression_mult_return pexpression_mult() throws RecognitionException {
		SleighParser.pexpression_mult_return retval = new SleighParser.pexpression_mult_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression_unary166 =null;
		ParserRuleReturnScope pexpression_mult_op167 =null;
		ParserRuleReturnScope pexpression_unary168 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:402:2: ( pexpression_unary ( pexpression_mult_op ^ pexpression_unary )* )
			// ghidra/sleigh/grammar/SleighParser.g:402:4: pexpression_unary ( pexpression_mult_op ^ pexpression_unary )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression_unary_in_pexpression_mult2438);
			pexpression_unary166=pexpression_unary();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_unary166.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:402:22: ( pexpression_mult_op ^ pexpression_unary )*
			loop54:
			while (true) {
				int alt54=2;
				int LA54_0 = input.LA(1);
				if ( (LA54_0==ASTERISK||LA54_0==SLASH) ) {
					alt54=1;
				}

				switch (alt54) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:402:23: pexpression_mult_op ^ pexpression_unary
					{
					pushFollow(FOLLOW_pexpression_mult_op_in_pexpression_mult2441);
					pexpression_mult_op167=pexpression_mult_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression_mult_op167.getTree(), root_0);
					pushFollow(FOLLOW_pexpression_unary_in_pexpression_mult2444);
					pexpression_unary168=pexpression_unary();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_unary168.getTree());

					}
					break;

				default :
					break loop54;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_mult"


	public static class pexpression_mult_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_mult_op"
	// ghidra/sleigh/grammar/SleighParser.g:405:1: pexpression_mult_op : (lc= ASTERISK -> ^( OP_MULT[$lc] ) |lc= SLASH -> ^( OP_DIV[$lc] ) );
	public final SleighParser.pexpression_mult_op_return pexpression_mult_op() throws RecognitionException {
		SleighParser.pexpression_mult_op_return retval = new SleighParser.pexpression_mult_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_SLASH=new RewriteRuleTokenStream(adaptor,"token SLASH");
		RewriteRuleTokenStream stream_ASTERISK=new RewriteRuleTokenStream(adaptor,"token ASTERISK");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:406:2: (lc= ASTERISK -> ^( OP_MULT[$lc] ) |lc= SLASH -> ^( OP_DIV[$lc] ) )
			int alt55=2;
			int LA55_0 = input.LA(1);
			if ( (LA55_0==ASTERISK) ) {
				alt55=1;
			}
			else if ( (LA55_0==SLASH) ) {
				alt55=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 55, 0, input);
				throw nvae;
			}

			switch (alt55) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:406:4: lc= ASTERISK
					{
					lc=(Token)match(input,ASTERISK,FOLLOW_ASTERISK_in_pexpression_mult_op2459); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_ASTERISK.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 406:16: -> ^( OP_MULT[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:406:19: ^( OP_MULT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_MULT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:407:4: lc= SLASH
					{
					lc=(Token)match(input,SLASH,FOLLOW_SLASH_in_pexpression_mult_op2473); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_SLASH.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 407:13: -> ^( OP_DIV[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:407:16: ^( OP_DIV[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_DIV, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_mult_op"


	public static class pexpression_unary_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_unary"
	// ghidra/sleigh/grammar/SleighParser.g:410:1: pexpression_unary : ( pexpression_unary_op ^ pexpression_term | pexpression_func );
	public final SleighParser.pexpression_unary_return pexpression_unary() throws RecognitionException {
		SleighParser.pexpression_unary_return retval = new SleighParser.pexpression_unary_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression_unary_op169 =null;
		ParserRuleReturnScope pexpression_term170 =null;
		ParserRuleReturnScope pexpression_func171 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:411:2: ( pexpression_unary_op ^ pexpression_term | pexpression_func )
			int alt56=2;
			int LA56_0 = input.LA(1);
			if ( (LA56_0==MINUS||LA56_0==TILDE) ) {
				alt56=1;
			}
			else if ( (LA56_0==BIN_INT||LA56_0==DEC_INT||(LA56_0 >= HEX_INT && LA56_0 <= KEY_WORDSIZE)||LA56_0==LPAREN) ) {
				alt56=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 56, 0, input);
				throw nvae;
			}

			switch (alt56) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:411:4: pexpression_unary_op ^ pexpression_term
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_pexpression_unary_op_in_pexpression_unary2491);
					pexpression_unary_op169=pexpression_unary_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression_unary_op169.getTree(), root_0);
					pushFollow(FOLLOW_pexpression_term_in_pexpression_unary2494);
					pexpression_term170=pexpression_term();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_term170.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:412:4: pexpression_func
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_pexpression_func_in_pexpression_unary2499);
					pexpression_func171=pexpression_func();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_func171.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_unary"


	public static class pexpression_unary_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_unary_op"
	// ghidra/sleigh/grammar/SleighParser.g:415:1: pexpression_unary_op : (lc= MINUS -> ^( OP_NEGATE[$lc] ) |lc= TILDE -> ^( OP_INVERT[$lc] ) );
	public final SleighParser.pexpression_unary_op_return pexpression_unary_op() throws RecognitionException {
		SleighParser.pexpression_unary_op_return retval = new SleighParser.pexpression_unary_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_TILDE=new RewriteRuleTokenStream(adaptor,"token TILDE");
		RewriteRuleTokenStream stream_MINUS=new RewriteRuleTokenStream(adaptor,"token MINUS");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:416:2: (lc= MINUS -> ^( OP_NEGATE[$lc] ) |lc= TILDE -> ^( OP_INVERT[$lc] ) )
			int alt57=2;
			int LA57_0 = input.LA(1);
			if ( (LA57_0==MINUS) ) {
				alt57=1;
			}
			else if ( (LA57_0==TILDE) ) {
				alt57=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 57, 0, input);
				throw nvae;
			}

			switch (alt57) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:416:4: lc= MINUS
					{
					lc=(Token)match(input,MINUS,FOLLOW_MINUS_in_pexpression_unary_op2512); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_MINUS.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 416:13: -> ^( OP_NEGATE[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:416:16: ^( OP_NEGATE[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_NEGATE, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:417:4: lc= TILDE
					{
					lc=(Token)match(input,TILDE,FOLLOW_TILDE_in_pexpression_unary_op2526); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_TILDE.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 417:13: -> ^( OP_INVERT[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:417:16: ^( OP_INVERT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_INVERT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_unary_op"


	public static class pexpression_func_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_func"
	// ghidra/sleigh/grammar/SleighParser.g:420:1: pexpression_func : ( pexpression_apply | pexpression_term );
	public final SleighParser.pexpression_func_return pexpression_func() throws RecognitionException {
		SleighParser.pexpression_func_return retval = new SleighParser.pexpression_func_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression_apply172 =null;
		ParserRuleReturnScope pexpression_term173 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:421:2: ( pexpression_apply | pexpression_term )
			int alt58=2;
			switch ( input.LA(1) ) {
			case IDENTIFIER:
				{
				int LA58_1 = input.LA(2);
				if ( (LA58_1==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_1==AMPERSAND||LA58_1==ASTERISK||LA58_1==CARET||LA58_1==COMMA||LA58_1==LEFT||LA58_1==MINUS||(LA58_1 >= PIPE && LA58_1 <= PLUS)||(LA58_1 >= RIGHT && LA58_1 <= RPAREN)||LA58_1==SEMI||LA58_1==SLASH||(LA58_1 >= SPEC_AND && LA58_1 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ALIGNMENT:
				{
				int LA58_2 = input.LA(2);
				if ( (LA58_2==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_2==AMPERSAND||LA58_2==ASTERISK||LA58_2==CARET||LA58_2==COMMA||LA58_2==LEFT||LA58_2==MINUS||(LA58_2 >= PIPE && LA58_2 <= PLUS)||(LA58_2 >= RIGHT && LA58_2 <= RPAREN)||LA58_2==SEMI||LA58_2==SLASH||(LA58_2 >= SPEC_AND && LA58_2 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 2, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ATTACH:
				{
				int LA58_3 = input.LA(2);
				if ( (LA58_3==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_3==AMPERSAND||LA58_3==ASTERISK||LA58_3==CARET||LA58_3==COMMA||LA58_3==LEFT||LA58_3==MINUS||(LA58_3 >= PIPE && LA58_3 <= PLUS)||(LA58_3 >= RIGHT && LA58_3 <= RPAREN)||LA58_3==SEMI||LA58_3==SLASH||(LA58_3 >= SPEC_AND && LA58_3 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 3, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BIG:
				{
				int LA58_4 = input.LA(2);
				if ( (LA58_4==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_4==AMPERSAND||LA58_4==ASTERISK||LA58_4==CARET||LA58_4==COMMA||LA58_4==LEFT||LA58_4==MINUS||(LA58_4 >= PIPE && LA58_4 <= PLUS)||(LA58_4 >= RIGHT && LA58_4 <= RPAREN)||LA58_4==SEMI||LA58_4==SLASH||(LA58_4 >= SPEC_AND && LA58_4 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 4, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BITRANGE:
				{
				int LA58_5 = input.LA(2);
				if ( (LA58_5==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_5==AMPERSAND||LA58_5==ASTERISK||LA58_5==CARET||LA58_5==COMMA||LA58_5==LEFT||LA58_5==MINUS||(LA58_5 >= PIPE && LA58_5 <= PLUS)||(LA58_5 >= RIGHT && LA58_5 <= RPAREN)||LA58_5==SEMI||LA58_5==SLASH||(LA58_5 >= SPEC_AND && LA58_5 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 5, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BUILD:
				{
				int LA58_6 = input.LA(2);
				if ( (LA58_6==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_6==AMPERSAND||LA58_6==ASTERISK||LA58_6==CARET||LA58_6==COMMA||LA58_6==LEFT||LA58_6==MINUS||(LA58_6 >= PIPE && LA58_6 <= PLUS)||(LA58_6 >= RIGHT && LA58_6 <= RPAREN)||LA58_6==SEMI||LA58_6==SLASH||(LA58_6 >= SPEC_AND && LA58_6 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 6, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CALL:
				{
				int LA58_7 = input.LA(2);
				if ( (LA58_7==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_7==AMPERSAND||LA58_7==ASTERISK||LA58_7==CARET||LA58_7==COMMA||LA58_7==LEFT||LA58_7==MINUS||(LA58_7 >= PIPE && LA58_7 <= PLUS)||(LA58_7 >= RIGHT && LA58_7 <= RPAREN)||LA58_7==SEMI||LA58_7==SLASH||(LA58_7 >= SPEC_AND && LA58_7 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 7, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CONTEXT:
				{
				int LA58_8 = input.LA(2);
				if ( (LA58_8==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_8==AMPERSAND||LA58_8==ASTERISK||LA58_8==CARET||LA58_8==COMMA||LA58_8==LEFT||LA58_8==MINUS||(LA58_8 >= PIPE && LA58_8 <= PLUS)||(LA58_8 >= RIGHT && LA58_8 <= RPAREN)||LA58_8==SEMI||LA58_8==SLASH||(LA58_8 >= SPEC_AND && LA58_8 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 8, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CROSSBUILD:
				{
				int LA58_9 = input.LA(2);
				if ( (LA58_9==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_9==AMPERSAND||LA58_9==ASTERISK||LA58_9==CARET||LA58_9==COMMA||LA58_9==LEFT||LA58_9==MINUS||(LA58_9 >= PIPE && LA58_9 <= PLUS)||(LA58_9 >= RIGHT && LA58_9 <= RPAREN)||LA58_9==SEMI||LA58_9==SLASH||(LA58_9 >= SPEC_AND && LA58_9 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 9, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEC:
				{
				int LA58_10 = input.LA(2);
				if ( (LA58_10==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_10==AMPERSAND||LA58_10==ASTERISK||LA58_10==CARET||LA58_10==COMMA||LA58_10==LEFT||LA58_10==MINUS||(LA58_10 >= PIPE && LA58_10 <= PLUS)||(LA58_10 >= RIGHT && LA58_10 <= RPAREN)||LA58_10==SEMI||LA58_10==SLASH||(LA58_10 >= SPEC_AND && LA58_10 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 10, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEFAULT:
				{
				int LA58_11 = input.LA(2);
				if ( (LA58_11==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_11==AMPERSAND||LA58_11==ASTERISK||LA58_11==CARET||LA58_11==COMMA||LA58_11==LEFT||LA58_11==MINUS||(LA58_11 >= PIPE && LA58_11 <= PLUS)||(LA58_11 >= RIGHT && LA58_11 <= RPAREN)||LA58_11==SEMI||LA58_11==SLASH||(LA58_11 >= SPEC_AND && LA58_11 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 11, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEFINE:
				{
				int LA58_12 = input.LA(2);
				if ( (LA58_12==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_12==AMPERSAND||LA58_12==ASTERISK||LA58_12==CARET||LA58_12==COMMA||LA58_12==LEFT||LA58_12==MINUS||(LA58_12 >= PIPE && LA58_12 <= PLUS)||(LA58_12 >= RIGHT && LA58_12 <= RPAREN)||LA58_12==SEMI||LA58_12==SLASH||(LA58_12 >= SPEC_AND && LA58_12 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 12, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ENDIAN:
				{
				int LA58_13 = input.LA(2);
				if ( (LA58_13==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_13==AMPERSAND||LA58_13==ASTERISK||LA58_13==CARET||LA58_13==COMMA||LA58_13==LEFT||LA58_13==MINUS||(LA58_13 >= PIPE && LA58_13 <= PLUS)||(LA58_13 >= RIGHT && LA58_13 <= RPAREN)||LA58_13==SEMI||LA58_13==SLASH||(LA58_13 >= SPEC_AND && LA58_13 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 13, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_EXPORT:
				{
				int LA58_14 = input.LA(2);
				if ( (LA58_14==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_14==AMPERSAND||LA58_14==ASTERISK||LA58_14==CARET||LA58_14==COMMA||LA58_14==LEFT||LA58_14==MINUS||(LA58_14 >= PIPE && LA58_14 <= PLUS)||(LA58_14 >= RIGHT && LA58_14 <= RPAREN)||LA58_14==SEMI||LA58_14==SLASH||(LA58_14 >= SPEC_AND && LA58_14 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 14, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_GOTO:
				{
				int LA58_15 = input.LA(2);
				if ( (LA58_15==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_15==AMPERSAND||LA58_15==ASTERISK||LA58_15==CARET||LA58_15==COMMA||LA58_15==LEFT||LA58_15==MINUS||(LA58_15 >= PIPE && LA58_15 <= PLUS)||(LA58_15 >= RIGHT && LA58_15 <= RPAREN)||LA58_15==SEMI||LA58_15==SLASH||(LA58_15 >= SPEC_AND && LA58_15 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 15, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_HEX:
				{
				int LA58_16 = input.LA(2);
				if ( (LA58_16==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_16==AMPERSAND||LA58_16==ASTERISK||LA58_16==CARET||LA58_16==COMMA||LA58_16==LEFT||LA58_16==MINUS||(LA58_16 >= PIPE && LA58_16 <= PLUS)||(LA58_16 >= RIGHT && LA58_16 <= RPAREN)||LA58_16==SEMI||LA58_16==SLASH||(LA58_16 >= SPEC_AND && LA58_16 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 16, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_LITTLE:
				{
				int LA58_17 = input.LA(2);
				if ( (LA58_17==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_17==AMPERSAND||LA58_17==ASTERISK||LA58_17==CARET||LA58_17==COMMA||LA58_17==LEFT||LA58_17==MINUS||(LA58_17 >= PIPE && LA58_17 <= PLUS)||(LA58_17 >= RIGHT && LA58_17 <= RPAREN)||LA58_17==SEMI||LA58_17==SLASH||(LA58_17 >= SPEC_AND && LA58_17 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 17, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_LOCAL:
				{
				int LA58_18 = input.LA(2);
				if ( (LA58_18==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_18==AMPERSAND||LA58_18==ASTERISK||LA58_18==CARET||LA58_18==COMMA||LA58_18==LEFT||LA58_18==MINUS||(LA58_18 >= PIPE && LA58_18 <= PLUS)||(LA58_18 >= RIGHT && LA58_18 <= RPAREN)||LA58_18==SEMI||LA58_18==SLASH||(LA58_18 >= SPEC_AND && LA58_18 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 18, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_MACRO:
				{
				int LA58_19 = input.LA(2);
				if ( (LA58_19==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_19==AMPERSAND||LA58_19==ASTERISK||LA58_19==CARET||LA58_19==COMMA||LA58_19==LEFT||LA58_19==MINUS||(LA58_19 >= PIPE && LA58_19 <= PLUS)||(LA58_19 >= RIGHT && LA58_19 <= RPAREN)||LA58_19==SEMI||LA58_19==SLASH||(LA58_19 >= SPEC_AND && LA58_19 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 19, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_NAMES:
				{
				int LA58_20 = input.LA(2);
				if ( (LA58_20==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_20==AMPERSAND||LA58_20==ASTERISK||LA58_20==CARET||LA58_20==COMMA||LA58_20==LEFT||LA58_20==MINUS||(LA58_20 >= PIPE && LA58_20 <= PLUS)||(LA58_20 >= RIGHT && LA58_20 <= RPAREN)||LA58_20==SEMI||LA58_20==SLASH||(LA58_20 >= SPEC_AND && LA58_20 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 20, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_NOFLOW:
				{
				int LA58_21 = input.LA(2);
				if ( (LA58_21==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_21==AMPERSAND||LA58_21==ASTERISK||LA58_21==CARET||LA58_21==COMMA||LA58_21==LEFT||LA58_21==MINUS||(LA58_21 >= PIPE && LA58_21 <= PLUS)||(LA58_21 >= RIGHT && LA58_21 <= RPAREN)||LA58_21==SEMI||LA58_21==SLASH||(LA58_21 >= SPEC_AND && LA58_21 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 21, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_OFFSET:
				{
				int LA58_22 = input.LA(2);
				if ( (LA58_22==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_22==AMPERSAND||LA58_22==ASTERISK||LA58_22==CARET||LA58_22==COMMA||LA58_22==LEFT||LA58_22==MINUS||(LA58_22 >= PIPE && LA58_22 <= PLUS)||(LA58_22 >= RIGHT && LA58_22 <= RPAREN)||LA58_22==SEMI||LA58_22==SLASH||(LA58_22 >= SPEC_AND && LA58_22 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 22, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_PCODEOP:
				{
				int LA58_23 = input.LA(2);
				if ( (LA58_23==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_23==AMPERSAND||LA58_23==ASTERISK||LA58_23==CARET||LA58_23==COMMA||LA58_23==LEFT||LA58_23==MINUS||(LA58_23 >= PIPE && LA58_23 <= PLUS)||(LA58_23 >= RIGHT && LA58_23 <= RPAREN)||LA58_23==SEMI||LA58_23==SLASH||(LA58_23 >= SPEC_AND && LA58_23 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 23, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_RETURN:
				{
				int LA58_24 = input.LA(2);
				if ( (LA58_24==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_24==AMPERSAND||LA58_24==ASTERISK||LA58_24==CARET||LA58_24==COMMA||LA58_24==LEFT||LA58_24==MINUS||(LA58_24 >= PIPE && LA58_24 <= PLUS)||(LA58_24 >= RIGHT && LA58_24 <= RPAREN)||LA58_24==SEMI||LA58_24==SLASH||(LA58_24 >= SPEC_AND && LA58_24 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 24, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SIGNED:
				{
				int LA58_25 = input.LA(2);
				if ( (LA58_25==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_25==AMPERSAND||LA58_25==ASTERISK||LA58_25==CARET||LA58_25==COMMA||LA58_25==LEFT||LA58_25==MINUS||(LA58_25 >= PIPE && LA58_25 <= PLUS)||(LA58_25 >= RIGHT && LA58_25 <= RPAREN)||LA58_25==SEMI||LA58_25==SLASH||(LA58_25 >= SPEC_AND && LA58_25 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 25, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SIZE:
				{
				int LA58_26 = input.LA(2);
				if ( (LA58_26==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_26==AMPERSAND||LA58_26==ASTERISK||LA58_26==CARET||LA58_26==COMMA||LA58_26==LEFT||LA58_26==MINUS||(LA58_26 >= PIPE && LA58_26 <= PLUS)||(LA58_26 >= RIGHT && LA58_26 <= RPAREN)||LA58_26==SEMI||LA58_26==SLASH||(LA58_26 >= SPEC_AND && LA58_26 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 26, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SPACE:
				{
				int LA58_27 = input.LA(2);
				if ( (LA58_27==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_27==AMPERSAND||LA58_27==ASTERISK||LA58_27==CARET||LA58_27==COMMA||LA58_27==LEFT||LA58_27==MINUS||(LA58_27 >= PIPE && LA58_27 <= PLUS)||(LA58_27 >= RIGHT && LA58_27 <= RPAREN)||LA58_27==SEMI||LA58_27==SLASH||(LA58_27 >= SPEC_AND && LA58_27 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 27, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_TOKEN:
				{
				int LA58_28 = input.LA(2);
				if ( (LA58_28==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_28==AMPERSAND||LA58_28==ASTERISK||LA58_28==CARET||LA58_28==COMMA||LA58_28==LEFT||LA58_28==MINUS||(LA58_28 >= PIPE && LA58_28 <= PLUS)||(LA58_28 >= RIGHT && LA58_28 <= RPAREN)||LA58_28==SEMI||LA58_28==SLASH||(LA58_28 >= SPEC_AND && LA58_28 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 28, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_TYPE:
				{
				int LA58_29 = input.LA(2);
				if ( (LA58_29==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_29==AMPERSAND||LA58_29==ASTERISK||LA58_29==CARET||LA58_29==COMMA||LA58_29==LEFT||LA58_29==MINUS||(LA58_29 >= PIPE && LA58_29 <= PLUS)||(LA58_29 >= RIGHT && LA58_29 <= RPAREN)||LA58_29==SEMI||LA58_29==SLASH||(LA58_29 >= SPEC_AND && LA58_29 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 29, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_UNIMPL:
				{
				int LA58_30 = input.LA(2);
				if ( (LA58_30==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_30==AMPERSAND||LA58_30==ASTERISK||LA58_30==CARET||LA58_30==COMMA||LA58_30==LEFT||LA58_30==MINUS||(LA58_30 >= PIPE && LA58_30 <= PLUS)||(LA58_30 >= RIGHT && LA58_30 <= RPAREN)||LA58_30==SEMI||LA58_30==SLASH||(LA58_30 >= SPEC_AND && LA58_30 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 30, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_VALUES:
				{
				int LA58_31 = input.LA(2);
				if ( (LA58_31==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_31==AMPERSAND||LA58_31==ASTERISK||LA58_31==CARET||LA58_31==COMMA||LA58_31==LEFT||LA58_31==MINUS||(LA58_31 >= PIPE && LA58_31 <= PLUS)||(LA58_31 >= RIGHT && LA58_31 <= RPAREN)||LA58_31==SEMI||LA58_31==SLASH||(LA58_31 >= SPEC_AND && LA58_31 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 31, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_VARIABLES:
				{
				int LA58_32 = input.LA(2);
				if ( (LA58_32==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_32==AMPERSAND||LA58_32==ASTERISK||LA58_32==CARET||LA58_32==COMMA||LA58_32==LEFT||LA58_32==MINUS||(LA58_32 >= PIPE && LA58_32 <= PLUS)||(LA58_32 >= RIGHT && LA58_32 <= RPAREN)||LA58_32==SEMI||LA58_32==SLASH||(LA58_32 >= SPEC_AND && LA58_32 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 32, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_WORDSIZE:
				{
				int LA58_33 = input.LA(2);
				if ( (LA58_33==LPAREN) ) {
					alt58=1;
				}
				else if ( (LA58_33==AMPERSAND||LA58_33==ASTERISK||LA58_33==CARET||LA58_33==COMMA||LA58_33==LEFT||LA58_33==MINUS||(LA58_33 >= PIPE && LA58_33 <= PLUS)||(LA58_33 >= RIGHT && LA58_33 <= RPAREN)||LA58_33==SEMI||LA58_33==SLASH||(LA58_33 >= SPEC_AND && LA58_33 <= SPEC_XOR)) ) {
					alt58=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 58, 33, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case BIN_INT:
			case DEC_INT:
			case HEX_INT:
			case LPAREN:
				{
				alt58=2;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 58, 0, input);
				throw nvae;
			}
			switch (alt58) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:421:4: pexpression_apply
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_pexpression_apply_in_pexpression_func2544);
					pexpression_apply172=pexpression_apply();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_apply172.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:422:4: pexpression_term
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_pexpression_term_in_pexpression_func2549);
					pexpression_term173=pexpression_term();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression_term173.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_func"


	public static class pexpression_apply_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_apply"
	// ghidra/sleigh/grammar/SleighParser.g:425:1: pexpression_apply : identifier pexpression_operands -> ^( OP_APPLY identifier ( pexpression_operands )? ) ;
	public final SleighParser.pexpression_apply_return pexpression_apply() throws RecognitionException {
		SleighParser.pexpression_apply_return retval = new SleighParser.pexpression_apply_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope identifier174 =null;
		ParserRuleReturnScope pexpression_operands175 =null;

		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_pexpression_operands=new RewriteRuleSubtreeStream(adaptor,"rule pexpression_operands");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:426:2: ( identifier pexpression_operands -> ^( OP_APPLY identifier ( pexpression_operands )? ) )
			// ghidra/sleigh/grammar/SleighParser.g:426:4: identifier pexpression_operands
			{
			pushFollow(FOLLOW_identifier_in_pexpression_apply2560);
			identifier174=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifier.add(identifier174.getTree());
			pushFollow(FOLLOW_pexpression_operands_in_pexpression_apply2562);
			pexpression_operands175=pexpression_operands();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_pexpression_operands.add(pexpression_operands175.getTree());
			// AST REWRITE
			// elements: identifier, pexpression_operands
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 426:36: -> ^( OP_APPLY identifier ( pexpression_operands )? )
			{
				// ghidra/sleigh/grammar/SleighParser.g:426:39: ^( OP_APPLY identifier ( pexpression_operands )? )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_APPLY, "OP_APPLY"), root_1);
				adaptor.addChild(root_1, stream_identifier.nextTree());
				// ghidra/sleigh/grammar/SleighParser.g:426:61: ( pexpression_operands )?
				if ( stream_pexpression_operands.hasNext() ) {
					adaptor.addChild(root_1, stream_pexpression_operands.nextTree());
				}
				stream_pexpression_operands.reset();

				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_apply"


	public static class pexpression_operands_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_operands"
	// ghidra/sleigh/grammar/SleighParser.g:429:1: pexpression_operands : LPAREN ! ( pexpression ( COMMA ! pexpression )* )? RPAREN !;
	public final SleighParser.pexpression_operands_return pexpression_operands() throws RecognitionException {
		SleighParser.pexpression_operands_return retval = new SleighParser.pexpression_operands_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token LPAREN176=null;
		Token COMMA178=null;
		Token RPAREN180=null;
		ParserRuleReturnScope pexpression177 =null;
		ParserRuleReturnScope pexpression179 =null;

		CommonTree LPAREN176_tree=null;
		CommonTree COMMA178_tree=null;
		CommonTree RPAREN180_tree=null;

		try {
			// ghidra/sleigh/grammar/SleighParser.g:430:2: ( LPAREN ! ( pexpression ( COMMA ! pexpression )* )? RPAREN !)
			// ghidra/sleigh/grammar/SleighParser.g:430:4: LPAREN ! ( pexpression ( COMMA ! pexpression )* )? RPAREN !
			{
			root_0 = (CommonTree)adaptor.nil();


			LPAREN176=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_pexpression_operands2584); if (state.failed) return retval;
			// ghidra/sleigh/grammar/SleighParser.g:430:12: ( pexpression ( COMMA ! pexpression )* )?
			int alt60=2;
			int LA60_0 = input.LA(1);
			if ( (LA60_0==BIN_INT||LA60_0==DEC_INT||(LA60_0 >= HEX_INT && LA60_0 <= KEY_WORDSIZE)||(LA60_0 >= LPAREN && LA60_0 <= MINUS)||LA60_0==TILDE) ) {
				alt60=1;
			}
			switch (alt60) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:430:13: pexpression ( COMMA ! pexpression )*
					{
					pushFollow(FOLLOW_pexpression_in_pexpression_operands2588);
					pexpression177=pexpression();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression177.getTree());

					// ghidra/sleigh/grammar/SleighParser.g:430:25: ( COMMA ! pexpression )*
					loop59:
					while (true) {
						int alt59=2;
						int LA59_0 = input.LA(1);
						if ( (LA59_0==COMMA) ) {
							alt59=1;
						}

						switch (alt59) {
						case 1 :
							// ghidra/sleigh/grammar/SleighParser.g:430:26: COMMA ! pexpression
							{
							COMMA178=(Token)match(input,COMMA,FOLLOW_COMMA_in_pexpression_operands2591); if (state.failed) return retval;
							pushFollow(FOLLOW_pexpression_in_pexpression_operands2594);
							pexpression179=pexpression();
							state._fsp--;
							if (state.failed) return retval;
							if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression179.getTree());

							}
							break;

						default :
							break loop59;
						}
					}

					}
					break;

			}

			RPAREN180=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_pexpression_operands2601); if (state.failed) return retval;
			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_operands"


	public static class pexpression_term_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression_term"
	// ghidra/sleigh/grammar/SleighParser.g:433:1: pexpression_term : ( identifier | integer |lc= LPAREN pexpression RPAREN -> ^( OP_PARENTHESIZED[$lc, \"(...)\"] pexpression ) );
	public final SleighParser.pexpression_term_return pexpression_term() throws RecognitionException {
		SleighParser.pexpression_term_return retval = new SleighParser.pexpression_term_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token RPAREN184=null;
		ParserRuleReturnScope identifier181 =null;
		ParserRuleReturnScope integer182 =null;
		ParserRuleReturnScope pexpression183 =null;

		CommonTree lc_tree=null;
		CommonTree RPAREN184_tree=null;
		RewriteRuleTokenStream stream_LPAREN=new RewriteRuleTokenStream(adaptor,"token LPAREN");
		RewriteRuleTokenStream stream_RPAREN=new RewriteRuleTokenStream(adaptor,"token RPAREN");
		RewriteRuleSubtreeStream stream_pexpression=new RewriteRuleSubtreeStream(adaptor,"rule pexpression");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:434:2: ( identifier | integer |lc= LPAREN pexpression RPAREN -> ^( OP_PARENTHESIZED[$lc, \"(...)\"] pexpression ) )
			int alt61=3;
			switch ( input.LA(1) ) {
			case IDENTIFIER:
			case KEY_ALIGNMENT:
			case KEY_ATTACH:
			case KEY_BIG:
			case KEY_BITRANGE:
			case KEY_BUILD:
			case KEY_CALL:
			case KEY_CONTEXT:
			case KEY_CROSSBUILD:
			case KEY_DEC:
			case KEY_DEFAULT:
			case KEY_DEFINE:
			case KEY_ENDIAN:
			case KEY_EXPORT:
			case KEY_GOTO:
			case KEY_HEX:
			case KEY_LITTLE:
			case KEY_LOCAL:
			case KEY_MACRO:
			case KEY_NAMES:
			case KEY_NOFLOW:
			case KEY_OFFSET:
			case KEY_PCODEOP:
			case KEY_RETURN:
			case KEY_SIGNED:
			case KEY_SIZE:
			case KEY_SPACE:
			case KEY_TOKEN:
			case KEY_TYPE:
			case KEY_UNIMPL:
			case KEY_VALUES:
			case KEY_VARIABLES:
			case KEY_WORDSIZE:
				{
				alt61=1;
				}
				break;
			case BIN_INT:
			case DEC_INT:
			case HEX_INT:
				{
				alt61=2;
				}
				break;
			case LPAREN:
				{
				alt61=3;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 61, 0, input);
				throw nvae;
			}
			switch (alt61) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:434:4: identifier
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_identifier_in_pexpression_term2613);
					identifier181=identifier();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, identifier181.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:435:4: integer
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_integer_in_pexpression_term2618);
					integer182=integer();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, integer182.getTree());

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighParser.g:436:4: lc= LPAREN pexpression RPAREN
					{
					lc=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_pexpression_term2625); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LPAREN.add(lc);

					pushFollow(FOLLOW_pexpression_in_pexpression_term2627);
					pexpression183=pexpression();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_pexpression.add(pexpression183.getTree());
					RPAREN184=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_pexpression_term2629); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_RPAREN.add(RPAREN184);

					// AST REWRITE
					// elements: pexpression
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 436:33: -> ^( OP_PARENTHESIZED[$lc, \"(...)\"] pexpression )
					{
						// ghidra/sleigh/grammar/SleighParser.g:436:36: ^( OP_PARENTHESIZED[$lc, \"(...)\"] pexpression )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_PARENTHESIZED, lc, "(...)"), root_1);
						adaptor.addChild(root_1, stream_pexpression.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression_term"


	public static class pexpression2_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2"
	// ghidra/sleigh/grammar/SleighParser.g:439:1: pexpression2 : pexpression2_or ;
	public final SleighParser.pexpression2_return pexpression2() throws RecognitionException {
		SleighParser.pexpression2_return retval = new SleighParser.pexpression2_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression2_or185 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:440:2: ( pexpression2_or )
			// ghidra/sleigh/grammar/SleighParser.g:440:4: pexpression2_or
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression2_or_in_pexpression22649);
			pexpression2_or185=pexpression2_or();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_or185.getTree());

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2"


	public static class pexpression2_or_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_or"
	// ghidra/sleigh/grammar/SleighParser.g:443:1: pexpression2_or : pexpression2_xor ( pexpression2_or_op ^ pexpression2_xor )* ;
	public final SleighParser.pexpression2_or_return pexpression2_or() throws RecognitionException {
		SleighParser.pexpression2_or_return retval = new SleighParser.pexpression2_or_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression2_xor186 =null;
		ParserRuleReturnScope pexpression2_or_op187 =null;
		ParserRuleReturnScope pexpression2_xor188 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:444:2: ( pexpression2_xor ( pexpression2_or_op ^ pexpression2_xor )* )
			// ghidra/sleigh/grammar/SleighParser.g:444:4: pexpression2_xor ( pexpression2_or_op ^ pexpression2_xor )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression2_xor_in_pexpression2_or2660);
			pexpression2_xor186=pexpression2_xor();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_xor186.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:444:21: ( pexpression2_or_op ^ pexpression2_xor )*
			loop62:
			while (true) {
				int alt62=2;
				int LA62_0 = input.LA(1);
				if ( (LA62_0==SPEC_OR) ) {
					alt62=1;
				}

				switch (alt62) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:444:22: pexpression2_or_op ^ pexpression2_xor
					{
					pushFollow(FOLLOW_pexpression2_or_op_in_pexpression2_or2663);
					pexpression2_or_op187=pexpression2_or_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression2_or_op187.getTree(), root_0);
					pushFollow(FOLLOW_pexpression2_xor_in_pexpression2_or2666);
					pexpression2_xor188=pexpression2_xor();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_xor188.getTree());

					}
					break;

				default :
					break loop62;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_or"


	public static class pexpression2_or_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_or_op"
	// ghidra/sleigh/grammar/SleighParser.g:447:1: pexpression2_or_op : lc= SPEC_OR -> ^( OP_OR[$lc] ) ;
	public final SleighParser.pexpression2_or_op_return pexpression2_or_op() throws RecognitionException {
		SleighParser.pexpression2_or_op_return retval = new SleighParser.pexpression2_or_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_SPEC_OR=new RewriteRuleTokenStream(adaptor,"token SPEC_OR");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:448:2: (lc= SPEC_OR -> ^( OP_OR[$lc] ) )
			// ghidra/sleigh/grammar/SleighParser.g:448:4: lc= SPEC_OR
			{
			lc=(Token)match(input,SPEC_OR,FOLLOW_SPEC_OR_in_pexpression2_or_op2681); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_SPEC_OR.add(lc);

			// AST REWRITE
			// elements: 
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 448:15: -> ^( OP_OR[$lc] )
			{
				// ghidra/sleigh/grammar/SleighParser.g:448:18: ^( OP_OR[$lc] )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_OR, lc), root_1);
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_or_op"


	public static class pexpression2_xor_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_xor"
	// ghidra/sleigh/grammar/SleighParser.g:451:1: pexpression2_xor : pexpression2_and ( pexpression2_xor_op ^ pexpression2_and )* ;
	public final SleighParser.pexpression2_xor_return pexpression2_xor() throws RecognitionException {
		SleighParser.pexpression2_xor_return retval = new SleighParser.pexpression2_xor_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression2_and189 =null;
		ParserRuleReturnScope pexpression2_xor_op190 =null;
		ParserRuleReturnScope pexpression2_and191 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:452:2: ( pexpression2_and ( pexpression2_xor_op ^ pexpression2_and )* )
			// ghidra/sleigh/grammar/SleighParser.g:452:4: pexpression2_and ( pexpression2_xor_op ^ pexpression2_and )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression2_and_in_pexpression2_xor2699);
			pexpression2_and189=pexpression2_and();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_and189.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:452:21: ( pexpression2_xor_op ^ pexpression2_and )*
			loop63:
			while (true) {
				int alt63=2;
				int LA63_0 = input.LA(1);
				if ( (LA63_0==SPEC_XOR) ) {
					alt63=1;
				}

				switch (alt63) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:452:22: pexpression2_xor_op ^ pexpression2_and
					{
					pushFollow(FOLLOW_pexpression2_xor_op_in_pexpression2_xor2702);
					pexpression2_xor_op190=pexpression2_xor_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression2_xor_op190.getTree(), root_0);
					pushFollow(FOLLOW_pexpression2_and_in_pexpression2_xor2705);
					pexpression2_and191=pexpression2_and();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_and191.getTree());

					}
					break;

				default :
					break loop63;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_xor"


	public static class pexpression2_xor_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_xor_op"
	// ghidra/sleigh/grammar/SleighParser.g:455:1: pexpression2_xor_op : lc= SPEC_XOR -> ^( OP_XOR[$lc] ) ;
	public final SleighParser.pexpression2_xor_op_return pexpression2_xor_op() throws RecognitionException {
		SleighParser.pexpression2_xor_op_return retval = new SleighParser.pexpression2_xor_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_SPEC_XOR=new RewriteRuleTokenStream(adaptor,"token SPEC_XOR");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:456:2: (lc= SPEC_XOR -> ^( OP_XOR[$lc] ) )
			// ghidra/sleigh/grammar/SleighParser.g:456:4: lc= SPEC_XOR
			{
			lc=(Token)match(input,SPEC_XOR,FOLLOW_SPEC_XOR_in_pexpression2_xor_op2720); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_SPEC_XOR.add(lc);

			// AST REWRITE
			// elements: 
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 456:16: -> ^( OP_XOR[$lc] )
			{
				// ghidra/sleigh/grammar/SleighParser.g:456:19: ^( OP_XOR[$lc] )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_XOR, lc), root_1);
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_xor_op"


	public static class pexpression2_and_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_and"
	// ghidra/sleigh/grammar/SleighParser.g:459:1: pexpression2_and : pexpression2_shift ( pexpression2_and_op ^ pexpression2_shift )* ;
	public final SleighParser.pexpression2_and_return pexpression2_and() throws RecognitionException {
		SleighParser.pexpression2_and_return retval = new SleighParser.pexpression2_and_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression2_shift192 =null;
		ParserRuleReturnScope pexpression2_and_op193 =null;
		ParserRuleReturnScope pexpression2_shift194 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:460:2: ( pexpression2_shift ( pexpression2_and_op ^ pexpression2_shift )* )
			// ghidra/sleigh/grammar/SleighParser.g:460:4: pexpression2_shift ( pexpression2_and_op ^ pexpression2_shift )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression2_shift_in_pexpression2_and2738);
			pexpression2_shift192=pexpression2_shift();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_shift192.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:460:23: ( pexpression2_and_op ^ pexpression2_shift )*
			loop64:
			while (true) {
				int alt64=2;
				int LA64_0 = input.LA(1);
				if ( (LA64_0==SPEC_AND) ) {
					alt64=1;
				}

				switch (alt64) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:460:24: pexpression2_and_op ^ pexpression2_shift
					{
					pushFollow(FOLLOW_pexpression2_and_op_in_pexpression2_and2741);
					pexpression2_and_op193=pexpression2_and_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression2_and_op193.getTree(), root_0);
					pushFollow(FOLLOW_pexpression2_shift_in_pexpression2_and2744);
					pexpression2_shift194=pexpression2_shift();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_shift194.getTree());

					}
					break;

				default :
					break loop64;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_and"


	public static class pexpression2_and_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_and_op"
	// ghidra/sleigh/grammar/SleighParser.g:463:1: pexpression2_and_op : lc= SPEC_AND -> ^( OP_AND[$lc] ) ;
	public final SleighParser.pexpression2_and_op_return pexpression2_and_op() throws RecognitionException {
		SleighParser.pexpression2_and_op_return retval = new SleighParser.pexpression2_and_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_SPEC_AND=new RewriteRuleTokenStream(adaptor,"token SPEC_AND");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:464:2: (lc= SPEC_AND -> ^( OP_AND[$lc] ) )
			// ghidra/sleigh/grammar/SleighParser.g:464:4: lc= SPEC_AND
			{
			lc=(Token)match(input,SPEC_AND,FOLLOW_SPEC_AND_in_pexpression2_and_op2759); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_SPEC_AND.add(lc);

			// AST REWRITE
			// elements: 
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 464:16: -> ^( OP_AND[$lc] )
			{
				// ghidra/sleigh/grammar/SleighParser.g:464:19: ^( OP_AND[$lc] )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_AND, lc), root_1);
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_and_op"


	public static class pexpression2_shift_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_shift"
	// ghidra/sleigh/grammar/SleighParser.g:467:1: pexpression2_shift : pexpression2_add ( pexpression2_shift_op ^ pexpression2_add )* ;
	public final SleighParser.pexpression2_shift_return pexpression2_shift() throws RecognitionException {
		SleighParser.pexpression2_shift_return retval = new SleighParser.pexpression2_shift_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression2_add195 =null;
		ParserRuleReturnScope pexpression2_shift_op196 =null;
		ParserRuleReturnScope pexpression2_add197 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:468:2: ( pexpression2_add ( pexpression2_shift_op ^ pexpression2_add )* )
			// ghidra/sleigh/grammar/SleighParser.g:468:4: pexpression2_add ( pexpression2_shift_op ^ pexpression2_add )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression2_add_in_pexpression2_shift2777);
			pexpression2_add195=pexpression2_add();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_add195.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:468:21: ( pexpression2_shift_op ^ pexpression2_add )*
			loop65:
			while (true) {
				int alt65=2;
				int LA65_0 = input.LA(1);
				if ( (LA65_0==LEFT||LA65_0==RIGHT) ) {
					alt65=1;
				}

				switch (alt65) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:468:22: pexpression2_shift_op ^ pexpression2_add
					{
					pushFollow(FOLLOW_pexpression2_shift_op_in_pexpression2_shift2780);
					pexpression2_shift_op196=pexpression2_shift_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression2_shift_op196.getTree(), root_0);
					pushFollow(FOLLOW_pexpression2_add_in_pexpression2_shift2783);
					pexpression2_add197=pexpression2_add();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_add197.getTree());

					}
					break;

				default :
					break loop65;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_shift"


	public static class pexpression2_shift_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_shift_op"
	// ghidra/sleigh/grammar/SleighParser.g:471:1: pexpression2_shift_op : (lc= LEFT -> ^( OP_LEFT[$lc] ) |lc= RIGHT -> ^( OP_RIGHT[$lc] ) );
	public final SleighParser.pexpression2_shift_op_return pexpression2_shift_op() throws RecognitionException {
		SleighParser.pexpression2_shift_op_return retval = new SleighParser.pexpression2_shift_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_LEFT=new RewriteRuleTokenStream(adaptor,"token LEFT");
		RewriteRuleTokenStream stream_RIGHT=new RewriteRuleTokenStream(adaptor,"token RIGHT");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:472:2: (lc= LEFT -> ^( OP_LEFT[$lc] ) |lc= RIGHT -> ^( OP_RIGHT[$lc] ) )
			int alt66=2;
			int LA66_0 = input.LA(1);
			if ( (LA66_0==LEFT) ) {
				alt66=1;
			}
			else if ( (LA66_0==RIGHT) ) {
				alt66=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 66, 0, input);
				throw nvae;
			}

			switch (alt66) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:472:4: lc= LEFT
					{
					lc=(Token)match(input,LEFT,FOLLOW_LEFT_in_pexpression2_shift_op2798); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LEFT.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 472:12: -> ^( OP_LEFT[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:472:15: ^( OP_LEFT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_LEFT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:473:4: lc= RIGHT
					{
					lc=(Token)match(input,RIGHT,FOLLOW_RIGHT_in_pexpression2_shift_op2812); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_RIGHT.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 473:13: -> ^( OP_RIGHT[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:473:16: ^( OP_RIGHT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_RIGHT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_shift_op"


	public static class pexpression2_add_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_add"
	// ghidra/sleigh/grammar/SleighParser.g:476:1: pexpression2_add : pexpression2_mult ( pexpression2_add_op ^ pexpression2_mult )* ;
	public final SleighParser.pexpression2_add_return pexpression2_add() throws RecognitionException {
		SleighParser.pexpression2_add_return retval = new SleighParser.pexpression2_add_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression2_mult198 =null;
		ParserRuleReturnScope pexpression2_add_op199 =null;
		ParserRuleReturnScope pexpression2_mult200 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:477:2: ( pexpression2_mult ( pexpression2_add_op ^ pexpression2_mult )* )
			// ghidra/sleigh/grammar/SleighParser.g:477:4: pexpression2_mult ( pexpression2_add_op ^ pexpression2_mult )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression2_mult_in_pexpression2_add2830);
			pexpression2_mult198=pexpression2_mult();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_mult198.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:477:22: ( pexpression2_add_op ^ pexpression2_mult )*
			loop67:
			while (true) {
				int alt67=2;
				int LA67_0 = input.LA(1);
				if ( (LA67_0==MINUS||LA67_0==PLUS) ) {
					alt67=1;
				}

				switch (alt67) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:477:23: pexpression2_add_op ^ pexpression2_mult
					{
					pushFollow(FOLLOW_pexpression2_add_op_in_pexpression2_add2833);
					pexpression2_add_op199=pexpression2_add_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression2_add_op199.getTree(), root_0);
					pushFollow(FOLLOW_pexpression2_mult_in_pexpression2_add2836);
					pexpression2_mult200=pexpression2_mult();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_mult200.getTree());

					}
					break;

				default :
					break loop67;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_add"


	public static class pexpression2_add_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_add_op"
	// ghidra/sleigh/grammar/SleighParser.g:480:1: pexpression2_add_op : (lc= PLUS -> ^( OP_ADD[$lc] ) |lc= MINUS -> ^( OP_SUB[$lc] ) );
	public final SleighParser.pexpression2_add_op_return pexpression2_add_op() throws RecognitionException {
		SleighParser.pexpression2_add_op_return retval = new SleighParser.pexpression2_add_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_PLUS=new RewriteRuleTokenStream(adaptor,"token PLUS");
		RewriteRuleTokenStream stream_MINUS=new RewriteRuleTokenStream(adaptor,"token MINUS");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:481:2: (lc= PLUS -> ^( OP_ADD[$lc] ) |lc= MINUS -> ^( OP_SUB[$lc] ) )
			int alt68=2;
			int LA68_0 = input.LA(1);
			if ( (LA68_0==PLUS) ) {
				alt68=1;
			}
			else if ( (LA68_0==MINUS) ) {
				alt68=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 68, 0, input);
				throw nvae;
			}

			switch (alt68) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:481:4: lc= PLUS
					{
					lc=(Token)match(input,PLUS,FOLLOW_PLUS_in_pexpression2_add_op2851); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_PLUS.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 481:12: -> ^( OP_ADD[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:481:15: ^( OP_ADD[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_ADD, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:482:4: lc= MINUS
					{
					lc=(Token)match(input,MINUS,FOLLOW_MINUS_in_pexpression2_add_op2865); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_MINUS.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 482:13: -> ^( OP_SUB[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:482:16: ^( OP_SUB[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SUB, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_add_op"


	public static class pexpression2_mult_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_mult"
	// ghidra/sleigh/grammar/SleighParser.g:485:1: pexpression2_mult : pexpression2_unary ( pexpression2_mult_op ^ pexpression2_unary )* ;
	public final SleighParser.pexpression2_mult_return pexpression2_mult() throws RecognitionException {
		SleighParser.pexpression2_mult_return retval = new SleighParser.pexpression2_mult_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression2_unary201 =null;
		ParserRuleReturnScope pexpression2_mult_op202 =null;
		ParserRuleReturnScope pexpression2_unary203 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:486:2: ( pexpression2_unary ( pexpression2_mult_op ^ pexpression2_unary )* )
			// ghidra/sleigh/grammar/SleighParser.g:486:4: pexpression2_unary ( pexpression2_mult_op ^ pexpression2_unary )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_pexpression2_unary_in_pexpression2_mult2883);
			pexpression2_unary201=pexpression2_unary();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_unary201.getTree());

			// ghidra/sleigh/grammar/SleighParser.g:486:23: ( pexpression2_mult_op ^ pexpression2_unary )*
			loop69:
			while (true) {
				int alt69=2;
				int LA69_0 = input.LA(1);
				if ( (LA69_0==ASTERISK||LA69_0==SLASH) ) {
					alt69=1;
				}

				switch (alt69) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:486:24: pexpression2_mult_op ^ pexpression2_unary
					{
					pushFollow(FOLLOW_pexpression2_mult_op_in_pexpression2_mult2886);
					pexpression2_mult_op202=pexpression2_mult_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression2_mult_op202.getTree(), root_0);
					pushFollow(FOLLOW_pexpression2_unary_in_pexpression2_mult2889);
					pexpression2_unary203=pexpression2_unary();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_unary203.getTree());

					}
					break;

				default :
					break loop69;
				}
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_mult"


	public static class pexpression2_mult_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_mult_op"
	// ghidra/sleigh/grammar/SleighParser.g:489:1: pexpression2_mult_op : (lc= ASTERISK -> ^( OP_MULT[$lc] ) |lc= SLASH -> ^( OP_DIV[$lc] ) );
	public final SleighParser.pexpression2_mult_op_return pexpression2_mult_op() throws RecognitionException {
		SleighParser.pexpression2_mult_op_return retval = new SleighParser.pexpression2_mult_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_SLASH=new RewriteRuleTokenStream(adaptor,"token SLASH");
		RewriteRuleTokenStream stream_ASTERISK=new RewriteRuleTokenStream(adaptor,"token ASTERISK");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:490:2: (lc= ASTERISK -> ^( OP_MULT[$lc] ) |lc= SLASH -> ^( OP_DIV[$lc] ) )
			int alt70=2;
			int LA70_0 = input.LA(1);
			if ( (LA70_0==ASTERISK) ) {
				alt70=1;
			}
			else if ( (LA70_0==SLASH) ) {
				alt70=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 70, 0, input);
				throw nvae;
			}

			switch (alt70) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:490:4: lc= ASTERISK
					{
					lc=(Token)match(input,ASTERISK,FOLLOW_ASTERISK_in_pexpression2_mult_op2904); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_ASTERISK.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 490:16: -> ^( OP_MULT[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:490:19: ^( OP_MULT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_MULT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:491:4: lc= SLASH
					{
					lc=(Token)match(input,SLASH,FOLLOW_SLASH_in_pexpression2_mult_op2918); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_SLASH.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 491:13: -> ^( OP_DIV[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:491:16: ^( OP_DIV[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_DIV, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_mult_op"


	public static class pexpression2_unary_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_unary"
	// ghidra/sleigh/grammar/SleighParser.g:494:1: pexpression2_unary : ( pexpression2_unary_op ^ pexpression2_term | pexpression2_func );
	public final SleighParser.pexpression2_unary_return pexpression2_unary() throws RecognitionException {
		SleighParser.pexpression2_unary_return retval = new SleighParser.pexpression2_unary_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression2_unary_op204 =null;
		ParserRuleReturnScope pexpression2_term205 =null;
		ParserRuleReturnScope pexpression2_func206 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:495:2: ( pexpression2_unary_op ^ pexpression2_term | pexpression2_func )
			int alt71=2;
			int LA71_0 = input.LA(1);
			if ( (LA71_0==MINUS||LA71_0==TILDE) ) {
				alt71=1;
			}
			else if ( (LA71_0==BIN_INT||LA71_0==DEC_INT||(LA71_0 >= HEX_INT && LA71_0 <= KEY_WORDSIZE)||LA71_0==LPAREN) ) {
				alt71=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 71, 0, input);
				throw nvae;
			}

			switch (alt71) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:495:4: pexpression2_unary_op ^ pexpression2_term
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_pexpression2_unary_op_in_pexpression2_unary2936);
					pexpression2_unary_op204=pexpression2_unary_op();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) root_0 = (CommonTree)adaptor.becomeRoot(pexpression2_unary_op204.getTree(), root_0);
					pushFollow(FOLLOW_pexpression2_term_in_pexpression2_unary2939);
					pexpression2_term205=pexpression2_term();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_term205.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:496:4: pexpression2_func
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_pexpression2_func_in_pexpression2_unary2944);
					pexpression2_func206=pexpression2_func();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_func206.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_unary"


	public static class pexpression2_unary_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_unary_op"
	// ghidra/sleigh/grammar/SleighParser.g:499:1: pexpression2_unary_op : (lc= MINUS -> ^( OP_NEGATE[$lc] ) |lc= TILDE -> ^( OP_INVERT[$lc] ) );
	public final SleighParser.pexpression2_unary_op_return pexpression2_unary_op() throws RecognitionException {
		SleighParser.pexpression2_unary_op_return retval = new SleighParser.pexpression2_unary_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_TILDE=new RewriteRuleTokenStream(adaptor,"token TILDE");
		RewriteRuleTokenStream stream_MINUS=new RewriteRuleTokenStream(adaptor,"token MINUS");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:500:2: (lc= MINUS -> ^( OP_NEGATE[$lc] ) |lc= TILDE -> ^( OP_INVERT[$lc] ) )
			int alt72=2;
			int LA72_0 = input.LA(1);
			if ( (LA72_0==MINUS) ) {
				alt72=1;
			}
			else if ( (LA72_0==TILDE) ) {
				alt72=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 72, 0, input);
				throw nvae;
			}

			switch (alt72) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:500:4: lc= MINUS
					{
					lc=(Token)match(input,MINUS,FOLLOW_MINUS_in_pexpression2_unary_op2957); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_MINUS.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 500:13: -> ^( OP_NEGATE[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:500:16: ^( OP_NEGATE[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_NEGATE, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:501:4: lc= TILDE
					{
					lc=(Token)match(input,TILDE,FOLLOW_TILDE_in_pexpression2_unary_op2971); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_TILDE.add(lc);

					// AST REWRITE
					// elements: 
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 501:13: -> ^( OP_INVERT[$lc] )
					{
						// ghidra/sleigh/grammar/SleighParser.g:501:16: ^( OP_INVERT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_INVERT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_unary_op"


	public static class pexpression2_func_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_func"
	// ghidra/sleigh/grammar/SleighParser.g:504:1: pexpression2_func : ( pexpression2_apply | pexpression2_term );
	public final SleighParser.pexpression2_func_return pexpression2_func() throws RecognitionException {
		SleighParser.pexpression2_func_return retval = new SleighParser.pexpression2_func_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope pexpression2_apply207 =null;
		ParserRuleReturnScope pexpression2_term208 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:505:2: ( pexpression2_apply | pexpression2_term )
			int alt73=2;
			switch ( input.LA(1) ) {
			case IDENTIFIER:
				{
				int LA73_1 = input.LA(2);
				if ( (LA73_1==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_1==AMPERSAND||LA73_1==ASTERISK||LA73_1==COMMA||LA73_1==ELLIPSIS||LA73_1==KEY_UNIMPL||(LA73_1 >= LBRACE && LA73_1 <= LEFT)||LA73_1==MINUS||(LA73_1 >= PIPE && LA73_1 <= PLUS)||(LA73_1 >= RIGHT && LA73_1 <= RPAREN)||LA73_1==SEMI||LA73_1==SLASH||(LA73_1 >= SPEC_AND && LA73_1 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ALIGNMENT:
				{
				int LA73_2 = input.LA(2);
				if ( (LA73_2==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_2==AMPERSAND||LA73_2==ASTERISK||LA73_2==COMMA||LA73_2==ELLIPSIS||LA73_2==KEY_UNIMPL||(LA73_2 >= LBRACE && LA73_2 <= LEFT)||LA73_2==MINUS||(LA73_2 >= PIPE && LA73_2 <= PLUS)||(LA73_2 >= RIGHT && LA73_2 <= RPAREN)||LA73_2==SEMI||LA73_2==SLASH||(LA73_2 >= SPEC_AND && LA73_2 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 2, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ATTACH:
				{
				int LA73_3 = input.LA(2);
				if ( (LA73_3==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_3==AMPERSAND||LA73_3==ASTERISK||LA73_3==COMMA||LA73_3==ELLIPSIS||LA73_3==KEY_UNIMPL||(LA73_3 >= LBRACE && LA73_3 <= LEFT)||LA73_3==MINUS||(LA73_3 >= PIPE && LA73_3 <= PLUS)||(LA73_3 >= RIGHT && LA73_3 <= RPAREN)||LA73_3==SEMI||LA73_3==SLASH||(LA73_3 >= SPEC_AND && LA73_3 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 3, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BIG:
				{
				int LA73_4 = input.LA(2);
				if ( (LA73_4==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_4==AMPERSAND||LA73_4==ASTERISK||LA73_4==COMMA||LA73_4==ELLIPSIS||LA73_4==KEY_UNIMPL||(LA73_4 >= LBRACE && LA73_4 <= LEFT)||LA73_4==MINUS||(LA73_4 >= PIPE && LA73_4 <= PLUS)||(LA73_4 >= RIGHT && LA73_4 <= RPAREN)||LA73_4==SEMI||LA73_4==SLASH||(LA73_4 >= SPEC_AND && LA73_4 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 4, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BITRANGE:
				{
				int LA73_5 = input.LA(2);
				if ( (LA73_5==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_5==AMPERSAND||LA73_5==ASTERISK||LA73_5==COMMA||LA73_5==ELLIPSIS||LA73_5==KEY_UNIMPL||(LA73_5 >= LBRACE && LA73_5 <= LEFT)||LA73_5==MINUS||(LA73_5 >= PIPE && LA73_5 <= PLUS)||(LA73_5 >= RIGHT && LA73_5 <= RPAREN)||LA73_5==SEMI||LA73_5==SLASH||(LA73_5 >= SPEC_AND && LA73_5 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 5, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BUILD:
				{
				int LA73_6 = input.LA(2);
				if ( (LA73_6==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_6==AMPERSAND||LA73_6==ASTERISK||LA73_6==COMMA||LA73_6==ELLIPSIS||LA73_6==KEY_UNIMPL||(LA73_6 >= LBRACE && LA73_6 <= LEFT)||LA73_6==MINUS||(LA73_6 >= PIPE && LA73_6 <= PLUS)||(LA73_6 >= RIGHT && LA73_6 <= RPAREN)||LA73_6==SEMI||LA73_6==SLASH||(LA73_6 >= SPEC_AND && LA73_6 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 6, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CALL:
				{
				int LA73_7 = input.LA(2);
				if ( (LA73_7==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_7==AMPERSAND||LA73_7==ASTERISK||LA73_7==COMMA||LA73_7==ELLIPSIS||LA73_7==KEY_UNIMPL||(LA73_7 >= LBRACE && LA73_7 <= LEFT)||LA73_7==MINUS||(LA73_7 >= PIPE && LA73_7 <= PLUS)||(LA73_7 >= RIGHT && LA73_7 <= RPAREN)||LA73_7==SEMI||LA73_7==SLASH||(LA73_7 >= SPEC_AND && LA73_7 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 7, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CONTEXT:
				{
				int LA73_8 = input.LA(2);
				if ( (LA73_8==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_8==AMPERSAND||LA73_8==ASTERISK||LA73_8==COMMA||LA73_8==ELLIPSIS||LA73_8==KEY_UNIMPL||(LA73_8 >= LBRACE && LA73_8 <= LEFT)||LA73_8==MINUS||(LA73_8 >= PIPE && LA73_8 <= PLUS)||(LA73_8 >= RIGHT && LA73_8 <= RPAREN)||LA73_8==SEMI||LA73_8==SLASH||(LA73_8 >= SPEC_AND && LA73_8 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 8, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CROSSBUILD:
				{
				int LA73_9 = input.LA(2);
				if ( (LA73_9==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_9==AMPERSAND||LA73_9==ASTERISK||LA73_9==COMMA||LA73_9==ELLIPSIS||LA73_9==KEY_UNIMPL||(LA73_9 >= LBRACE && LA73_9 <= LEFT)||LA73_9==MINUS||(LA73_9 >= PIPE && LA73_9 <= PLUS)||(LA73_9 >= RIGHT && LA73_9 <= RPAREN)||LA73_9==SEMI||LA73_9==SLASH||(LA73_9 >= SPEC_AND && LA73_9 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 9, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEC:
				{
				int LA73_10 = input.LA(2);
				if ( (LA73_10==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_10==AMPERSAND||LA73_10==ASTERISK||LA73_10==COMMA||LA73_10==ELLIPSIS||LA73_10==KEY_UNIMPL||(LA73_10 >= LBRACE && LA73_10 <= LEFT)||LA73_10==MINUS||(LA73_10 >= PIPE && LA73_10 <= PLUS)||(LA73_10 >= RIGHT && LA73_10 <= RPAREN)||LA73_10==SEMI||LA73_10==SLASH||(LA73_10 >= SPEC_AND && LA73_10 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 10, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEFAULT:
				{
				int LA73_11 = input.LA(2);
				if ( (LA73_11==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_11==AMPERSAND||LA73_11==ASTERISK||LA73_11==COMMA||LA73_11==ELLIPSIS||LA73_11==KEY_UNIMPL||(LA73_11 >= LBRACE && LA73_11 <= LEFT)||LA73_11==MINUS||(LA73_11 >= PIPE && LA73_11 <= PLUS)||(LA73_11 >= RIGHT && LA73_11 <= RPAREN)||LA73_11==SEMI||LA73_11==SLASH||(LA73_11 >= SPEC_AND && LA73_11 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 11, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEFINE:
				{
				int LA73_12 = input.LA(2);
				if ( (LA73_12==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_12==AMPERSAND||LA73_12==ASTERISK||LA73_12==COMMA||LA73_12==ELLIPSIS||LA73_12==KEY_UNIMPL||(LA73_12 >= LBRACE && LA73_12 <= LEFT)||LA73_12==MINUS||(LA73_12 >= PIPE && LA73_12 <= PLUS)||(LA73_12 >= RIGHT && LA73_12 <= RPAREN)||LA73_12==SEMI||LA73_12==SLASH||(LA73_12 >= SPEC_AND && LA73_12 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 12, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ENDIAN:
				{
				int LA73_13 = input.LA(2);
				if ( (LA73_13==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_13==AMPERSAND||LA73_13==ASTERISK||LA73_13==COMMA||LA73_13==ELLIPSIS||LA73_13==KEY_UNIMPL||(LA73_13 >= LBRACE && LA73_13 <= LEFT)||LA73_13==MINUS||(LA73_13 >= PIPE && LA73_13 <= PLUS)||(LA73_13 >= RIGHT && LA73_13 <= RPAREN)||LA73_13==SEMI||LA73_13==SLASH||(LA73_13 >= SPEC_AND && LA73_13 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 13, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_EXPORT:
				{
				int LA73_14 = input.LA(2);
				if ( (LA73_14==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_14==AMPERSAND||LA73_14==ASTERISK||LA73_14==COMMA||LA73_14==ELLIPSIS||LA73_14==KEY_UNIMPL||(LA73_14 >= LBRACE && LA73_14 <= LEFT)||LA73_14==MINUS||(LA73_14 >= PIPE && LA73_14 <= PLUS)||(LA73_14 >= RIGHT && LA73_14 <= RPAREN)||LA73_14==SEMI||LA73_14==SLASH||(LA73_14 >= SPEC_AND && LA73_14 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 14, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_GOTO:
				{
				int LA73_15 = input.LA(2);
				if ( (LA73_15==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_15==AMPERSAND||LA73_15==ASTERISK||LA73_15==COMMA||LA73_15==ELLIPSIS||LA73_15==KEY_UNIMPL||(LA73_15 >= LBRACE && LA73_15 <= LEFT)||LA73_15==MINUS||(LA73_15 >= PIPE && LA73_15 <= PLUS)||(LA73_15 >= RIGHT && LA73_15 <= RPAREN)||LA73_15==SEMI||LA73_15==SLASH||(LA73_15 >= SPEC_AND && LA73_15 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 15, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_HEX:
				{
				int LA73_16 = input.LA(2);
				if ( (LA73_16==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_16==AMPERSAND||LA73_16==ASTERISK||LA73_16==COMMA||LA73_16==ELLIPSIS||LA73_16==KEY_UNIMPL||(LA73_16 >= LBRACE && LA73_16 <= LEFT)||LA73_16==MINUS||(LA73_16 >= PIPE && LA73_16 <= PLUS)||(LA73_16 >= RIGHT && LA73_16 <= RPAREN)||LA73_16==SEMI||LA73_16==SLASH||(LA73_16 >= SPEC_AND && LA73_16 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 16, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_LITTLE:
				{
				int LA73_17 = input.LA(2);
				if ( (LA73_17==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_17==AMPERSAND||LA73_17==ASTERISK||LA73_17==COMMA||LA73_17==ELLIPSIS||LA73_17==KEY_UNIMPL||(LA73_17 >= LBRACE && LA73_17 <= LEFT)||LA73_17==MINUS||(LA73_17 >= PIPE && LA73_17 <= PLUS)||(LA73_17 >= RIGHT && LA73_17 <= RPAREN)||LA73_17==SEMI||LA73_17==SLASH||(LA73_17 >= SPEC_AND && LA73_17 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 17, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_LOCAL:
				{
				int LA73_18 = input.LA(2);
				if ( (LA73_18==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_18==AMPERSAND||LA73_18==ASTERISK||LA73_18==COMMA||LA73_18==ELLIPSIS||LA73_18==KEY_UNIMPL||(LA73_18 >= LBRACE && LA73_18 <= LEFT)||LA73_18==MINUS||(LA73_18 >= PIPE && LA73_18 <= PLUS)||(LA73_18 >= RIGHT && LA73_18 <= RPAREN)||LA73_18==SEMI||LA73_18==SLASH||(LA73_18 >= SPEC_AND && LA73_18 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 18, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_MACRO:
				{
				int LA73_19 = input.LA(2);
				if ( (LA73_19==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_19==AMPERSAND||LA73_19==ASTERISK||LA73_19==COMMA||LA73_19==ELLIPSIS||LA73_19==KEY_UNIMPL||(LA73_19 >= LBRACE && LA73_19 <= LEFT)||LA73_19==MINUS||(LA73_19 >= PIPE && LA73_19 <= PLUS)||(LA73_19 >= RIGHT && LA73_19 <= RPAREN)||LA73_19==SEMI||LA73_19==SLASH||(LA73_19 >= SPEC_AND && LA73_19 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 19, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_NAMES:
				{
				int LA73_20 = input.LA(2);
				if ( (LA73_20==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_20==AMPERSAND||LA73_20==ASTERISK||LA73_20==COMMA||LA73_20==ELLIPSIS||LA73_20==KEY_UNIMPL||(LA73_20 >= LBRACE && LA73_20 <= LEFT)||LA73_20==MINUS||(LA73_20 >= PIPE && LA73_20 <= PLUS)||(LA73_20 >= RIGHT && LA73_20 <= RPAREN)||LA73_20==SEMI||LA73_20==SLASH||(LA73_20 >= SPEC_AND && LA73_20 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 20, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_NOFLOW:
				{
				int LA73_21 = input.LA(2);
				if ( (LA73_21==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_21==AMPERSAND||LA73_21==ASTERISK||LA73_21==COMMA||LA73_21==ELLIPSIS||LA73_21==KEY_UNIMPL||(LA73_21 >= LBRACE && LA73_21 <= LEFT)||LA73_21==MINUS||(LA73_21 >= PIPE && LA73_21 <= PLUS)||(LA73_21 >= RIGHT && LA73_21 <= RPAREN)||LA73_21==SEMI||LA73_21==SLASH||(LA73_21 >= SPEC_AND && LA73_21 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 21, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_OFFSET:
				{
				int LA73_22 = input.LA(2);
				if ( (LA73_22==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_22==AMPERSAND||LA73_22==ASTERISK||LA73_22==COMMA||LA73_22==ELLIPSIS||LA73_22==KEY_UNIMPL||(LA73_22 >= LBRACE && LA73_22 <= LEFT)||LA73_22==MINUS||(LA73_22 >= PIPE && LA73_22 <= PLUS)||(LA73_22 >= RIGHT && LA73_22 <= RPAREN)||LA73_22==SEMI||LA73_22==SLASH||(LA73_22 >= SPEC_AND && LA73_22 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 22, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_PCODEOP:
				{
				int LA73_23 = input.LA(2);
				if ( (LA73_23==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_23==AMPERSAND||LA73_23==ASTERISK||LA73_23==COMMA||LA73_23==ELLIPSIS||LA73_23==KEY_UNIMPL||(LA73_23 >= LBRACE && LA73_23 <= LEFT)||LA73_23==MINUS||(LA73_23 >= PIPE && LA73_23 <= PLUS)||(LA73_23 >= RIGHT && LA73_23 <= RPAREN)||LA73_23==SEMI||LA73_23==SLASH||(LA73_23 >= SPEC_AND && LA73_23 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 23, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_RETURN:
				{
				int LA73_24 = input.LA(2);
				if ( (LA73_24==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_24==AMPERSAND||LA73_24==ASTERISK||LA73_24==COMMA||LA73_24==ELLIPSIS||LA73_24==KEY_UNIMPL||(LA73_24 >= LBRACE && LA73_24 <= LEFT)||LA73_24==MINUS||(LA73_24 >= PIPE && LA73_24 <= PLUS)||(LA73_24 >= RIGHT && LA73_24 <= RPAREN)||LA73_24==SEMI||LA73_24==SLASH||(LA73_24 >= SPEC_AND && LA73_24 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 24, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SIGNED:
				{
				int LA73_25 = input.LA(2);
				if ( (LA73_25==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_25==AMPERSAND||LA73_25==ASTERISK||LA73_25==COMMA||LA73_25==ELLIPSIS||LA73_25==KEY_UNIMPL||(LA73_25 >= LBRACE && LA73_25 <= LEFT)||LA73_25==MINUS||(LA73_25 >= PIPE && LA73_25 <= PLUS)||(LA73_25 >= RIGHT && LA73_25 <= RPAREN)||LA73_25==SEMI||LA73_25==SLASH||(LA73_25 >= SPEC_AND && LA73_25 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 25, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SIZE:
				{
				int LA73_26 = input.LA(2);
				if ( (LA73_26==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_26==AMPERSAND||LA73_26==ASTERISK||LA73_26==COMMA||LA73_26==ELLIPSIS||LA73_26==KEY_UNIMPL||(LA73_26 >= LBRACE && LA73_26 <= LEFT)||LA73_26==MINUS||(LA73_26 >= PIPE && LA73_26 <= PLUS)||(LA73_26 >= RIGHT && LA73_26 <= RPAREN)||LA73_26==SEMI||LA73_26==SLASH||(LA73_26 >= SPEC_AND && LA73_26 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 26, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SPACE:
				{
				int LA73_27 = input.LA(2);
				if ( (LA73_27==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_27==AMPERSAND||LA73_27==ASTERISK||LA73_27==COMMA||LA73_27==ELLIPSIS||LA73_27==KEY_UNIMPL||(LA73_27 >= LBRACE && LA73_27 <= LEFT)||LA73_27==MINUS||(LA73_27 >= PIPE && LA73_27 <= PLUS)||(LA73_27 >= RIGHT && LA73_27 <= RPAREN)||LA73_27==SEMI||LA73_27==SLASH||(LA73_27 >= SPEC_AND && LA73_27 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 27, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_TOKEN:
				{
				int LA73_28 = input.LA(2);
				if ( (LA73_28==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_28==AMPERSAND||LA73_28==ASTERISK||LA73_28==COMMA||LA73_28==ELLIPSIS||LA73_28==KEY_UNIMPL||(LA73_28 >= LBRACE && LA73_28 <= LEFT)||LA73_28==MINUS||(LA73_28 >= PIPE && LA73_28 <= PLUS)||(LA73_28 >= RIGHT && LA73_28 <= RPAREN)||LA73_28==SEMI||LA73_28==SLASH||(LA73_28 >= SPEC_AND && LA73_28 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 28, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_TYPE:
				{
				int LA73_29 = input.LA(2);
				if ( (LA73_29==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_29==AMPERSAND||LA73_29==ASTERISK||LA73_29==COMMA||LA73_29==ELLIPSIS||LA73_29==KEY_UNIMPL||(LA73_29 >= LBRACE && LA73_29 <= LEFT)||LA73_29==MINUS||(LA73_29 >= PIPE && LA73_29 <= PLUS)||(LA73_29 >= RIGHT && LA73_29 <= RPAREN)||LA73_29==SEMI||LA73_29==SLASH||(LA73_29 >= SPEC_AND && LA73_29 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 29, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_UNIMPL:
				{
				int LA73_30 = input.LA(2);
				if ( (LA73_30==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_30==AMPERSAND||LA73_30==ASTERISK||LA73_30==COMMA||LA73_30==ELLIPSIS||LA73_30==KEY_UNIMPL||(LA73_30 >= LBRACE && LA73_30 <= LEFT)||LA73_30==MINUS||(LA73_30 >= PIPE && LA73_30 <= PLUS)||(LA73_30 >= RIGHT && LA73_30 <= RPAREN)||LA73_30==SEMI||LA73_30==SLASH||(LA73_30 >= SPEC_AND && LA73_30 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 30, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_VALUES:
				{
				int LA73_31 = input.LA(2);
				if ( (LA73_31==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_31==AMPERSAND||LA73_31==ASTERISK||LA73_31==COMMA||LA73_31==ELLIPSIS||LA73_31==KEY_UNIMPL||(LA73_31 >= LBRACE && LA73_31 <= LEFT)||LA73_31==MINUS||(LA73_31 >= PIPE && LA73_31 <= PLUS)||(LA73_31 >= RIGHT && LA73_31 <= RPAREN)||LA73_31==SEMI||LA73_31==SLASH||(LA73_31 >= SPEC_AND && LA73_31 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 31, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_VARIABLES:
				{
				int LA73_32 = input.LA(2);
				if ( (LA73_32==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_32==AMPERSAND||LA73_32==ASTERISK||LA73_32==COMMA||LA73_32==ELLIPSIS||LA73_32==KEY_UNIMPL||(LA73_32 >= LBRACE && LA73_32 <= LEFT)||LA73_32==MINUS||(LA73_32 >= PIPE && LA73_32 <= PLUS)||(LA73_32 >= RIGHT && LA73_32 <= RPAREN)||LA73_32==SEMI||LA73_32==SLASH||(LA73_32 >= SPEC_AND && LA73_32 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 32, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_WORDSIZE:
				{
				int LA73_33 = input.LA(2);
				if ( (LA73_33==LPAREN) ) {
					alt73=1;
				}
				else if ( (LA73_33==AMPERSAND||LA73_33==ASTERISK||LA73_33==COMMA||LA73_33==ELLIPSIS||LA73_33==KEY_UNIMPL||(LA73_33 >= LBRACE && LA73_33 <= LEFT)||LA73_33==MINUS||(LA73_33 >= PIPE && LA73_33 <= PLUS)||(LA73_33 >= RIGHT && LA73_33 <= RPAREN)||LA73_33==SEMI||LA73_33==SLASH||(LA73_33 >= SPEC_AND && LA73_33 <= SPEC_XOR)) ) {
					alt73=2;
				}

				else {
					if (state.backtracking>0) {state.failed=true; return retval;}
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 73, 33, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case BIN_INT:
			case DEC_INT:
			case HEX_INT:
			case LPAREN:
				{
				alt73=2;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 73, 0, input);
				throw nvae;
			}
			switch (alt73) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:505:4: pexpression2_apply
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_pexpression2_apply_in_pexpression2_func2989);
					pexpression2_apply207=pexpression2_apply();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_apply207.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:506:4: pexpression2_term
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_pexpression2_term_in_pexpression2_func2994);
					pexpression2_term208=pexpression2_term();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2_term208.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_func"


	public static class pexpression2_apply_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_apply"
	// ghidra/sleigh/grammar/SleighParser.g:509:1: pexpression2_apply : identifier pexpression2_operands -> ^( OP_APPLY identifier ( pexpression2_operands )? ) ;
	public final SleighParser.pexpression2_apply_return pexpression2_apply() throws RecognitionException {
		SleighParser.pexpression2_apply_return retval = new SleighParser.pexpression2_apply_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope identifier209 =null;
		ParserRuleReturnScope pexpression2_operands210 =null;

		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_pexpression2_operands=new RewriteRuleSubtreeStream(adaptor,"rule pexpression2_operands");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:510:2: ( identifier pexpression2_operands -> ^( OP_APPLY identifier ( pexpression2_operands )? ) )
			// ghidra/sleigh/grammar/SleighParser.g:510:4: identifier pexpression2_operands
			{
			pushFollow(FOLLOW_identifier_in_pexpression2_apply3005);
			identifier209=identifier();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_identifier.add(identifier209.getTree());
			pushFollow(FOLLOW_pexpression2_operands_in_pexpression2_apply3007);
			pexpression2_operands210=pexpression2_operands();
			state._fsp--;
			if (state.failed) return retval;
			if ( state.backtracking==0 ) stream_pexpression2_operands.add(pexpression2_operands210.getTree());
			// AST REWRITE
			// elements: identifier, pexpression2_operands
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 510:37: -> ^( OP_APPLY identifier ( pexpression2_operands )? )
			{
				// ghidra/sleigh/grammar/SleighParser.g:510:40: ^( OP_APPLY identifier ( pexpression2_operands )? )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_APPLY, "OP_APPLY"), root_1);
				adaptor.addChild(root_1, stream_identifier.nextTree());
				// ghidra/sleigh/grammar/SleighParser.g:510:62: ( pexpression2_operands )?
				if ( stream_pexpression2_operands.hasNext() ) {
					adaptor.addChild(root_1, stream_pexpression2_operands.nextTree());
				}
				stream_pexpression2_operands.reset();

				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_apply"


	public static class pexpression2_operands_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_operands"
	// ghidra/sleigh/grammar/SleighParser.g:513:1: pexpression2_operands : LPAREN ! ( pexpression2 ( COMMA ! pexpression2 )* )? RPAREN !;
	public final SleighParser.pexpression2_operands_return pexpression2_operands() throws RecognitionException {
		SleighParser.pexpression2_operands_return retval = new SleighParser.pexpression2_operands_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token LPAREN211=null;
		Token COMMA213=null;
		Token RPAREN215=null;
		ParserRuleReturnScope pexpression2212 =null;
		ParserRuleReturnScope pexpression2214 =null;

		CommonTree LPAREN211_tree=null;
		CommonTree COMMA213_tree=null;
		CommonTree RPAREN215_tree=null;

		try {
			// ghidra/sleigh/grammar/SleighParser.g:514:2: ( LPAREN ! ( pexpression2 ( COMMA ! pexpression2 )* )? RPAREN !)
			// ghidra/sleigh/grammar/SleighParser.g:514:4: LPAREN ! ( pexpression2 ( COMMA ! pexpression2 )* )? RPAREN !
			{
			root_0 = (CommonTree)adaptor.nil();


			LPAREN211=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_pexpression2_operands3029); if (state.failed) return retval;
			// ghidra/sleigh/grammar/SleighParser.g:514:12: ( pexpression2 ( COMMA ! pexpression2 )* )?
			int alt75=2;
			int LA75_0 = input.LA(1);
			if ( (LA75_0==BIN_INT||LA75_0==DEC_INT||(LA75_0 >= HEX_INT && LA75_0 <= KEY_WORDSIZE)||(LA75_0 >= LPAREN && LA75_0 <= MINUS)||LA75_0==TILDE) ) {
				alt75=1;
			}
			switch (alt75) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:514:13: pexpression2 ( COMMA ! pexpression2 )*
					{
					pushFollow(FOLLOW_pexpression2_in_pexpression2_operands3033);
					pexpression2212=pexpression2();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2212.getTree());

					// ghidra/sleigh/grammar/SleighParser.g:514:26: ( COMMA ! pexpression2 )*
					loop74:
					while (true) {
						int alt74=2;
						int LA74_0 = input.LA(1);
						if ( (LA74_0==COMMA) ) {
							alt74=1;
						}

						switch (alt74) {
						case 1 :
							// ghidra/sleigh/grammar/SleighParser.g:514:27: COMMA ! pexpression2
							{
							COMMA213=(Token)match(input,COMMA,FOLLOW_COMMA_in_pexpression2_operands3036); if (state.failed) return retval;
							pushFollow(FOLLOW_pexpression2_in_pexpression2_operands3039);
							pexpression2214=pexpression2();
							state._fsp--;
							if (state.failed) return retval;
							if ( state.backtracking==0 ) adaptor.addChild(root_0, pexpression2214.getTree());

							}
							break;

						default :
							break loop74;
						}
					}

					}
					break;

			}

			RPAREN215=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_pexpression2_operands3046); if (state.failed) return retval;
			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_operands"


	public static class pexpression2_term_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pexpression2_term"
	// ghidra/sleigh/grammar/SleighParser.g:517:1: pexpression2_term : ( identifier | integer |lc= LPAREN pexpression2 RPAREN -> ^( OP_PARENTHESIZED[$lc, \"(...)\"] pexpression2 ) );
	public final SleighParser.pexpression2_term_return pexpression2_term() throws RecognitionException {
		SleighParser.pexpression2_term_return retval = new SleighParser.pexpression2_term_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token RPAREN219=null;
		ParserRuleReturnScope identifier216 =null;
		ParserRuleReturnScope integer217 =null;
		ParserRuleReturnScope pexpression2218 =null;

		CommonTree lc_tree=null;
		CommonTree RPAREN219_tree=null;
		RewriteRuleTokenStream stream_LPAREN=new RewriteRuleTokenStream(adaptor,"token LPAREN");
		RewriteRuleTokenStream stream_RPAREN=new RewriteRuleTokenStream(adaptor,"token RPAREN");
		RewriteRuleSubtreeStream stream_pexpression2=new RewriteRuleSubtreeStream(adaptor,"rule pexpression2");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:518:2: ( identifier | integer |lc= LPAREN pexpression2 RPAREN -> ^( OP_PARENTHESIZED[$lc, \"(...)\"] pexpression2 ) )
			int alt76=3;
			switch ( input.LA(1) ) {
			case IDENTIFIER:
			case KEY_ALIGNMENT:
			case KEY_ATTACH:
			case KEY_BIG:
			case KEY_BITRANGE:
			case KEY_BUILD:
			case KEY_CALL:
			case KEY_CONTEXT:
			case KEY_CROSSBUILD:
			case KEY_DEC:
			case KEY_DEFAULT:
			case KEY_DEFINE:
			case KEY_ENDIAN:
			case KEY_EXPORT:
			case KEY_GOTO:
			case KEY_HEX:
			case KEY_LITTLE:
			case KEY_LOCAL:
			case KEY_MACRO:
			case KEY_NAMES:
			case KEY_NOFLOW:
			case KEY_OFFSET:
			case KEY_PCODEOP:
			case KEY_RETURN:
			case KEY_SIGNED:
			case KEY_SIZE:
			case KEY_SPACE:
			case KEY_TOKEN:
			case KEY_TYPE:
			case KEY_UNIMPL:
			case KEY_VALUES:
			case KEY_VARIABLES:
			case KEY_WORDSIZE:
				{
				alt76=1;
				}
				break;
			case BIN_INT:
			case DEC_INT:
			case HEX_INT:
				{
				alt76=2;
				}
				break;
			case LPAREN:
				{
				alt76=3;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 76, 0, input);
				throw nvae;
			}
			switch (alt76) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:518:4: identifier
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_identifier_in_pexpression2_term3058);
					identifier216=identifier();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, identifier216.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:519:4: integer
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_integer_in_pexpression2_term3063);
					integer217=integer();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, integer217.getTree());

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighParser.g:520:4: lc= LPAREN pexpression2 RPAREN
					{
					lc=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_pexpression2_term3070); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_LPAREN.add(lc);

					pushFollow(FOLLOW_pexpression2_in_pexpression2_term3072);
					pexpression2218=pexpression2();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) stream_pexpression2.add(pexpression2218.getTree());
					RPAREN219=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_pexpression2_term3074); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_RPAREN.add(RPAREN219);

					// AST REWRITE
					// elements: pexpression2
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 520:34: -> ^( OP_PARENTHESIZED[$lc, \"(...)\"] pexpression2 )
					{
						// ghidra/sleigh/grammar/SleighParser.g:520:37: ^( OP_PARENTHESIZED[$lc, \"(...)\"] pexpression2 )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_PARENTHESIZED, lc, "(...)"), root_1);
						adaptor.addChild(root_1, stream_pexpression2.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "pexpression2_term"


	public static class qstring_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "qstring"
	// ghidra/sleigh/grammar/SleighParser.g:523:1: qstring : lc= QSTRING -> ^( OP_QSTRING[$lc, \"QSTRING\"] QSTRING ) ;
	public final SleighParser.qstring_return qstring() throws RecognitionException {
		SleighParser.qstring_return retval = new SleighParser.qstring_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_QSTRING=new RewriteRuleTokenStream(adaptor,"token QSTRING");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:524:2: (lc= QSTRING -> ^( OP_QSTRING[$lc, \"QSTRING\"] QSTRING ) )
			// ghidra/sleigh/grammar/SleighParser.g:524:4: lc= QSTRING
			{
			lc=(Token)match(input,QSTRING,FOLLOW_QSTRING_in_qstring3096); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_QSTRING.add(lc);

			// AST REWRITE
			// elements: QSTRING
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 524:15: -> ^( OP_QSTRING[$lc, \"QSTRING\"] QSTRING )
			{
				// ghidra/sleigh/grammar/SleighParser.g:524:18: ^( OP_QSTRING[$lc, \"QSTRING\"] QSTRING )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_QSTRING, lc, "QSTRING"), root_1);
				adaptor.addChild(root_1, stream_QSTRING.nextNode());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "qstring"


	public static class id_or_wild_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "id_or_wild"
	// ghidra/sleigh/grammar/SleighParser.g:527:1: id_or_wild : ( identifier | wildcard );
	public final SleighParser.id_or_wild_return id_or_wild() throws RecognitionException {
		SleighParser.id_or_wild_return retval = new SleighParser.id_or_wild_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope identifier220 =null;
		ParserRuleReturnScope wildcard221 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:528:2: ( identifier | wildcard )
			int alt77=2;
			int LA77_0 = input.LA(1);
			if ( ((LA77_0 >= IDENTIFIER && LA77_0 <= KEY_WORDSIZE)) ) {
				alt77=1;
			}
			else if ( (LA77_0==UNDERSCORE) ) {
				alt77=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 77, 0, input);
				throw nvae;
			}

			switch (alt77) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:528:4: identifier
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_identifier_in_id_or_wild3116);
					identifier220=identifier();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, identifier220.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:529:4: wildcard
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_wildcard_in_id_or_wild3121);
					wildcard221=wildcard();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, wildcard221.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "id_or_wild"


	public static class wildcard_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "wildcard"
	// ghidra/sleigh/grammar/SleighParser.g:532:1: wildcard : lc= UNDERSCORE -> OP_WILDCARD[$lc] ;
	public final SleighParser.wildcard_return wildcard() throws RecognitionException {
		SleighParser.wildcard_return retval = new SleighParser.wildcard_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_UNDERSCORE=new RewriteRuleTokenStream(adaptor,"token UNDERSCORE");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:533:2: (lc= UNDERSCORE -> OP_WILDCARD[$lc] )
			// ghidra/sleigh/grammar/SleighParser.g:533:4: lc= UNDERSCORE
			{
			lc=(Token)match(input,UNDERSCORE,FOLLOW_UNDERSCORE_in_wildcard3134); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_UNDERSCORE.add(lc);

			// AST REWRITE
			// elements: 
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 533:19: -> OP_WILDCARD[$lc]
			{
				adaptor.addChild(root_0, (CommonTree)adaptor.create(OP_WILDCARD, lc));
			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "wildcard"


	public static class identifier_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "identifier"
	// ghidra/sleigh/grammar/SleighParser.g:536:1: identifier : ( strict_id | key_as_id );
	public final SleighParser.identifier_return identifier() throws RecognitionException {
		SleighParser.identifier_return retval = new SleighParser.identifier_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope strict_id222 =null;
		ParserRuleReturnScope key_as_id223 =null;


		try {
			// ghidra/sleigh/grammar/SleighParser.g:537:2: ( strict_id | key_as_id )
			int alt78=2;
			int LA78_0 = input.LA(1);
			if ( (LA78_0==IDENTIFIER) ) {
				alt78=1;
			}
			else if ( ((LA78_0 >= KEY_ALIGNMENT && LA78_0 <= KEY_WORDSIZE)) ) {
				alt78=2;
			}

			else {
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 78, 0, input);
				throw nvae;
			}

			switch (alt78) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:537:4: strict_id
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_strict_id_in_identifier3151);
					strict_id222=strict_id();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, strict_id222.getTree());

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:538:4: key_as_id
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_key_as_id_in_identifier3156);
					key_as_id223=key_as_id();
					state._fsp--;
					if (state.failed) return retval;
					if ( state.backtracking==0 ) adaptor.addChild(root_0, key_as_id223.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "identifier"


	public static class key_as_id_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "key_as_id"
	// ghidra/sleigh/grammar/SleighParser.g:541:1: key_as_id : (lc= KEY_ALIGNMENT -> ^( OP_IDENTIFIER[$lc, \"KEY_ALIGNMENT\"] KEY_ALIGNMENT ) |lc= KEY_ATTACH -> ^( OP_IDENTIFIER[$lc, \"KEY_ATTACH\"] KEY_ATTACH ) |lc= KEY_BIG -> ^( OP_IDENTIFIER[$lc, \"KEY_BIG\"] KEY_BIG ) |lc= KEY_BITRANGE -> ^( OP_IDENTIFIER[$lc, \"KEY_BITRANGE\"] KEY_BITRANGE ) |lc= KEY_BUILD -> ^( OP_IDENTIFIER[$lc, \"KEY_BUILD\"] KEY_BUILD ) |lc= KEY_CALL -> ^( OP_IDENTIFIER[$lc, \"KEY_CALL\"] KEY_CALL ) |lc= KEY_CONTEXT -> ^( OP_IDENTIFIER[$lc, \"KEY_CONTEXT\"] KEY_CONTEXT ) |lc= KEY_CROSSBUILD -> ^( OP_IDENTIFIER[$lc, \"KEY_CROSSBUILD\"] KEY_CROSSBUILD ) |lc= KEY_DEC -> ^( OP_IDENTIFIER[$lc, \"KEY_DEC\"] KEY_DEC ) |lc= KEY_DEFAULT -> ^( OP_IDENTIFIER[$lc, \"KEY_DEFAULT\"] KEY_DEFAULT ) |lc= KEY_DEFINE -> ^( OP_IDENTIFIER[$lc, \"KEY_DEFINE\"] KEY_DEFINE ) |lc= KEY_ENDIAN -> ^( OP_IDENTIFIER[$lc, \"KEY_ENDIAN\"] KEY_ENDIAN ) |lc= KEY_EXPORT -> ^( OP_IDENTIFIER[$lc, \"KEY_EXPORT\"] KEY_EXPORT ) |lc= KEY_GOTO -> ^( OP_IDENTIFIER[$lc, \"KEY_GOTO\"] KEY_GOTO ) |lc= KEY_HEX -> ^( OP_IDENTIFIER[$lc, \"KEY_HEX\"] KEY_HEX ) |lc= KEY_LITTLE -> ^( OP_IDENTIFIER[$lc, \"KEY_LITTLE\"] KEY_LITTLE ) |lc= KEY_LOCAL -> ^( OP_IDENTIFIER[$lc, \"KEY_LOCAL\"] KEY_LOCAL ) |lc= KEY_MACRO -> ^( OP_IDENTIFIER[$lc, \"KEY_MACRO\"] KEY_MACRO ) |lc= KEY_NAMES -> ^( OP_IDENTIFIER[$lc, \"KEY_NAMES\"] KEY_NAMES ) |lc= KEY_NOFLOW -> ^( OP_IDENTIFIER[$lc, \"KEY_NOFLOW\"] KEY_NOFLOW ) |lc= KEY_OFFSET -> ^( OP_IDENTIFIER[$lc, \"KEY_OFFSET\"] KEY_OFFSET ) |lc= KEY_PCODEOP -> ^( OP_IDENTIFIER[$lc, \"KEY_PCODEOP\"] KEY_PCODEOP ) |lc= KEY_RETURN -> ^( OP_IDENTIFIER[$lc, \"KEY_RETURN\"] KEY_RETURN ) |lc= KEY_SIGNED -> ^( OP_IDENTIFIER[$lc, \"KEY_SIGNED\"] KEY_SIGNED ) |lc= KEY_SIZE -> ^( OP_IDENTIFIER[$lc, \"KEY_SIZE\"] KEY_SIZE ) |lc= KEY_SPACE -> ^( OP_IDENTIFIER[$lc, \"KEY_SPACE\"] KEY_SPACE ) |lc= KEY_TOKEN -> ^( OP_IDENTIFIER[$lc, \"KEY_TOKEN\"] KEY_TOKEN ) |lc= KEY_TYPE -> ^( OP_IDENTIFIER[$lc, \"KEY_TYPE\"] KEY_TYPE ) |lc= KEY_UNIMPL -> ^( OP_IDENTIFIER[$lc, \"KEY_UNIMPL\"] KEY_UNIMPL ) |lc= KEY_VALUES -> ^( OP_IDENTIFIER[$lc, \"KEY_VALUES\"] KEY_VALUES ) |lc= KEY_VARIABLES -> ^( OP_IDENTIFIER[$lc, \"KEY_VARIABLES\"] KEY_VARIABLES ) |lc= KEY_WORDSIZE -> ^( OP_IDENTIFIER[$lc, \"KEY_WORDSIZE\"] KEY_WORDSIZE ) );
	public final SleighParser.key_as_id_return key_as_id() throws RecognitionException {
		SleighParser.key_as_id_return retval = new SleighParser.key_as_id_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_KEY_ENDIAN=new RewriteRuleTokenStream(adaptor,"token KEY_ENDIAN");
		RewriteRuleTokenStream stream_KEY_VALUES=new RewriteRuleTokenStream(adaptor,"token KEY_VALUES");
		RewriteRuleTokenStream stream_KEY_SIZE=new RewriteRuleTokenStream(adaptor,"token KEY_SIZE");
		RewriteRuleTokenStream stream_KEY_WORDSIZE=new RewriteRuleTokenStream(adaptor,"token KEY_WORDSIZE");
		RewriteRuleTokenStream stream_KEY_UNIMPL=new RewriteRuleTokenStream(adaptor,"token KEY_UNIMPL");
		RewriteRuleTokenStream stream_KEY_BITRANGE=new RewriteRuleTokenStream(adaptor,"token KEY_BITRANGE");
		RewriteRuleTokenStream stream_KEY_DEFINE=new RewriteRuleTokenStream(adaptor,"token KEY_DEFINE");
		RewriteRuleTokenStream stream_KEY_EXPORT=new RewriteRuleTokenStream(adaptor,"token KEY_EXPORT");
		RewriteRuleTokenStream stream_KEY_BUILD=new RewriteRuleTokenStream(adaptor,"token KEY_BUILD");
		RewriteRuleTokenStream stream_KEY_CALL=new RewriteRuleTokenStream(adaptor,"token KEY_CALL");
		RewriteRuleTokenStream stream_KEY_GOTO=new RewriteRuleTokenStream(adaptor,"token KEY_GOTO");
		RewriteRuleTokenStream stream_KEY_VARIABLES=new RewriteRuleTokenStream(adaptor,"token KEY_VARIABLES");
		RewriteRuleTokenStream stream_KEY_BIG=new RewriteRuleTokenStream(adaptor,"token KEY_BIG");
		RewriteRuleTokenStream stream_KEY_DEFAULT=new RewriteRuleTokenStream(adaptor,"token KEY_DEFAULT");
		RewriteRuleTokenStream stream_KEY_ATTACH=new RewriteRuleTokenStream(adaptor,"token KEY_ATTACH");
		RewriteRuleTokenStream stream_KEY_DEC=new RewriteRuleTokenStream(adaptor,"token KEY_DEC");
		RewriteRuleTokenStream stream_KEY_NAMES=new RewriteRuleTokenStream(adaptor,"token KEY_NAMES");
		RewriteRuleTokenStream stream_KEY_CONTEXT=new RewriteRuleTokenStream(adaptor,"token KEY_CONTEXT");
		RewriteRuleTokenStream stream_KEY_OFFSET=new RewriteRuleTokenStream(adaptor,"token KEY_OFFSET");
		RewriteRuleTokenStream stream_KEY_SIGNED=new RewriteRuleTokenStream(adaptor,"token KEY_SIGNED");
		RewriteRuleTokenStream stream_KEY_MACRO=new RewriteRuleTokenStream(adaptor,"token KEY_MACRO");
		RewriteRuleTokenStream stream_KEY_NOFLOW=new RewriteRuleTokenStream(adaptor,"token KEY_NOFLOW");
		RewriteRuleTokenStream stream_KEY_TOKEN=new RewriteRuleTokenStream(adaptor,"token KEY_TOKEN");
		RewriteRuleTokenStream stream_KEY_CROSSBUILD=new RewriteRuleTokenStream(adaptor,"token KEY_CROSSBUILD");
		RewriteRuleTokenStream stream_KEY_LOCAL=new RewriteRuleTokenStream(adaptor,"token KEY_LOCAL");
		RewriteRuleTokenStream stream_KEY_PCODEOP=new RewriteRuleTokenStream(adaptor,"token KEY_PCODEOP");
		RewriteRuleTokenStream stream_KEY_ALIGNMENT=new RewriteRuleTokenStream(adaptor,"token KEY_ALIGNMENT");
		RewriteRuleTokenStream stream_KEY_LITTLE=new RewriteRuleTokenStream(adaptor,"token KEY_LITTLE");
		RewriteRuleTokenStream stream_KEY_SPACE=new RewriteRuleTokenStream(adaptor,"token KEY_SPACE");
		RewriteRuleTokenStream stream_KEY_TYPE=new RewriteRuleTokenStream(adaptor,"token KEY_TYPE");
		RewriteRuleTokenStream stream_KEY_HEX=new RewriteRuleTokenStream(adaptor,"token KEY_HEX");
		RewriteRuleTokenStream stream_KEY_RETURN=new RewriteRuleTokenStream(adaptor,"token KEY_RETURN");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:542:2: (lc= KEY_ALIGNMENT -> ^( OP_IDENTIFIER[$lc, \"KEY_ALIGNMENT\"] KEY_ALIGNMENT ) |lc= KEY_ATTACH -> ^( OP_IDENTIFIER[$lc, \"KEY_ATTACH\"] KEY_ATTACH ) |lc= KEY_BIG -> ^( OP_IDENTIFIER[$lc, \"KEY_BIG\"] KEY_BIG ) |lc= KEY_BITRANGE -> ^( OP_IDENTIFIER[$lc, \"KEY_BITRANGE\"] KEY_BITRANGE ) |lc= KEY_BUILD -> ^( OP_IDENTIFIER[$lc, \"KEY_BUILD\"] KEY_BUILD ) |lc= KEY_CALL -> ^( OP_IDENTIFIER[$lc, \"KEY_CALL\"] KEY_CALL ) |lc= KEY_CONTEXT -> ^( OP_IDENTIFIER[$lc, \"KEY_CONTEXT\"] KEY_CONTEXT ) |lc= KEY_CROSSBUILD -> ^( OP_IDENTIFIER[$lc, \"KEY_CROSSBUILD\"] KEY_CROSSBUILD ) |lc= KEY_DEC -> ^( OP_IDENTIFIER[$lc, \"KEY_DEC\"] KEY_DEC ) |lc= KEY_DEFAULT -> ^( OP_IDENTIFIER[$lc, \"KEY_DEFAULT\"] KEY_DEFAULT ) |lc= KEY_DEFINE -> ^( OP_IDENTIFIER[$lc, \"KEY_DEFINE\"] KEY_DEFINE ) |lc= KEY_ENDIAN -> ^( OP_IDENTIFIER[$lc, \"KEY_ENDIAN\"] KEY_ENDIAN ) |lc= KEY_EXPORT -> ^( OP_IDENTIFIER[$lc, \"KEY_EXPORT\"] KEY_EXPORT ) |lc= KEY_GOTO -> ^( OP_IDENTIFIER[$lc, \"KEY_GOTO\"] KEY_GOTO ) |lc= KEY_HEX -> ^( OP_IDENTIFIER[$lc, \"KEY_HEX\"] KEY_HEX ) |lc= KEY_LITTLE -> ^( OP_IDENTIFIER[$lc, \"KEY_LITTLE\"] KEY_LITTLE ) |lc= KEY_LOCAL -> ^( OP_IDENTIFIER[$lc, \"KEY_LOCAL\"] KEY_LOCAL ) |lc= KEY_MACRO -> ^( OP_IDENTIFIER[$lc, \"KEY_MACRO\"] KEY_MACRO ) |lc= KEY_NAMES -> ^( OP_IDENTIFIER[$lc, \"KEY_NAMES\"] KEY_NAMES ) |lc= KEY_NOFLOW -> ^( OP_IDENTIFIER[$lc, \"KEY_NOFLOW\"] KEY_NOFLOW ) |lc= KEY_OFFSET -> ^( OP_IDENTIFIER[$lc, \"KEY_OFFSET\"] KEY_OFFSET ) |lc= KEY_PCODEOP -> ^( OP_IDENTIFIER[$lc, \"KEY_PCODEOP\"] KEY_PCODEOP ) |lc= KEY_RETURN -> ^( OP_IDENTIFIER[$lc, \"KEY_RETURN\"] KEY_RETURN ) |lc= KEY_SIGNED -> ^( OP_IDENTIFIER[$lc, \"KEY_SIGNED\"] KEY_SIGNED ) |lc= KEY_SIZE -> ^( OP_IDENTIFIER[$lc, \"KEY_SIZE\"] KEY_SIZE ) |lc= KEY_SPACE -> ^( OP_IDENTIFIER[$lc, \"KEY_SPACE\"] KEY_SPACE ) |lc= KEY_TOKEN -> ^( OP_IDENTIFIER[$lc, \"KEY_TOKEN\"] KEY_TOKEN ) |lc= KEY_TYPE -> ^( OP_IDENTIFIER[$lc, \"KEY_TYPE\"] KEY_TYPE ) |lc= KEY_UNIMPL -> ^( OP_IDENTIFIER[$lc, \"KEY_UNIMPL\"] KEY_UNIMPL ) |lc= KEY_VALUES -> ^( OP_IDENTIFIER[$lc, \"KEY_VALUES\"] KEY_VALUES ) |lc= KEY_VARIABLES -> ^( OP_IDENTIFIER[$lc, \"KEY_VARIABLES\"] KEY_VARIABLES ) |lc= KEY_WORDSIZE -> ^( OP_IDENTIFIER[$lc, \"KEY_WORDSIZE\"] KEY_WORDSIZE ) )
			int alt79=32;
			switch ( input.LA(1) ) {
			case KEY_ALIGNMENT:
				{
				alt79=1;
				}
				break;
			case KEY_ATTACH:
				{
				alt79=2;
				}
				break;
			case KEY_BIG:
				{
				alt79=3;
				}
				break;
			case KEY_BITRANGE:
				{
				alt79=4;
				}
				break;
			case KEY_BUILD:
				{
				alt79=5;
				}
				break;
			case KEY_CALL:
				{
				alt79=6;
				}
				break;
			case KEY_CONTEXT:
				{
				alt79=7;
				}
				break;
			case KEY_CROSSBUILD:
				{
				alt79=8;
				}
				break;
			case KEY_DEC:
				{
				alt79=9;
				}
				break;
			case KEY_DEFAULT:
				{
				alt79=10;
				}
				break;
			case KEY_DEFINE:
				{
				alt79=11;
				}
				break;
			case KEY_ENDIAN:
				{
				alt79=12;
				}
				break;
			case KEY_EXPORT:
				{
				alt79=13;
				}
				break;
			case KEY_GOTO:
				{
				alt79=14;
				}
				break;
			case KEY_HEX:
				{
				alt79=15;
				}
				break;
			case KEY_LITTLE:
				{
				alt79=16;
				}
				break;
			case KEY_LOCAL:
				{
				alt79=17;
				}
				break;
			case KEY_MACRO:
				{
				alt79=18;
				}
				break;
			case KEY_NAMES:
				{
				alt79=19;
				}
				break;
			case KEY_NOFLOW:
				{
				alt79=20;
				}
				break;
			case KEY_OFFSET:
				{
				alt79=21;
				}
				break;
			case KEY_PCODEOP:
				{
				alt79=22;
				}
				break;
			case KEY_RETURN:
				{
				alt79=23;
				}
				break;
			case KEY_SIGNED:
				{
				alt79=24;
				}
				break;
			case KEY_SIZE:
				{
				alt79=25;
				}
				break;
			case KEY_SPACE:
				{
				alt79=26;
				}
				break;
			case KEY_TOKEN:
				{
				alt79=27;
				}
				break;
			case KEY_TYPE:
				{
				alt79=28;
				}
				break;
			case KEY_UNIMPL:
				{
				alt79=29;
				}
				break;
			case KEY_VALUES:
				{
				alt79=30;
				}
				break;
			case KEY_VARIABLES:
				{
				alt79=31;
				}
				break;
			case KEY_WORDSIZE:
				{
				alt79=32;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 79, 0, input);
				throw nvae;
			}
			switch (alt79) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:542:4: lc= KEY_ALIGNMENT
					{
					lc=(Token)match(input,KEY_ALIGNMENT,FOLLOW_KEY_ALIGNMENT_in_key_as_id3169); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_ALIGNMENT.add(lc);

					// AST REWRITE
					// elements: KEY_ALIGNMENT
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 542:21: -> ^( OP_IDENTIFIER[$lc, \"KEY_ALIGNMENT\"] KEY_ALIGNMENT )
					{
						// ghidra/sleigh/grammar/SleighParser.g:542:24: ^( OP_IDENTIFIER[$lc, \"KEY_ALIGNMENT\"] KEY_ALIGNMENT )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_ALIGNMENT"), root_1);
						adaptor.addChild(root_1, stream_KEY_ALIGNMENT.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:543:4: lc= KEY_ATTACH
					{
					lc=(Token)match(input,KEY_ATTACH,FOLLOW_KEY_ATTACH_in_key_as_id3185); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_ATTACH.add(lc);

					// AST REWRITE
					// elements: KEY_ATTACH
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 543:19: -> ^( OP_IDENTIFIER[$lc, \"KEY_ATTACH\"] KEY_ATTACH )
					{
						// ghidra/sleigh/grammar/SleighParser.g:543:22: ^( OP_IDENTIFIER[$lc, \"KEY_ATTACH\"] KEY_ATTACH )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_ATTACH"), root_1);
						adaptor.addChild(root_1, stream_KEY_ATTACH.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighParser.g:544:4: lc= KEY_BIG
					{
					lc=(Token)match(input,KEY_BIG,FOLLOW_KEY_BIG_in_key_as_id3202); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_BIG.add(lc);

					// AST REWRITE
					// elements: KEY_BIG
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 544:17: -> ^( OP_IDENTIFIER[$lc, \"KEY_BIG\"] KEY_BIG )
					{
						// ghidra/sleigh/grammar/SleighParser.g:544:20: ^( OP_IDENTIFIER[$lc, \"KEY_BIG\"] KEY_BIG )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_BIG"), root_1);
						adaptor.addChild(root_1, stream_KEY_BIG.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighParser.g:545:4: lc= KEY_BITRANGE
					{
					lc=(Token)match(input,KEY_BITRANGE,FOLLOW_KEY_BITRANGE_in_key_as_id3220); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_BITRANGE.add(lc);

					// AST REWRITE
					// elements: KEY_BITRANGE
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 545:21: -> ^( OP_IDENTIFIER[$lc, \"KEY_BITRANGE\"] KEY_BITRANGE )
					{
						// ghidra/sleigh/grammar/SleighParser.g:545:24: ^( OP_IDENTIFIER[$lc, \"KEY_BITRANGE\"] KEY_BITRANGE )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_BITRANGE"), root_1);
						adaptor.addChild(root_1, stream_KEY_BITRANGE.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighParser.g:546:4: lc= KEY_BUILD
					{
					lc=(Token)match(input,KEY_BUILD,FOLLOW_KEY_BUILD_in_key_as_id3237); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_BUILD.add(lc);

					// AST REWRITE
					// elements: KEY_BUILD
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 546:18: -> ^( OP_IDENTIFIER[$lc, \"KEY_BUILD\"] KEY_BUILD )
					{
						// ghidra/sleigh/grammar/SleighParser.g:546:21: ^( OP_IDENTIFIER[$lc, \"KEY_BUILD\"] KEY_BUILD )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_BUILD"), root_1);
						adaptor.addChild(root_1, stream_KEY_BUILD.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighParser.g:547:4: lc= KEY_CALL
					{
					lc=(Token)match(input,KEY_CALL,FOLLOW_KEY_CALL_in_key_as_id3254); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_CALL.add(lc);

					// AST REWRITE
					// elements: KEY_CALL
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 547:18: -> ^( OP_IDENTIFIER[$lc, \"KEY_CALL\"] KEY_CALL )
					{
						// ghidra/sleigh/grammar/SleighParser.g:547:21: ^( OP_IDENTIFIER[$lc, \"KEY_CALL\"] KEY_CALL )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_CALL"), root_1);
						adaptor.addChild(root_1, stream_KEY_CALL.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighParser.g:548:4: lc= KEY_CONTEXT
					{
					lc=(Token)match(input,KEY_CONTEXT,FOLLOW_KEY_CONTEXT_in_key_as_id3273); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_CONTEXT.add(lc);

					// AST REWRITE
					// elements: KEY_CONTEXT
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 548:20: -> ^( OP_IDENTIFIER[$lc, \"KEY_CONTEXT\"] KEY_CONTEXT )
					{
						// ghidra/sleigh/grammar/SleighParser.g:548:23: ^( OP_IDENTIFIER[$lc, \"KEY_CONTEXT\"] KEY_CONTEXT )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_CONTEXT"), root_1);
						adaptor.addChild(root_1, stream_KEY_CONTEXT.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 8 :
					// ghidra/sleigh/grammar/SleighParser.g:549:4: lc= KEY_CROSSBUILD
					{
					lc=(Token)match(input,KEY_CROSSBUILD,FOLLOW_KEY_CROSSBUILD_in_key_as_id3290); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_CROSSBUILD.add(lc);

					// AST REWRITE
					// elements: KEY_CROSSBUILD
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 549:22: -> ^( OP_IDENTIFIER[$lc, \"KEY_CROSSBUILD\"] KEY_CROSSBUILD )
					{
						// ghidra/sleigh/grammar/SleighParser.g:549:25: ^( OP_IDENTIFIER[$lc, \"KEY_CROSSBUILD\"] KEY_CROSSBUILD )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_CROSSBUILD"), root_1);
						adaptor.addChild(root_1, stream_KEY_CROSSBUILD.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 9 :
					// ghidra/sleigh/grammar/SleighParser.g:550:4: lc= KEY_DEC
					{
					lc=(Token)match(input,KEY_DEC,FOLLOW_KEY_DEC_in_key_as_id3306); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_DEC.add(lc);

					// AST REWRITE
					// elements: KEY_DEC
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 550:17: -> ^( OP_IDENTIFIER[$lc, \"KEY_DEC\"] KEY_DEC )
					{
						// ghidra/sleigh/grammar/SleighParser.g:550:20: ^( OP_IDENTIFIER[$lc, \"KEY_DEC\"] KEY_DEC )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_DEC"), root_1);
						adaptor.addChild(root_1, stream_KEY_DEC.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 10 :
					// ghidra/sleigh/grammar/SleighParser.g:551:4: lc= KEY_DEFAULT
					{
					lc=(Token)match(input,KEY_DEFAULT,FOLLOW_KEY_DEFAULT_in_key_as_id3325); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_DEFAULT.add(lc);

					// AST REWRITE
					// elements: KEY_DEFAULT
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 551:20: -> ^( OP_IDENTIFIER[$lc, \"KEY_DEFAULT\"] KEY_DEFAULT )
					{
						// ghidra/sleigh/grammar/SleighParser.g:551:23: ^( OP_IDENTIFIER[$lc, \"KEY_DEFAULT\"] KEY_DEFAULT )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_DEFAULT"), root_1);
						adaptor.addChild(root_1, stream_KEY_DEFAULT.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 11 :
					// ghidra/sleigh/grammar/SleighParser.g:552:4: lc= KEY_DEFINE
					{
					lc=(Token)match(input,KEY_DEFINE,FOLLOW_KEY_DEFINE_in_key_as_id3342); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_DEFINE.add(lc);

					// AST REWRITE
					// elements: KEY_DEFINE
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 552:19: -> ^( OP_IDENTIFIER[$lc, \"KEY_DEFINE\"] KEY_DEFINE )
					{
						// ghidra/sleigh/grammar/SleighParser.g:552:22: ^( OP_IDENTIFIER[$lc, \"KEY_DEFINE\"] KEY_DEFINE )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_DEFINE"), root_1);
						adaptor.addChild(root_1, stream_KEY_DEFINE.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 12 :
					// ghidra/sleigh/grammar/SleighParser.g:553:4: lc= KEY_ENDIAN
					{
					lc=(Token)match(input,KEY_ENDIAN,FOLLOW_KEY_ENDIAN_in_key_as_id3359); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_ENDIAN.add(lc);

					// AST REWRITE
					// elements: KEY_ENDIAN
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 553:19: -> ^( OP_IDENTIFIER[$lc, \"KEY_ENDIAN\"] KEY_ENDIAN )
					{
						// ghidra/sleigh/grammar/SleighParser.g:553:22: ^( OP_IDENTIFIER[$lc, \"KEY_ENDIAN\"] KEY_ENDIAN )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_ENDIAN"), root_1);
						adaptor.addChild(root_1, stream_KEY_ENDIAN.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 13 :
					// ghidra/sleigh/grammar/SleighParser.g:554:4: lc= KEY_EXPORT
					{
					lc=(Token)match(input,KEY_EXPORT,FOLLOW_KEY_EXPORT_in_key_as_id3376); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_EXPORT.add(lc);

					// AST REWRITE
					// elements: KEY_EXPORT
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 554:19: -> ^( OP_IDENTIFIER[$lc, \"KEY_EXPORT\"] KEY_EXPORT )
					{
						// ghidra/sleigh/grammar/SleighParser.g:554:22: ^( OP_IDENTIFIER[$lc, \"KEY_EXPORT\"] KEY_EXPORT )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_EXPORT"), root_1);
						adaptor.addChild(root_1, stream_KEY_EXPORT.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 14 :
					// ghidra/sleigh/grammar/SleighParser.g:555:4: lc= KEY_GOTO
					{
					lc=(Token)match(input,KEY_GOTO,FOLLOW_KEY_GOTO_in_key_as_id3393); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_GOTO.add(lc);

					// AST REWRITE
					// elements: KEY_GOTO
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 555:18: -> ^( OP_IDENTIFIER[$lc, \"KEY_GOTO\"] KEY_GOTO )
					{
						// ghidra/sleigh/grammar/SleighParser.g:555:21: ^( OP_IDENTIFIER[$lc, \"KEY_GOTO\"] KEY_GOTO )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_GOTO"), root_1);
						adaptor.addChild(root_1, stream_KEY_GOTO.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 15 :
					// ghidra/sleigh/grammar/SleighParser.g:556:4: lc= KEY_HEX
					{
					lc=(Token)match(input,KEY_HEX,FOLLOW_KEY_HEX_in_key_as_id3411); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_HEX.add(lc);

					// AST REWRITE
					// elements: KEY_HEX
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 556:17: -> ^( OP_IDENTIFIER[$lc, \"KEY_HEX\"] KEY_HEX )
					{
						// ghidra/sleigh/grammar/SleighParser.g:556:20: ^( OP_IDENTIFIER[$lc, \"KEY_HEX\"] KEY_HEX )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_HEX"), root_1);
						adaptor.addChild(root_1, stream_KEY_HEX.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 16 :
					// ghidra/sleigh/grammar/SleighParser.g:557:4: lc= KEY_LITTLE
					{
					lc=(Token)match(input,KEY_LITTLE,FOLLOW_KEY_LITTLE_in_key_as_id3429); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_LITTLE.add(lc);

					// AST REWRITE
					// elements: KEY_LITTLE
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 557:19: -> ^( OP_IDENTIFIER[$lc, \"KEY_LITTLE\"] KEY_LITTLE )
					{
						// ghidra/sleigh/grammar/SleighParser.g:557:22: ^( OP_IDENTIFIER[$lc, \"KEY_LITTLE\"] KEY_LITTLE )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_LITTLE"), root_1);
						adaptor.addChild(root_1, stream_KEY_LITTLE.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 17 :
					// ghidra/sleigh/grammar/SleighParser.g:558:4: lc= KEY_LOCAL
					{
					lc=(Token)match(input,KEY_LOCAL,FOLLOW_KEY_LOCAL_in_key_as_id3446); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_LOCAL.add(lc);

					// AST REWRITE
					// elements: KEY_LOCAL
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 558:18: -> ^( OP_IDENTIFIER[$lc, \"KEY_LOCAL\"] KEY_LOCAL )
					{
						// ghidra/sleigh/grammar/SleighParser.g:558:21: ^( OP_IDENTIFIER[$lc, \"KEY_LOCAL\"] KEY_LOCAL )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_LOCAL"), root_1);
						adaptor.addChild(root_1, stream_KEY_LOCAL.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 18 :
					// ghidra/sleigh/grammar/SleighParser.g:559:4: lc= KEY_MACRO
					{
					lc=(Token)match(input,KEY_MACRO,FOLLOW_KEY_MACRO_in_key_as_id3463); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_MACRO.add(lc);

					// AST REWRITE
					// elements: KEY_MACRO
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 559:18: -> ^( OP_IDENTIFIER[$lc, \"KEY_MACRO\"] KEY_MACRO )
					{
						// ghidra/sleigh/grammar/SleighParser.g:559:21: ^( OP_IDENTIFIER[$lc, \"KEY_MACRO\"] KEY_MACRO )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_MACRO"), root_1);
						adaptor.addChild(root_1, stream_KEY_MACRO.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 19 :
					// ghidra/sleigh/grammar/SleighParser.g:560:4: lc= KEY_NAMES
					{
					lc=(Token)match(input,KEY_NAMES,FOLLOW_KEY_NAMES_in_key_as_id3480); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_NAMES.add(lc);

					// AST REWRITE
					// elements: KEY_NAMES
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 560:18: -> ^( OP_IDENTIFIER[$lc, \"KEY_NAMES\"] KEY_NAMES )
					{
						// ghidra/sleigh/grammar/SleighParser.g:560:21: ^( OP_IDENTIFIER[$lc, \"KEY_NAMES\"] KEY_NAMES )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_NAMES"), root_1);
						adaptor.addChild(root_1, stream_KEY_NAMES.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 20 :
					// ghidra/sleigh/grammar/SleighParser.g:561:4: lc= KEY_NOFLOW
					{
					lc=(Token)match(input,KEY_NOFLOW,FOLLOW_KEY_NOFLOW_in_key_as_id3497); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_NOFLOW.add(lc);

					// AST REWRITE
					// elements: KEY_NOFLOW
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 561:19: -> ^( OP_IDENTIFIER[$lc, \"KEY_NOFLOW\"] KEY_NOFLOW )
					{
						// ghidra/sleigh/grammar/SleighParser.g:561:22: ^( OP_IDENTIFIER[$lc, \"KEY_NOFLOW\"] KEY_NOFLOW )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_NOFLOW"), root_1);
						adaptor.addChild(root_1, stream_KEY_NOFLOW.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 21 :
					// ghidra/sleigh/grammar/SleighParser.g:562:4: lc= KEY_OFFSET
					{
					lc=(Token)match(input,KEY_OFFSET,FOLLOW_KEY_OFFSET_in_key_as_id3514); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_OFFSET.add(lc);

					// AST REWRITE
					// elements: KEY_OFFSET
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 562:19: -> ^( OP_IDENTIFIER[$lc, \"KEY_OFFSET\"] KEY_OFFSET )
					{
						// ghidra/sleigh/grammar/SleighParser.g:562:22: ^( OP_IDENTIFIER[$lc, \"KEY_OFFSET\"] KEY_OFFSET )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_OFFSET"), root_1);
						adaptor.addChild(root_1, stream_KEY_OFFSET.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 22 :
					// ghidra/sleigh/grammar/SleighParser.g:563:4: lc= KEY_PCODEOP
					{
					lc=(Token)match(input,KEY_PCODEOP,FOLLOW_KEY_PCODEOP_in_key_as_id3531); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_PCODEOP.add(lc);

					// AST REWRITE
					// elements: KEY_PCODEOP
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 563:20: -> ^( OP_IDENTIFIER[$lc, \"KEY_PCODEOP\"] KEY_PCODEOP )
					{
						// ghidra/sleigh/grammar/SleighParser.g:563:23: ^( OP_IDENTIFIER[$lc, \"KEY_PCODEOP\"] KEY_PCODEOP )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_PCODEOP"), root_1);
						adaptor.addChild(root_1, stream_KEY_PCODEOP.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 23 :
					// ghidra/sleigh/grammar/SleighParser.g:564:4: lc= KEY_RETURN
					{
					lc=(Token)match(input,KEY_RETURN,FOLLOW_KEY_RETURN_in_key_as_id3548); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_RETURN.add(lc);

					// AST REWRITE
					// elements: KEY_RETURN
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 564:19: -> ^( OP_IDENTIFIER[$lc, \"KEY_RETURN\"] KEY_RETURN )
					{
						// ghidra/sleigh/grammar/SleighParser.g:564:22: ^( OP_IDENTIFIER[$lc, \"KEY_RETURN\"] KEY_RETURN )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_RETURN"), root_1);
						adaptor.addChild(root_1, stream_KEY_RETURN.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 24 :
					// ghidra/sleigh/grammar/SleighParser.g:565:4: lc= KEY_SIGNED
					{
					lc=(Token)match(input,KEY_SIGNED,FOLLOW_KEY_SIGNED_in_key_as_id3565); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_SIGNED.add(lc);

					// AST REWRITE
					// elements: KEY_SIGNED
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 565:19: -> ^( OP_IDENTIFIER[$lc, \"KEY_SIGNED\"] KEY_SIGNED )
					{
						// ghidra/sleigh/grammar/SleighParser.g:565:22: ^( OP_IDENTIFIER[$lc, \"KEY_SIGNED\"] KEY_SIGNED )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_SIGNED"), root_1);
						adaptor.addChild(root_1, stream_KEY_SIGNED.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 25 :
					// ghidra/sleigh/grammar/SleighParser.g:566:4: lc= KEY_SIZE
					{
					lc=(Token)match(input,KEY_SIZE,FOLLOW_KEY_SIZE_in_key_as_id3582); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_SIZE.add(lc);

					// AST REWRITE
					// elements: KEY_SIZE
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 566:18: -> ^( OP_IDENTIFIER[$lc, \"KEY_SIZE\"] KEY_SIZE )
					{
						// ghidra/sleigh/grammar/SleighParser.g:566:21: ^( OP_IDENTIFIER[$lc, \"KEY_SIZE\"] KEY_SIZE )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_SIZE"), root_1);
						adaptor.addChild(root_1, stream_KEY_SIZE.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 26 :
					// ghidra/sleigh/grammar/SleighParser.g:567:4: lc= KEY_SPACE
					{
					lc=(Token)match(input,KEY_SPACE,FOLLOW_KEY_SPACE_in_key_as_id3600); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_SPACE.add(lc);

					// AST REWRITE
					// elements: KEY_SPACE
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 567:18: -> ^( OP_IDENTIFIER[$lc, \"KEY_SPACE\"] KEY_SPACE )
					{
						// ghidra/sleigh/grammar/SleighParser.g:567:21: ^( OP_IDENTIFIER[$lc, \"KEY_SPACE\"] KEY_SPACE )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_SPACE"), root_1);
						adaptor.addChild(root_1, stream_KEY_SPACE.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 27 :
					// ghidra/sleigh/grammar/SleighParser.g:568:4: lc= KEY_TOKEN
					{
					lc=(Token)match(input,KEY_TOKEN,FOLLOW_KEY_TOKEN_in_key_as_id3617); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_TOKEN.add(lc);

					// AST REWRITE
					// elements: KEY_TOKEN
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 568:18: -> ^( OP_IDENTIFIER[$lc, \"KEY_TOKEN\"] KEY_TOKEN )
					{
						// ghidra/sleigh/grammar/SleighParser.g:568:21: ^( OP_IDENTIFIER[$lc, \"KEY_TOKEN\"] KEY_TOKEN )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_TOKEN"), root_1);
						adaptor.addChild(root_1, stream_KEY_TOKEN.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 28 :
					// ghidra/sleigh/grammar/SleighParser.g:569:4: lc= KEY_TYPE
					{
					lc=(Token)match(input,KEY_TYPE,FOLLOW_KEY_TYPE_in_key_as_id3634); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_TYPE.add(lc);

					// AST REWRITE
					// elements: KEY_TYPE
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 569:18: -> ^( OP_IDENTIFIER[$lc, \"KEY_TYPE\"] KEY_TYPE )
					{
						// ghidra/sleigh/grammar/SleighParser.g:569:21: ^( OP_IDENTIFIER[$lc, \"KEY_TYPE\"] KEY_TYPE )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_TYPE"), root_1);
						adaptor.addChild(root_1, stream_KEY_TYPE.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 29 :
					// ghidra/sleigh/grammar/SleighParser.g:570:4: lc= KEY_UNIMPL
					{
					lc=(Token)match(input,KEY_UNIMPL,FOLLOW_KEY_UNIMPL_in_key_as_id3652); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_UNIMPL.add(lc);

					// AST REWRITE
					// elements: KEY_UNIMPL
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 570:19: -> ^( OP_IDENTIFIER[$lc, \"KEY_UNIMPL\"] KEY_UNIMPL )
					{
						// ghidra/sleigh/grammar/SleighParser.g:570:22: ^( OP_IDENTIFIER[$lc, \"KEY_UNIMPL\"] KEY_UNIMPL )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_UNIMPL"), root_1);
						adaptor.addChild(root_1, stream_KEY_UNIMPL.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 30 :
					// ghidra/sleigh/grammar/SleighParser.g:571:4: lc= KEY_VALUES
					{
					lc=(Token)match(input,KEY_VALUES,FOLLOW_KEY_VALUES_in_key_as_id3669); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_VALUES.add(lc);

					// AST REWRITE
					// elements: KEY_VALUES
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 571:19: -> ^( OP_IDENTIFIER[$lc, \"KEY_VALUES\"] KEY_VALUES )
					{
						// ghidra/sleigh/grammar/SleighParser.g:571:22: ^( OP_IDENTIFIER[$lc, \"KEY_VALUES\"] KEY_VALUES )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_VALUES"), root_1);
						adaptor.addChild(root_1, stream_KEY_VALUES.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 31 :
					// ghidra/sleigh/grammar/SleighParser.g:572:4: lc= KEY_VARIABLES
					{
					lc=(Token)match(input,KEY_VARIABLES,FOLLOW_KEY_VARIABLES_in_key_as_id3686); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_VARIABLES.add(lc);

					// AST REWRITE
					// elements: KEY_VARIABLES
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 572:21: -> ^( OP_IDENTIFIER[$lc, \"KEY_VARIABLES\"] KEY_VARIABLES )
					{
						// ghidra/sleigh/grammar/SleighParser.g:572:24: ^( OP_IDENTIFIER[$lc, \"KEY_VARIABLES\"] KEY_VARIABLES )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_VARIABLES"), root_1);
						adaptor.addChild(root_1, stream_KEY_VARIABLES.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 32 :
					// ghidra/sleigh/grammar/SleighParser.g:573:4: lc= KEY_WORDSIZE
					{
					lc=(Token)match(input,KEY_WORDSIZE,FOLLOW_KEY_WORDSIZE_in_key_as_id3702); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_KEY_WORDSIZE.add(lc);

					// AST REWRITE
					// elements: KEY_WORDSIZE
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 573:21: -> ^( OP_IDENTIFIER[$lc, \"KEY_WORDSIZE\"] KEY_WORDSIZE )
					{
						// ghidra/sleigh/grammar/SleighParser.g:573:24: ^( OP_IDENTIFIER[$lc, \"KEY_WORDSIZE\"] KEY_WORDSIZE )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "KEY_WORDSIZE"), root_1);
						adaptor.addChild(root_1, stream_KEY_WORDSIZE.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "key_as_id"


	public static class strict_id_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "strict_id"
	// ghidra/sleigh/grammar/SleighParser.g:576:1: strict_id : lc= IDENTIFIER -> ^( OP_IDENTIFIER[$lc, \"IDENTIFIER\"] IDENTIFIER ) ;
	public final SleighParser.strict_id_return strict_id() throws RecognitionException {
		SleighParser.strict_id_return retval = new SleighParser.strict_id_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_IDENTIFIER=new RewriteRuleTokenStream(adaptor,"token IDENTIFIER");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:577:2: (lc= IDENTIFIER -> ^( OP_IDENTIFIER[$lc, \"IDENTIFIER\"] IDENTIFIER ) )
			// ghidra/sleigh/grammar/SleighParser.g:577:4: lc= IDENTIFIER
			{
			lc=(Token)match(input,IDENTIFIER,FOLLOW_IDENTIFIER_in_strict_id3725); if (state.failed) return retval; 
			if ( state.backtracking==0 ) stream_IDENTIFIER.add(lc);

			// AST REWRITE
			// elements: IDENTIFIER
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			if ( state.backtracking==0 ) {
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 577:19: -> ^( OP_IDENTIFIER[$lc, \"IDENTIFIER\"] IDENTIFIER )
			{
				// ghidra/sleigh/grammar/SleighParser.g:577:22: ^( OP_IDENTIFIER[$lc, \"IDENTIFIER\"] IDENTIFIER )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IDENTIFIER, lc, "IDENTIFIER"), root_1);
				adaptor.addChild(root_1, stream_IDENTIFIER.nextNode());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;
			}

			}

			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "strict_id"


	public static class integer_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "integer"
	// ghidra/sleigh/grammar/SleighParser.g:580:1: integer : (lc= HEX_INT -> ^( OP_HEX_CONSTANT[$lc, \"HEX_INT\"] HEX_INT ) |lc= DEC_INT -> ^( OP_DEC_CONSTANT[$lc, \"DEC_INT\"] DEC_INT ) |lc= BIN_INT -> ^( OP_BIN_CONSTANT[$lc, \"BIN_INT\"] BIN_INT ) );
	public final SleighParser.integer_return integer() throws RecognitionException {
		SleighParser.integer_return retval = new SleighParser.integer_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_DEC_INT=new RewriteRuleTokenStream(adaptor,"token DEC_INT");
		RewriteRuleTokenStream stream_BIN_INT=new RewriteRuleTokenStream(adaptor,"token BIN_INT");
		RewriteRuleTokenStream stream_HEX_INT=new RewriteRuleTokenStream(adaptor,"token HEX_INT");

		try {
			// ghidra/sleigh/grammar/SleighParser.g:581:2: (lc= HEX_INT -> ^( OP_HEX_CONSTANT[$lc, \"HEX_INT\"] HEX_INT ) |lc= DEC_INT -> ^( OP_DEC_CONSTANT[$lc, \"DEC_INT\"] DEC_INT ) |lc= BIN_INT -> ^( OP_BIN_CONSTANT[$lc, \"BIN_INT\"] BIN_INT ) )
			int alt80=3;
			switch ( input.LA(1) ) {
			case HEX_INT:
				{
				alt80=1;
				}
				break;
			case DEC_INT:
				{
				alt80=2;
				}
				break;
			case BIN_INT:
				{
				alt80=3;
				}
				break;
			default:
				if (state.backtracking>0) {state.failed=true; return retval;}
				NoViableAltException nvae =
					new NoViableAltException("", 80, 0, input);
				throw nvae;
			}
			switch (alt80) {
				case 1 :
					// ghidra/sleigh/grammar/SleighParser.g:581:4: lc= HEX_INT
					{
					lc=(Token)match(input,HEX_INT,FOLLOW_HEX_INT_in_integer3748); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_HEX_INT.add(lc);

					// AST REWRITE
					// elements: HEX_INT
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 581:15: -> ^( OP_HEX_CONSTANT[$lc, \"HEX_INT\"] HEX_INT )
					{
						// ghidra/sleigh/grammar/SleighParser.g:581:18: ^( OP_HEX_CONSTANT[$lc, \"HEX_INT\"] HEX_INT )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_HEX_CONSTANT, lc, "HEX_INT"), root_1);
						adaptor.addChild(root_1, stream_HEX_INT.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighParser.g:582:4: lc= DEC_INT
					{
					lc=(Token)match(input,DEC_INT,FOLLOW_DEC_INT_in_integer3764); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_DEC_INT.add(lc);

					// AST REWRITE
					// elements: DEC_INT
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 582:15: -> ^( OP_DEC_CONSTANT[$lc, \"DEC_INT\"] DEC_INT )
					{
						// ghidra/sleigh/grammar/SleighParser.g:582:18: ^( OP_DEC_CONSTANT[$lc, \"DEC_INT\"] DEC_INT )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_DEC_CONSTANT, lc, "DEC_INT"), root_1);
						adaptor.addChild(root_1, stream_DEC_INT.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighParser.g:583:4: lc= BIN_INT
					{
					lc=(Token)match(input,BIN_INT,FOLLOW_BIN_INT_in_integer3780); if (state.failed) return retval; 
					if ( state.backtracking==0 ) stream_BIN_INT.add(lc);

					// AST REWRITE
					// elements: BIN_INT
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					if ( state.backtracking==0 ) {
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 583:15: -> ^( OP_BIN_CONSTANT[$lc, \"BIN_INT\"] BIN_INT )
					{
						// ghidra/sleigh/grammar/SleighParser.g:583:18: ^( OP_BIN_CONSTANT[$lc, \"BIN_INT\"] BIN_INT )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_BIN_CONSTANT, lc, "BIN_INT"), root_1);
						adaptor.addChild(root_1, stream_BIN_INT.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;
					}

					}
					break;

			}
			retval.stop = input.LT(-1);

			if ( state.backtracking==0 ) {
			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);
			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
			retval.tree = (CommonTree)adaptor.errorNode(input, retval.start, input.LT(-1), re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "integer"

	// $ANTLR start synpred1_SleighParser
	public final void synpred1_SleighParser_fragment() throws RecognitionException {
		// ghidra/sleigh/grammar/SleighParser.g:330:4: ( pequation_atomic ELLIPSIS )
		// ghidra/sleigh/grammar/SleighParser.g:330:5: pequation_atomic ELLIPSIS
		{
		pushFollow(FOLLOW_pequation_atomic_in_synpred1_SleighParser1986);
		pequation_atomic();
		state._fsp--;
		if (state.failed) return;

		match(input,ELLIPSIS,FOLLOW_ELLIPSIS_in_synpred1_SleighParser1988); if (state.failed) return;

		}

	}
	// $ANTLR end synpred1_SleighParser

	// Delegated rules
	public SleighParser_SemanticParser.sizedexport_return sizedexport() throws RecognitionException { return gSemanticParser.sizedexport(); }

	public SleighParser_SemanticParser.cond_stmt_return cond_stmt() throws RecognitionException { return gSemanticParser.cond_stmt(); }

	public SleighParser_SemanticParser.expr_add_return expr_add() throws RecognitionException { return gSemanticParser.expr_add(); }

	public SleighParser_DisplayParser.printpiece_return printpiece() throws RecognitionException { return gDisplayParser.printpiece(); }

	public SleighParser_DisplayParser.special_return special() throws RecognitionException { return gDisplayParser.special(); }

	public SleighParser_SemanticParser.call_stmt_return call_stmt() throws RecognitionException { return gSemanticParser.call_stmt(); }

	public SleighParser_SemanticParser.expr_func_return expr_func() throws RecognitionException { return gSemanticParser.expr_func(); }

	public SleighParser_SemanticParser.eq_op_return eq_op() throws RecognitionException { return gSemanticParser.eq_op(); }

	public SleighParser_SemanticParser.compare_op_return compare_op() throws RecognitionException { return gSemanticParser.compare_op(); }

	public SleighParser_SemanticParser.goto_stmt_return goto_stmt() throws RecognitionException { return gSemanticParser.goto_stmt(); }

	public SleighParser_SemanticParser.expr_term_return expr_term() throws RecognitionException { return gSemanticParser.expr_term(); }

	public SleighParser_SemanticParser.semanticbody_return semanticbody() throws RecognitionException { return gSemanticParser.semanticbody(); }

	public SleighParser_SemanticParser.semantic_return semantic() throws RecognitionException { return gSemanticParser.semantic(); }

	public SleighParser_SemanticParser.constant_return constant() throws RecognitionException { return gSemanticParser.constant(); }

	public SleighParser_SemanticParser.expr_or_return expr_or() throws RecognitionException { return gSemanticParser.expr_or(); }

	public SleighParser_SemanticParser.lvalue_return lvalue() throws RecognitionException { return gSemanticParser.lvalue(); }

	public SleighParser_SemanticParser.return_stmt_return return_stmt() throws RecognitionException { return gSemanticParser.return_stmt(); }

	public SleighParser_SemanticParser.statement_return statement() throws RecognitionException { return gSemanticParser.statement(); }

	public SleighParser_SemanticParser.build_stmt_return build_stmt() throws RecognitionException { return gSemanticParser.build_stmt(); }

	public SleighParser_SemanticParser.sizedstar_return sizedstar() throws RecognitionException { return gSemanticParser.sizedstar(); }

	public SleighParser_SemanticParser.expr_and_return expr_and() throws RecognitionException { return gSemanticParser.expr_and(); }

	public SleighParser_SemanticParser.outererror_return outererror() throws RecognitionException { return gSemanticParser.outererror(); }

	public SleighParser_SemanticParser.assignment_return assignment() throws RecognitionException { return gSemanticParser.assignment(); }

	public SleighParser_SemanticParser.label_return label() throws RecognitionException { return gSemanticParser.label(); }

	public SleighParser_SemanticParser.expr_xor_op_return expr_xor_op() throws RecognitionException { return gSemanticParser.expr_xor_op(); }

	public SleighParser_SemanticParser.sembitrange_return sembitrange() throws RecognitionException { return gSemanticParser.sembitrange(); }

	public SleighParser_SemanticParser.expr_boolor_op_return expr_boolor_op() throws RecognitionException { return gSemanticParser.expr_boolor_op(); }

	public SleighParser_SemanticParser.expr_return expr() throws RecognitionException { return gSemanticParser.expr(); }

	public SleighParser_SemanticParser.code_block_return code_block() throws RecognitionException { return gSemanticParser.code_block(); }

	public SleighParser_DisplayParser.pieces_return pieces() throws RecognitionException { return gDisplayParser.pieces(); }

	public SleighParser_SemanticParser.expr_unary_return expr_unary() throws RecognitionException { return gSemanticParser.expr_unary(); }

	public SleighParser_DisplayParser.concatenate_return concatenate() throws RecognitionException { return gDisplayParser.concatenate(); }

	public SleighParser_DisplayParser.whitespace_return whitespace() throws RecognitionException { return gDisplayParser.whitespace(); }

	public SleighParser_SemanticParser.shift_op_return shift_op() throws RecognitionException { return gSemanticParser.shift_op(); }

	public SleighParser_SemanticParser.mult_op_return mult_op() throws RecognitionException { return gSemanticParser.mult_op(); }

	public SleighParser_SemanticParser.funcall_return funcall() throws RecognitionException { return gSemanticParser.funcall(); }

	public SleighParser_SemanticParser.expr_or_op_return expr_or_op() throws RecognitionException { return gSemanticParser.expr_or_op(); }

	public SleighParser_SemanticParser.export_return export() throws RecognitionException { return gSemanticParser.export(); }

	public SleighParser_SemanticParser.declaration_return declaration() throws RecognitionException { return gSemanticParser.declaration(); }

	public SleighParser_SemanticParser.expr_comp_return expr_comp() throws RecognitionException { return gSemanticParser.expr_comp(); }

	public SleighParser_SemanticParser.expr_booland_return expr_booland() throws RecognitionException { return gSemanticParser.expr_booland(); }

	public SleighParser_SemanticParser.add_op_return add_op() throws RecognitionException { return gSemanticParser.add_op(); }

	public SleighParser_SemanticParser.expr_apply_return expr_apply() throws RecognitionException { return gSemanticParser.expr_apply(); }

	public SleighParser_SemanticParser.expr_xor_return expr_xor() throws RecognitionException { return gSemanticParser.expr_xor(); }

	public SleighParser_SemanticParser.expr_boolor_return expr_boolor() throws RecognitionException { return gSemanticParser.expr_boolor(); }

	public SleighParser_DisplayParser.display_return display() throws RecognitionException { return gDisplayParser.display(); }

	public SleighParser_SemanticParser.expr_mult_return expr_mult() throws RecognitionException { return gSemanticParser.expr_mult(); }

	public SleighParser_SemanticParser.jumpdest_return jumpdest() throws RecognitionException { return gSemanticParser.jumpdest(); }

	public SleighParser_SemanticParser.varnode_return varnode() throws RecognitionException { return gSemanticParser.varnode(); }

	public SleighParser_SemanticParser.section_def_return section_def() throws RecognitionException { return gSemanticParser.section_def(); }

	public SleighParser_SemanticParser.crossbuild_stmt_return crossbuild_stmt() throws RecognitionException { return gSemanticParser.crossbuild_stmt(); }

	public SleighParser_SemanticParser.unary_op_return unary_op() throws RecognitionException { return gSemanticParser.unary_op(); }

	public SleighParser_SemanticParser.expr_and_op_return expr_and_op() throws RecognitionException { return gSemanticParser.expr_and_op(); }

	public SleighParser_SemanticParser.expr_operands_return expr_operands() throws RecognitionException { return gSemanticParser.expr_operands(); }

	public SleighParser_SemanticParser.expr_eq_return expr_eq() throws RecognitionException { return gSemanticParser.expr_eq(); }

	public SleighParser_SemanticParser.booland_op_return booland_op() throws RecognitionException { return gSemanticParser.booland_op(); }

	public SleighParser_SemanticParser.expr_shift_return expr_shift() throws RecognitionException { return gSemanticParser.expr_shift(); }

	public SleighParser_SemanticParser.statements_return statements() throws RecognitionException { return gSemanticParser.statements(); }

	public final boolean synpred1_SleighParser() {
		state.backtracking++;
		int start = input.mark();
		try {
			synpred1_SleighParser_fragment(); // can never throw exception
		} catch (RecognitionException re) {
			System.err.println("impossible: "+re);
		}
		boolean success = !state.failed;
		input.rewind(start);
		state.backtracking--;
		state.failed=false;
		return success;
	}



	public static final BitSet FOLLOW_endiandef_in_spec78 = new BitSet(new long[]{0xFFFFFF0000008000L,0x00000000000001FFL,0x0000000000000000L,0x0000000002000000L});
	public static final BitSet FOLLOW_definition_in_spec84 = new BitSet(new long[]{0xFFFFFF0000008000L,0x00000000000001FFL,0x0000000000000000L,0x0000000002000000L});
	public static final BitSet FOLLOW_constructorlike_in_spec90 = new BitSet(new long[]{0xFFFFFF0000008000L,0x00000000000001FFL,0x0000000000000000L,0x0000000002000000L});
	public static final BitSet FOLLOW_EOF_in_spec97 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFINE_in_endiandef110 = new BitSet(new long[]{0x0010000000000000L});
	public static final BitSet FOLLOW_KEY_ENDIAN_in_endiandef112 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_endiandef114 = new BitSet(new long[]{0x0100080000000000L});
	public static final BitSet FOLLOW_endian_in_endiandef116 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_SEMI_in_endiandef118 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_BIG_in_endian140 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_LITTLE_in_endian152 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_aligndef_in_definition169 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_tokendef_in_definition174 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_contextdef_in_definition179 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_spacedef_in_definition184 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_varnodedef_in_definition189 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_bitrangedef_in_definition194 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_pcodeopdef_in_definition199 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_valueattach_in_definition204 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_nameattach_in_definition209 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_varattach_in_definition214 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_SEMI_in_definition217 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFINE_in_aligndef231 = new BitSet(new long[]{0x0000020000000000L});
	public static final BitSet FOLLOW_KEY_ALIGNMENT_in_aligndef233 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_aligndef235 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_aligndef237 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFINE_in_tokendef259 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000008L});
	public static final BitSet FOLLOW_KEY_TOKEN_in_tokendef261 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_tokendef263 = new BitSet(new long[]{0x0000000000000000L,0x0000000000008000L});
	public static final BitSet FOLLOW_LPAREN_in_tokendef265 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_tokendef267 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000008000000L});
	public static final BitSet FOLLOW_RPAREN_in_tokendef271 = new BitSet(new long[]{0x0000010000000000L});
	public static final BitSet FOLLOW_fielddefs_in_tokendef273 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_fielddef_in_fielddefs299 = new BitSet(new long[]{0x0000010000000002L});
	public static final BitSet FOLLOW_strict_id_in_fielddef321 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_fielddef325 = new BitSet(new long[]{0x0000000000000000L,0x0000000000008000L});
	public static final BitSet FOLLOW_LPAREN_in_fielddef327 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_fielddef331 = new BitSet(new long[]{0x0000000000010000L});
	public static final BitSet FOLLOW_COMMA_in_fielddef333 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_fielddef337 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000008000000L});
	public static final BitSet FOLLOW_RPAREN_in_fielddef341 = new BitSet(new long[]{0x0082000000000000L,0x0000000000000001L});
	public static final BitSet FOLLOW_fieldmods_in_fielddef343 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_fieldmod_in_fieldmods373 = new BitSet(new long[]{0x0082000000000002L,0x0000000000000001L});
	public static final BitSet FOLLOW_KEY_SIGNED_in_fieldmod410 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_HEX_in_fieldmod427 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEC_in_fieldmod444 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_contextfielddef_in_contextfielddefs464 = new BitSet(new long[]{0xFFFFFF0000000002L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_contextfielddef486 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_contextfielddef490 = new BitSet(new long[]{0x0000000000000000L,0x0000000000008000L});
	public static final BitSet FOLLOW_LPAREN_in_contextfielddef492 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_contextfielddef496 = new BitSet(new long[]{0x0000000000010000L});
	public static final BitSet FOLLOW_COMMA_in_contextfielddef498 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_contextfielddef502 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000008000000L});
	public static final BitSet FOLLOW_RPAREN_in_contextfielddef506 = new BitSet(new long[]{0x1082000000000000L,0x0000000000000001L});
	public static final BitSet FOLLOW_contextfieldmods_in_contextfielddef508 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_contextfieldmod_in_contextfieldmods543 = new BitSet(new long[]{0x1082000000000002L,0x0000000000000001L});
	public static final BitSet FOLLOW_KEY_SIGNED_in_contextfieldmod588 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_NOFLOW_in_contextfieldmod605 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_HEX_in_contextfieldmod622 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEC_in_contextfieldmod639 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFINE_in_contextdef660 = new BitSet(new long[]{0x0000800000000000L});
	public static final BitSet FOLLOW_KEY_CONTEXT_in_contextdef664 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_contextdef666 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_contextfielddefs_in_contextdef668 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFINE_in_spacedef693 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000004L});
	public static final BitSet FOLLOW_KEY_SPACE_in_spacedef695 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_spacedef697 = new BitSet(new long[]{0x0004000000000000L,0x0000000000000112L});
	public static final BitSet FOLLOW_spacemods_in_spacedef699 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_spacemod_in_spacemods723 = new BitSet(new long[]{0x0004000000000002L,0x0000000000000112L});
	public static final BitSet FOLLOW_typemod_in_spacemod745 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_sizemod_in_spacemod750 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_wordsizemod_in_spacemod755 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFAULT_in_spacemod762 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_TYPE_in_typemod780 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_typemod782 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_type_in_typemod784 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_type804 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_SIZE_in_sizemod817 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_sizemod819 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_sizemod821 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_WORDSIZE_in_wordsizemod843 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_wordsizemod845 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_wordsizemod847 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFINE_in_varnodedef869 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_varnodedef871 = new BitSet(new long[]{0x2000000000000000L});
	public static final BitSet FOLLOW_KEY_OFFSET_in_varnodedef873 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_varnodedef875 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_varnodedef879 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_SIZE_in_varnodedef881 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_varnodedef885 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_varnodedef889 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000005FFL,0x0000000000000000L,0x0000040000000000L});
	public static final BitSet FOLLOW_identifierlist_in_varnodedef891 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFINE_in_bitrangedef924 = new BitSet(new long[]{0x0000100000000000L});
	public static final BitSet FOLLOW_KEY_BITRANGE_in_bitrangedef926 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_bitranges_in_bitrangedef928 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_bitrange_in_bitranges948 = new BitSet(new long[]{0xFFFFFF0000000002L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_bitrange962 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_bitrange966 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_bitrange970 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_LBRACKET_in_bitrange972 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_bitrange976 = new BitSet(new long[]{0x0000000000010000L});
	public static final BitSet FOLLOW_COMMA_in_bitrange978 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_bitrange982 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000400000L});
	public static final BitSet FOLLOW_RBRACKET_in_bitrange984 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFINE_in_pcodeopdef1016 = new BitSet(new long[]{0x4000000000000000L});
	public static final BitSet FOLLOW_KEY_PCODEOP_in_pcodeopdef1020 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000005FFL,0x0000000000000000L,0x0000040000000000L});
	public static final BitSet FOLLOW_identifierlist_in_pcodeopdef1022 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_ATTACH_in_valueattach1045 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000040L});
	public static final BitSet FOLLOW_KEY_VALUES_in_valueattach1049 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000005FFL,0x0000000000000000L,0x0000040000000000L});
	public static final BitSet FOLLOW_identifierlist_in_valueattach1051 = new BitSet(new long[]{0x0000008000040400L,0x0000000000010400L});
	public static final BitSet FOLLOW_intblist_in_valueattach1054 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_ATTACH_in_nameattach1079 = new BitSet(new long[]{0x0800000000000000L});
	public static final BitSet FOLLOW_KEY_NAMES_in_nameattach1083 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000005FFL,0x0000000000000000L,0x0000040000000000L});
	public static final BitSet FOLLOW_identifierlist_in_nameattach1087 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000005FFL,0x0000000000000000L,0x0000040000100000L});
	public static final BitSet FOLLOW_stringoridentlist_in_nameattach1092 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_ATTACH_in_varattach1119 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000080L});
	public static final BitSet FOLLOW_KEY_VARIABLES_in_varattach1123 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000005FFL,0x0000000000000000L,0x0000040000000000L});
	public static final BitSet FOLLOW_identifierlist_in_varattach1127 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000005FFL,0x0000000000000000L,0x0000040000000000L});
	public static final BitSet FOLLOW_identifierlist_in_varattach1132 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LBRACKET_in_identifierlist1158 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL,0x0000000000000000L,0x0000040000000000L});
	public static final BitSet FOLLOW_id_or_wild_in_identifierlist1160 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL,0x0000000000000000L,0x0000040000400000L});
	public static final BitSet FOLLOW_RBRACKET_in_identifierlist1163 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_id_or_wild_in_identifierlist1178 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LBRACKET_in_stringoridentlist1199 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL,0x0000000000000000L,0x0000040000100000L});
	public static final BitSet FOLLOW_stringorident_in_stringoridentlist1201 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL,0x0000000000000000L,0x0000040000500000L});
	public static final BitSet FOLLOW_RBRACKET_in_stringoridentlist1204 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_stringorident_in_stringoridentlist1219 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_id_or_wild_in_stringorident1239 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_qstring_in_stringorident1244 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LBRACKET_in_intblist1256 = new BitSet(new long[]{0x0000008000040400L,0x0000000000010000L,0x0000000000000000L,0x0000040000000000L});
	public static final BitSet FOLLOW_intbpart_in_intblist1258 = new BitSet(new long[]{0x0000008000040400L,0x0000000000010000L,0x0000000000000000L,0x0000040000400000L});
	public static final BitSet FOLLOW_RBRACKET_in_intblist1261 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_neginteger_in_intblist1276 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_neginteger_in_intbpart1296 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_UNDERSCORE_in_intbpart1303 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_integer_in_neginteger1319 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_MINUS_in_neginteger1326 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_integer_in_neginteger1328 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_macrodef_in_constructorlike1348 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_withblock_in_constructorlike1353 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_constructor_in_constructorlike1358 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_MACRO_in_macrodef1371 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_macrodef1373 = new BitSet(new long[]{0x0000000000000000L,0x0000000000008000L});
	public static final BitSet FOLLOW_LPAREN_in_macrodef1377 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL,0x0000000000000000L,0x0000000008000000L});
	public static final BitSet FOLLOW_arguments_in_macrodef1379 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000008000000L});
	public static final BitSet FOLLOW_RPAREN_in_macrodef1382 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000200L});
	public static final BitSet FOLLOW_semanticbody_in_macrodef1384 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_oplist_in_arguments1409 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_oplist1439 = new BitSet(new long[]{0x0000000000010002L});
	public static final BitSet FOLLOW_COMMA_in_oplist1442 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_oplist1445 = new BitSet(new long[]{0x0000000000010002L});
	public static final BitSet FOLLOW_RES_WITH_in_withblock1460 = new BitSet(new long[]{0xFFFFFF0000008000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_id_or_nil_in_withblock1462 = new BitSet(new long[]{0x0000000000008000L});
	public static final BitSet FOLLOW_COLON_in_withblock1464 = new BitSet(new long[]{0xFFFFFF0000200000L,0x00000000000087FFL});
	public static final BitSet FOLLOW_bitpat_or_nil_in_withblock1466 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000600L});
	public static final BitSet FOLLOW_contextblock_in_withblock1468 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000200L});
	public static final BitSet FOLLOW_LBRACE_in_withblock1470 = new BitSet(new long[]{0xFFFFFF0000008000L,0x00000000000001FFL,0x0000000000000000L,0x0000000002200000L});
	public static final BitSet FOLLOW_constructorlikelist_in_withblock1472 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000200000L});
	public static final BitSet FOLLOW_RBRACE_in_withblock1474 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_id_or_nil1503 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_bitpattern_in_bitpat_or_nil1523 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_definition_in_def_or_conslike1543 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_constructorlike_in_def_or_conslike1548 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_def_or_conslike_in_constructorlikelist1559 = new BitSet(new long[]{0xFFFFFF0000008002L,0x00000000000001FFL,0x0000000000000000L,0x0000000002000000L});
	public static final BitSet FOLLOW_ctorstart_in_constructor1581 = new BitSet(new long[]{0xFFFFFF0000200000L,0x00000000000081FFL});
	public static final BitSet FOLLOW_bitpattern_in_constructor1583 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000620L});
	public static final BitSet FOLLOW_contextblock_in_constructor1585 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000220L});
	public static final BitSet FOLLOW_ctorsemantic_in_constructor1587 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_semanticbody_in_ctorsemantic1612 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_UNIMPL_in_ctorsemantic1627 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pequation_in_bitpattern1648 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_ctorstart1667 = new BitSet(new long[]{0x0000000000008000L});
	public static final BitSet FOLLOW_display_in_ctorstart1669 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_display_in_ctorstart1684 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LBRACKET_in_contextblock1705 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL,0x0000000000000000L,0x0000000000400000L});
	public static final BitSet FOLLOW_ctxstmts_in_contextblock1707 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000400000L});
	public static final BitSet FOLLOW_RBRACKET_in_contextblock1709 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_ctxstmt_in_ctxstmts1738 = new BitSet(new long[]{0xFFFFFF0000000002L,0x00000000000001FFL});
	public static final BitSet FOLLOW_ctxassign_in_ctxstmt1750 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_SEMI_in_ctxstmt1752 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pfuncall_in_ctxstmt1758 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_SEMI_in_ctxstmt1760 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_ctxlval_in_ctxassign1772 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_ctxassign1776 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_pexpression_in_ctxassign1778 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_ctxlval1800 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_apply_in_pfuncall1811 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pequation_or_in_pequation1822 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pequation_seq_in_pequation_or1833 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000000000010000L});
	public static final BitSet FOLLOW_pequation_or_op_in_pequation_or1837 = new BitSet(new long[]{0xFFFFFF0000200000L,0x00000000000081FFL});
	public static final BitSet FOLLOW_pequation_seq_in_pequation_or1840 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000000000010000L});
	public static final BitSet FOLLOW_PIPE_in_pequation_or_op1856 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pequation_and_in_pequation_seq1874 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_pequation_seq_op_in_pequation_seq1878 = new BitSet(new long[]{0xFFFFFF0000200000L,0x00000000000081FFL});
	public static final BitSet FOLLOW_pequation_and_in_pequation_seq1881 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_SEMI_in_pequation_seq_op1897 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pequation_ellipsis_in_pequation_and1915 = new BitSet(new long[]{0x0000000000000042L});
	public static final BitSet FOLLOW_pequation_and_op_in_pequation_and1919 = new BitSet(new long[]{0xFFFFFF0000200000L,0x00000000000081FFL});
	public static final BitSet FOLLOW_pequation_ellipsis_in_pequation_and1922 = new BitSet(new long[]{0x0000000000000042L});
	public static final BitSet FOLLOW_AMPERSAND_in_pequation_and_op1938 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_ELLIPSIS_in_pequation_ellipsis1958 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000081FFL});
	public static final BitSet FOLLOW_pequation_ellipsis_right_in_pequation_ellipsis1960 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pequation_ellipsis_right_in_pequation_ellipsis1974 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pequation_atomic_in_pequation_ellipsis_right1992 = new BitSet(new long[]{0x0000000000200000L});
	public static final BitSet FOLLOW_ELLIPSIS_in_pequation_ellipsis_right1996 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pequation_atomic_in_pequation_ellipsis_right2010 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_constraint_in_pequation_atomic2022 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LPAREN_in_pequation_atomic2029 = new BitSet(new long[]{0xFFFFFF0000200000L,0x00000000000081FFL});
	public static final BitSet FOLLOW_pequation_in_pequation_atomic2031 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000008000000L});
	public static final BitSet FOLLOW_RPAREN_in_pequation_atomic2033 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_constraint2053 = new BitSet(new long[]{0x0000003000000082L,0x0000000000023000L});
	public static final BitSet FOLLOW_constraint_op_in_constraint2056 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_pexpression2_in_constraint2059 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_ASSIGN_in_constraint_op2074 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_NOTEQUAL_in_constraint_op2088 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LESS_in_constraint_op2102 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LESSEQUAL_in_constraint_op2116 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_GREAT_in_constraint_op2130 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_GREATEQUAL_in_constraint_op2144 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_or_in_pexpression2162 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_xor_in_pexpression_or2173 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000001000010000L});
	public static final BitSet FOLLOW_pexpression_or_op_in_pexpression_or2176 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_pexpression_xor_in_pexpression_or2179 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000001000010000L});
	public static final BitSet FOLLOW_PIPE_in_pexpression_or_op2194 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SPEC_OR_in_pexpression_or_op2208 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_and_in_pexpression_xor2226 = new BitSet(new long[]{0x0000000000004002L,0x0000000000000000L,0x0000000000000000L,0x0000002000000000L});
	public static final BitSet FOLLOW_pexpression_xor_op_in_pexpression_xor2229 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_pexpression_and_in_pexpression_xor2232 = new BitSet(new long[]{0x0000000000004002L,0x0000000000000000L,0x0000000000000000L,0x0000002000000000L});
	public static final BitSet FOLLOW_CARET_in_pexpression_xor_op2247 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SPEC_XOR_in_pexpression_xor_op2261 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_shift_in_pexpression_and2279 = new BitSet(new long[]{0x0000000000000042L,0x0000000000000000L,0x0000000000000000L,0x0000000800000000L});
	public static final BitSet FOLLOW_pexpression_and_op_in_pexpression_and2282 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_pexpression_shift_in_pexpression_and2285 = new BitSet(new long[]{0x0000000000000042L,0x0000000000000000L,0x0000000000000000L,0x0000000800000000L});
	public static final BitSet FOLLOW_AMPERSAND_in_pexpression_and_op2300 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SPEC_AND_in_pexpression_and_op2314 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_add_in_pexpression_shift2332 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000800L,0x0000000000000000L,0x0000000004000000L});
	public static final BitSet FOLLOW_pexpression_shift_op_in_pexpression_shift2335 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_pexpression_add_in_pexpression_shift2338 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000800L,0x0000000000000000L,0x0000000004000000L});
	public static final BitSet FOLLOW_LEFT_in_pexpression_shift_op2353 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_RIGHT_in_pexpression_shift_op2367 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_mult_in_pexpression_add2385 = new BitSet(new long[]{0x0000000000000002L,0x0000000000010000L,0x0000000000000000L,0x0000000000020000L});
	public static final BitSet FOLLOW_pexpression_add_op_in_pexpression_add2388 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_pexpression_mult_in_pexpression_add2391 = new BitSet(new long[]{0x0000000000000002L,0x0000000000010000L,0x0000000000000000L,0x0000000000020000L});
	public static final BitSet FOLLOW_PLUS_in_pexpression_add_op2406 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_MINUS_in_pexpression_add_op2420 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_unary_in_pexpression_mult2438 = new BitSet(new long[]{0x0000000000000102L,0x0000000000000000L,0x0000000000000000L,0x0000000100000000L});
	public static final BitSet FOLLOW_pexpression_mult_op_in_pexpression_mult2441 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_pexpression_unary_in_pexpression_mult2444 = new BitSet(new long[]{0x0000000000000102L,0x0000000000000000L,0x0000000000000000L,0x0000000100000000L});
	public static final BitSet FOLLOW_ASTERISK_in_pexpression_mult_op2459 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SLASH_in_pexpression_mult_op2473 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_unary_op_in_pexpression_unary2491 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000081FFL});
	public static final BitSet FOLLOW_pexpression_term_in_pexpression_unary2494 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_func_in_pexpression_unary2499 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_MINUS_in_pexpression_unary_op2512 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_TILDE_in_pexpression_unary_op2526 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_apply_in_pexpression_func2544 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression_term_in_pexpression_func2549 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_pexpression_apply2560 = new BitSet(new long[]{0x0000000000000000L,0x0000000000008000L});
	public static final BitSet FOLLOW_pexpression_operands_in_pexpression_apply2562 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LPAREN_in_pexpression_operands2584 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000010008000000L});
	public static final BitSet FOLLOW_pexpression_in_pexpression_operands2588 = new BitSet(new long[]{0x0000000000010000L,0x0000000000000000L,0x0000000000000000L,0x0000000008000000L});
	public static final BitSet FOLLOW_COMMA_in_pexpression_operands2591 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_pexpression_in_pexpression_operands2594 = new BitSet(new long[]{0x0000000000010000L,0x0000000000000000L,0x0000000000000000L,0x0000000008000000L});
	public static final BitSet FOLLOW_RPAREN_in_pexpression_operands2601 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_pexpression_term2613 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_integer_in_pexpression_term2618 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LPAREN_in_pexpression_term2625 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_pexpression_in_pexpression_term2627 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000008000000L});
	public static final BitSet FOLLOW_RPAREN_in_pexpression_term2629 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression2_or_in_pexpression22649 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression2_xor_in_pexpression2_or2660 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000001000000000L});
	public static final BitSet FOLLOW_pexpression2_or_op_in_pexpression2_or2663 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_pexpression2_xor_in_pexpression2_or2666 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000001000000000L});
	public static final BitSet FOLLOW_SPEC_OR_in_pexpression2_or_op2681 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression2_and_in_pexpression2_xor2699 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000002000000000L});
	public static final BitSet FOLLOW_pexpression2_xor_op_in_pexpression2_xor2702 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_pexpression2_and_in_pexpression2_xor2705 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000002000000000L});
	public static final BitSet FOLLOW_SPEC_XOR_in_pexpression2_xor_op2720 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression2_shift_in_pexpression2_and2738 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000000800000000L});
	public static final BitSet FOLLOW_pexpression2_and_op_in_pexpression2_and2741 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_pexpression2_shift_in_pexpression2_and2744 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000000800000000L});
	public static final BitSet FOLLOW_SPEC_AND_in_pexpression2_and_op2759 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression2_add_in_pexpression2_shift2777 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000800L,0x0000000000000000L,0x0000000004000000L});
	public static final BitSet FOLLOW_pexpression2_shift_op_in_pexpression2_shift2780 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_pexpression2_add_in_pexpression2_shift2783 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000800L,0x0000000000000000L,0x0000000004000000L});
	public static final BitSet FOLLOW_LEFT_in_pexpression2_shift_op2798 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_RIGHT_in_pexpression2_shift_op2812 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression2_mult_in_pexpression2_add2830 = new BitSet(new long[]{0x0000000000000002L,0x0000000000010000L,0x0000000000000000L,0x0000000000020000L});
	public static final BitSet FOLLOW_pexpression2_add_op_in_pexpression2_add2833 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_pexpression2_mult_in_pexpression2_add2836 = new BitSet(new long[]{0x0000000000000002L,0x0000000000010000L,0x0000000000000000L,0x0000000000020000L});
	public static final BitSet FOLLOW_PLUS_in_pexpression2_add_op2851 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_MINUS_in_pexpression2_add_op2865 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression2_unary_in_pexpression2_mult2883 = new BitSet(new long[]{0x0000000000000102L,0x0000000000000000L,0x0000000000000000L,0x0000000100000000L});
	public static final BitSet FOLLOW_pexpression2_mult_op_in_pexpression2_mult2886 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_pexpression2_unary_in_pexpression2_mult2889 = new BitSet(new long[]{0x0000000000000102L,0x0000000000000000L,0x0000000000000000L,0x0000000100000000L});
	public static final BitSet FOLLOW_ASTERISK_in_pexpression2_mult_op2904 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SLASH_in_pexpression2_mult_op2918 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression2_unary_op_in_pexpression2_unary2936 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000081FFL});
	public static final BitSet FOLLOW_pexpression2_term_in_pexpression2_unary2939 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression2_func_in_pexpression2_unary2944 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_MINUS_in_pexpression2_unary_op2957 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_TILDE_in_pexpression2_unary_op2971 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression2_apply_in_pexpression2_func2989 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pexpression2_term_in_pexpression2_func2994 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_pexpression2_apply3005 = new BitSet(new long[]{0x0000000000000000L,0x0000000000008000L});
	public static final BitSet FOLLOW_pexpression2_operands_in_pexpression2_apply3007 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LPAREN_in_pexpression2_operands3029 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000010008000000L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression2_operands3033 = new BitSet(new long[]{0x0000000000010000L,0x0000000000000000L,0x0000000000000000L,0x0000000008000000L});
	public static final BitSet FOLLOW_COMMA_in_pexpression2_operands3036 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression2_operands3039 = new BitSet(new long[]{0x0000000000010000L,0x0000000000000000L,0x0000000000000000L,0x0000000008000000L});
	public static final BitSet FOLLOW_RPAREN_in_pexpression2_operands3046 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_pexpression2_term3058 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_integer_in_pexpression2_term3063 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LPAREN_in_pexpression2_term3070 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression2_term3072 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000008000000L});
	public static final BitSet FOLLOW_RPAREN_in_pexpression2_term3074 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_QSTRING_in_qstring3096 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_id_or_wild3116 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_wildcard_in_id_or_wild3121 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_UNDERSCORE_in_wildcard3134 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_strict_id_in_identifier3151 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_key_as_id_in_identifier3156 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_ALIGNMENT_in_key_as_id3169 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_ATTACH_in_key_as_id3185 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_BIG_in_key_as_id3202 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_BITRANGE_in_key_as_id3220 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_BUILD_in_key_as_id3237 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_CALL_in_key_as_id3254 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_CONTEXT_in_key_as_id3273 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_CROSSBUILD_in_key_as_id3290 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEC_in_key_as_id3306 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFAULT_in_key_as_id3325 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFINE_in_key_as_id3342 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_ENDIAN_in_key_as_id3359 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_EXPORT_in_key_as_id3376 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_GOTO_in_key_as_id3393 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_HEX_in_key_as_id3411 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_LITTLE_in_key_as_id3429 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_LOCAL_in_key_as_id3446 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_MACRO_in_key_as_id3463 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_NAMES_in_key_as_id3480 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_NOFLOW_in_key_as_id3497 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_OFFSET_in_key_as_id3514 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_PCODEOP_in_key_as_id3531 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_RETURN_in_key_as_id3548 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_SIGNED_in_key_as_id3565 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_SIZE_in_key_as_id3582 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_SPACE_in_key_as_id3600 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_TOKEN_in_key_as_id3617 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_TYPE_in_key_as_id3634 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_UNIMPL_in_key_as_id3652 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_VALUES_in_key_as_id3669 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_VARIABLES_in_key_as_id3686 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_WORDSIZE_in_key_as_id3702 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_IDENTIFIER_in_strict_id3725 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_HEX_INT_in_integer3748 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_DEC_INT_in_integer3764 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_BIN_INT_in_integer3780 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pequation_atomic_in_synpred1_SleighParser1986 = new BitSet(new long[]{0x0000000000200000L});
	public static final BitSet FOLLOW_ELLIPSIS_in_synpred1_SleighParser1988 = new BitSet(new long[]{0x0000000000000002L});
}
