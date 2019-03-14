package ghidra.sleigh.grammar;
// $ANTLR 3.5.2 DisplayParser.g 2019-02-28 12:48:47

import org.antlr.runtime.*;
import java.util.Stack;
import java.util.List;
import java.util.ArrayList;

import org.antlr.runtime.tree.*;


@SuppressWarnings("all")
public class SleighParser_DisplayParser extends AbstractSleighParser {
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
	public AbstractSleighParser[] getDelegates() {
		return new AbstractSleighParser[] {};
	}

	// delegators
	public SleighParser gSleighParser;
	public SleighParser gParent;


	public SleighParser_DisplayParser(TokenStream input, SleighParser gSleighParser) {
		this(input, new RecognizerSharedState(), gSleighParser);
	}
	public SleighParser_DisplayParser(TokenStream input, RecognizerSharedState state, SleighParser gSleighParser) {
		super(input, state);
		this.gSleighParser = gSleighParser;
		gParent = gSleighParser;
	}

	protected TreeAdaptor adaptor = new CommonTreeAdaptor();

	public void setTreeAdaptor(TreeAdaptor adaptor) {
		this.adaptor = adaptor;
	}
	public TreeAdaptor getTreeAdaptor() {
		return adaptor;
	}
	@Override public String[] getTokenNames() { return SleighParser.tokenNames; }
	@Override public String getGrammarFileName() { return "DisplayParser.g"; }


	public static class display_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "display"
	// DisplayParser.g:14:1: display : COLON pieces RES_IS -> ^( OP_DISPLAY pieces ) ;
	public final SleighParser_DisplayParser.display_return display() throws RecognitionException {
		SleighParser_DisplayParser.display_return retval = new SleighParser_DisplayParser.display_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token COLON1=null;
		Token RES_IS3=null;
		ParserRuleReturnScope pieces2 =null;

		CommonTree COLON1_tree=null;
		CommonTree RES_IS3_tree=null;
		RewriteRuleTokenStream stream_RES_IS=new RewriteRuleTokenStream(adaptor,"token RES_IS");
		RewriteRuleTokenStream stream_COLON=new RewriteRuleTokenStream(adaptor,"token COLON");
		RewriteRuleSubtreeStream stream_pieces=new RewriteRuleSubtreeStream(adaptor,"rule pieces");

		try {
			// DisplayParser.g:15:2: ( COLON pieces RES_IS -> ^( OP_DISPLAY pieces ) )
			// DisplayParser.g:15:4: COLON pieces RES_IS
			{
			 lexer.pushMode(DISPLAY); 
			COLON1=(Token)match(input,COLON,FOLLOW_COLON_in_display32);  
			stream_COLON.add(COLON1);

			pushFollow(FOLLOW_pieces_in_display34);
			pieces2=pieces();
			state._fsp--;

			stream_pieces.add(pieces2.getTree());
			RES_IS3=(Token)match(input,RES_IS,FOLLOW_RES_IS_in_display36);  
			stream_RES_IS.add(RES_IS3);

			 lexer.popMode(); 
			// AST REWRITE
			// elements: pieces
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 15:74: -> ^( OP_DISPLAY pieces )
			{
				// DisplayParser.g:15:77: ^( OP_DISPLAY pieces )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_DISPLAY, "OP_DISPLAY"), root_1);
				adaptor.addChild(root_1, stream_pieces.nextTree());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;

			}

			retval.stop = input.LT(-1);

			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);

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
	// $ANTLR end "display"


	public static class pieces_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "pieces"
	// DisplayParser.g:18:1: pieces : ( printpiece )* ;
	public final SleighParser_DisplayParser.pieces_return pieces() throws RecognitionException {
		SleighParser_DisplayParser.pieces_return retval = new SleighParser_DisplayParser.pieces_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope printpiece4 =null;


		try {
			// DisplayParser.g:19:2: ( ( printpiece )* )
			// DisplayParser.g:19:4: ( printpiece )*
			{
			root_0 = (CommonTree)adaptor.nil();


			// DisplayParser.g:19:4: ( printpiece )*
			loop1:
			while (true) {
				int alt1=2;
				int LA1_0 = input.LA(1);
				if ( ((LA1_0 >= AMPERSAND && LA1_0 <= ASTERISK)||(LA1_0 >= BIN_INT && LA1_0 <= COMMA)||LA1_0==DEC_INT||(LA1_0 >= DISPCHAR && LA1_0 <= ELLIPSIS)||LA1_0==EQUAL||LA1_0==EXCLAIM||(LA1_0 >= GREAT && LA1_0 <= GREATEQUAL)||(LA1_0 >= HEX_INT && LA1_0 <= NOTEQUAL)||(LA1_0 >= PERCENT && LA1_0 <= PLUS)||(LA1_0 >= QSTRING && LA1_0 <= RBRACKET)||(LA1_0 >= RIGHT && LA1_0 <= RPAREN)||LA1_0==SEMI||LA1_0==SLASH||(LA1_0 >= SPEC_AND && LA1_0 <= SPEC_XOR)||LA1_0==TILDE||LA1_0==WS) ) {
					alt1=1;
				}

				switch (alt1) {
				case 1 :
					// DisplayParser.g:19:4: printpiece
					{
					pushFollow(FOLLOW_printpiece_in_pieces57);
					printpiece4=printpiece();
					state._fsp--;

					adaptor.addChild(root_0, printpiece4.getTree());

					}
					break;

				default :
					break loop1;
				}
			}

			}

			retval.stop = input.LT(-1);

			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);

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
	// $ANTLR end "pieces"


	public static class printpiece_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "printpiece"
	// DisplayParser.g:22:1: printpiece : ( identifier | whitespace | concatenate | qstring | special );
	public final SleighParser_DisplayParser.printpiece_return printpiece() throws RecognitionException {
		SleighParser_DisplayParser.printpiece_return retval = new SleighParser_DisplayParser.printpiece_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope identifier5 =null;
		ParserRuleReturnScope whitespace6 =null;
		ParserRuleReturnScope concatenate7 =null;
		ParserRuleReturnScope qstring8 =null;
		ParserRuleReturnScope special9 =null;


		try {
			// DisplayParser.g:23:2: ( identifier | whitespace | concatenate | qstring | special )
			int alt2=5;
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
				alt2=1;
				}
				break;
			case WS:
				{
				alt2=2;
				}
				break;
			case CARET:
				{
				alt2=3;
				}
				break;
			case QSTRING:
				{
				alt2=4;
				}
				break;
			case AMPERSAND:
			case ASSIGN:
			case ASTERISK:
			case BIN_INT:
			case BOOL_AND:
			case BOOL_OR:
			case BOOL_XOR:
			case COLON:
			case COMMA:
			case DEC_INT:
			case DISPCHAR:
			case ELLIPSIS:
			case EQUAL:
			case EXCLAIM:
			case GREAT:
			case GREATEQUAL:
			case HEX_INT:
			case LBRACE:
			case LBRACKET:
			case LEFT:
			case LESS:
			case LESSEQUAL:
			case LINECOMMENT:
			case LPAREN:
			case MINUS:
			case NOTEQUAL:
			case PERCENT:
			case PIPE:
			case PLUS:
			case RBRACE:
			case RBRACKET:
			case RIGHT:
			case RPAREN:
			case SEMI:
			case SLASH:
			case SPEC_AND:
			case SPEC_OR:
			case SPEC_XOR:
			case TILDE:
				{
				alt2=5;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 2, 0, input);
				throw nvae;
			}
			switch (alt2) {
				case 1 :
					// DisplayParser.g:23:4: identifier
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_identifier_in_printpiece69);
					identifier5=gSleighParser.identifier();
					state._fsp--;

					adaptor.addChild(root_0, identifier5.getTree());

					}
					break;
				case 2 :
					// DisplayParser.g:24:4: whitespace
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_whitespace_in_printpiece74);
					whitespace6=whitespace();
					state._fsp--;

					adaptor.addChild(root_0, whitespace6.getTree());

					}
					break;
				case 3 :
					// DisplayParser.g:25:4: concatenate
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_concatenate_in_printpiece79);
					concatenate7=concatenate();
					state._fsp--;

					adaptor.addChild(root_0, concatenate7.getTree());

					}
					break;
				case 4 :
					// DisplayParser.g:26:4: qstring
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_qstring_in_printpiece84);
					qstring8=gSleighParser.qstring();
					state._fsp--;

					adaptor.addChild(root_0, qstring8.getTree());

					}
					break;
				case 5 :
					// DisplayParser.g:27:4: special
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_special_in_printpiece89);
					special9=special();
					state._fsp--;

					adaptor.addChild(root_0, special9.getTree());

					}
					break;

			}
			retval.stop = input.LT(-1);

			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);

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
	// $ANTLR end "printpiece"


	public static class whitespace_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "whitespace"
	// DisplayParser.g:30:1: whitespace : lc= WS -> ^( OP_WHITESPACE[$lc, \"WS\"] WS ) ;
	public final SleighParser_DisplayParser.whitespace_return whitespace() throws RecognitionException {
		SleighParser_DisplayParser.whitespace_return retval = new SleighParser_DisplayParser.whitespace_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_WS=new RewriteRuleTokenStream(adaptor,"token WS");

		try {
			// DisplayParser.g:31:2: (lc= WS -> ^( OP_WHITESPACE[$lc, \"WS\"] WS ) )
			// DisplayParser.g:31:4: lc= WS
			{
			lc=(Token)match(input,WS,FOLLOW_WS_in_whitespace102);  
			stream_WS.add(lc);

			// AST REWRITE
			// elements: WS
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 31:10: -> ^( OP_WHITESPACE[$lc, \"WS\"] WS )
			{
				// DisplayParser.g:31:13: ^( OP_WHITESPACE[$lc, \"WS\"] WS )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_WHITESPACE, lc, "WS"), root_1);
				adaptor.addChild(root_1, stream_WS.nextNode());
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;

			}

			retval.stop = input.LT(-1);

			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);

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
	// $ANTLR end "whitespace"


	public static class concatenate_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "concatenate"
	// DisplayParser.g:36:1: concatenate : lc= CARET -> ^( OP_CONCATENATE[$lc] ) ;
	public final SleighParser_DisplayParser.concatenate_return concatenate() throws RecognitionException {
		SleighParser_DisplayParser.concatenate_return retval = new SleighParser_DisplayParser.concatenate_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_CARET=new RewriteRuleTokenStream(adaptor,"token CARET");

		try {
			// DisplayParser.g:37:2: (lc= CARET -> ^( OP_CONCATENATE[$lc] ) )
			// DisplayParser.g:37:4: lc= CARET
			{
			lc=(Token)match(input,CARET,FOLLOW_CARET_in_concatenate126);  
			stream_CARET.add(lc);

			// AST REWRITE
			// elements: 
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 37:13: -> ^( OP_CONCATENATE[$lc] )
			{
				// DisplayParser.g:37:16: ^( OP_CONCATENATE[$lc] )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_CONCATENATE, lc), root_1);
				adaptor.addChild(root_0, root_1);
				}

			}


			retval.tree = root_0;

			}

			retval.stop = input.LT(-1);

			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);

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
	// $ANTLR end "concatenate"


	public static class special_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "special"
	// DisplayParser.g:44:1: special : (lc= DISPCHAR -> ^( OP_STRING[$lc, \"DISPCHAR\"] DISPCHAR ) |lc= LINECOMMENT -> ^( OP_STRING[$lc, \"LINECOMMENT\"] LINECOMMENT ) |lc= LBRACE -> ^( OP_STRING[$lc, \"LBRACE\"] LBRACE ) |lc= RBRACE -> ^( OP_STRING[$lc, \"RBRACE\"] RBRACE ) |lc= LBRACKET -> ^( OP_STRING[$lc, \"LBRACKET\"] LBRACKET ) |lc= RBRACKET -> ^( OP_STRING[$lc, \"RBRACKET\"] RBRACKET ) |lc= LPAREN -> ^( OP_STRING[$lc, \"LPAREN\"] LPAREN ) |lc= RPAREN -> ^( OP_STRING[$lc, \"RPAREN\"] RPAREN ) |lc= ELLIPSIS -> ^( OP_STRING[$lc, \"ELLIPSIS\"] ELLIPSIS ) |lc= EQUAL -> ^( OP_STRING[$lc, \"EQUAL\"] EQUAL ) |lc= NOTEQUAL -> ^( OP_STRING[$lc, \"NOTEQUAL\"] NOTEQUAL ) |lc= LESS -> ^( OP_STRING[$lc, \"LESS\"] LESS ) |lc= GREAT -> ^( OP_STRING[$lc, \"GREAT\"] GREAT ) |lc= LESSEQUAL -> ^( OP_STRING[$lc, \"LESSEQUAL\"] LESSEQUAL ) |lc= GREATEQUAL -> ^( OP_STRING[$lc, \"GREATEQUAL\"] GREATEQUAL ) |lc= ASSIGN -> ^( OP_STRING[$lc, \"ASSIGN\"] ASSIGN ) |lc= COLON -> ^( OP_STRING[$lc, \"COLON\"] COLON ) |lc= COMMA -> ^( OP_STRING[$lc, \"COMMA\"] COMMA ) |lc= ASTERISK -> ^( OP_STRING[$lc, \"ASTERISK\"] ASTERISK ) |lc= BOOL_OR -> ^( OP_STRING[$lc, \"BOOL_OR\"] BOOL_OR ) |lc= BOOL_XOR -> ^( OP_STRING[$lc, \"BOOL_XOR\"] BOOL_XOR ) |lc= BOOL_AND -> ^( OP_STRING[$lc, \"BOOL_AND\"] BOOL_AND ) |lc= PIPE -> ^( OP_STRING[$lc, \"PIPE\"] PIPE ) |lc= AMPERSAND -> ^( OP_STRING[$lc, \"AMPERSAND\"] AMPERSAND ) |lc= LEFT -> ^( OP_STRING[$lc, \"LEFT\"] LEFT ) |lc= RIGHT -> ^( OP_STRING[$lc, \"RIGHT\"] RIGHT ) |lc= PLUS -> ^( OP_STRING[$lc, \"PLUS\"] PLUS ) |lc= MINUS -> ^( OP_STRING[$lc, \"MINUS\"] MINUS ) |lc= SLASH -> ^( OP_STRING[$lc, \"SLASH\"] SLASH ) |lc= PERCENT -> ^( OP_STRING[$lc, \"PERCENT\"] PERCENT ) |lc= EXCLAIM -> ^( OP_STRING[$lc, \"EXCLAIM\"] EXCLAIM ) |lc= TILDE -> ^( OP_STRING[$lc, \"TILDE\"] TILDE ) |lc= SEMI -> ^( OP_STRING[$lc, \"SEMI\"] SEMI ) |lc= SPEC_OR -> ^( OP_STRING[$lc, \"SPEC_OR\"] SPEC_OR ) |lc= SPEC_AND -> ^( OP_STRING[$lc, \"SPEC_AND\"] SPEC_AND ) |lc= SPEC_XOR -> ^( OP_STRING[$lc, \"SPEC_XOR\"] SPEC_XOR ) |lc= DEC_INT -> ^( OP_STRING[$lc, \"DEC_INT\"] DEC_INT ) |lc= HEX_INT -> ^( OP_STRING[$lc, \"HEX_INT\"] HEX_INT ) |lc= BIN_INT -> ^( OP_STRING[$lc, \"BIN_INT\"] BIN_INT ) );
	public final SleighParser_DisplayParser.special_return special() throws RecognitionException {
		SleighParser_DisplayParser.special_return retval = new SleighParser_DisplayParser.special_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_EXCLAIM=new RewriteRuleTokenStream(adaptor,"token EXCLAIM");
		RewriteRuleTokenStream stream_SEMI=new RewriteRuleTokenStream(adaptor,"token SEMI");
		RewriteRuleTokenStream stream_HEX_INT=new RewriteRuleTokenStream(adaptor,"token HEX_INT");
		RewriteRuleTokenStream stream_PIPE=new RewriteRuleTokenStream(adaptor,"token PIPE");
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleTokenStream stream_MINUS=new RewriteRuleTokenStream(adaptor,"token MINUS");
		RewriteRuleTokenStream stream_BIN_INT=new RewriteRuleTokenStream(adaptor,"token BIN_INT");
		RewriteRuleTokenStream stream_LINECOMMENT=new RewriteRuleTokenStream(adaptor,"token LINECOMMENT");
		RewriteRuleTokenStream stream_RIGHT=new RewriteRuleTokenStream(adaptor,"token RIGHT");
		RewriteRuleTokenStream stream_LESSEQUAL=new RewriteRuleTokenStream(adaptor,"token LESSEQUAL");
		RewriteRuleTokenStream stream_COMMA=new RewriteRuleTokenStream(adaptor,"token COMMA");
		RewriteRuleTokenStream stream_AMPERSAND=new RewriteRuleTokenStream(adaptor,"token AMPERSAND");
		RewriteRuleTokenStream stream_BOOL_AND=new RewriteRuleTokenStream(adaptor,"token BOOL_AND");
		RewriteRuleTokenStream stream_BOOL_XOR=new RewriteRuleTokenStream(adaptor,"token BOOL_XOR");
		RewriteRuleTokenStream stream_GREAT=new RewriteRuleTokenStream(adaptor,"token GREAT");
		RewriteRuleTokenStream stream_LEFT=new RewriteRuleTokenStream(adaptor,"token LEFT");
		RewriteRuleTokenStream stream_EQUAL=new RewriteRuleTokenStream(adaptor,"token EQUAL");
		RewriteRuleTokenStream stream_DISPCHAR=new RewriteRuleTokenStream(adaptor,"token DISPCHAR");
		RewriteRuleTokenStream stream_LPAREN=new RewriteRuleTokenStream(adaptor,"token LPAREN");
		RewriteRuleTokenStream stream_SLASH=new RewriteRuleTokenStream(adaptor,"token SLASH");
		RewriteRuleTokenStream stream_LBRACKET=new RewriteRuleTokenStream(adaptor,"token LBRACKET");
		RewriteRuleTokenStream stream_ASTERISK=new RewriteRuleTokenStream(adaptor,"token ASTERISK");
		RewriteRuleTokenStream stream_RBRACKET=new RewriteRuleTokenStream(adaptor,"token RBRACKET");
		RewriteRuleTokenStream stream_COLON=new RewriteRuleTokenStream(adaptor,"token COLON");
		RewriteRuleTokenStream stream_RPAREN=new RewriteRuleTokenStream(adaptor,"token RPAREN");
		RewriteRuleTokenStream stream_NOTEQUAL=new RewriteRuleTokenStream(adaptor,"token NOTEQUAL");
		RewriteRuleTokenStream stream_DEC_INT=new RewriteRuleTokenStream(adaptor,"token DEC_INT");
		RewriteRuleTokenStream stream_SPEC_OR=new RewriteRuleTokenStream(adaptor,"token SPEC_OR");
		RewriteRuleTokenStream stream_RBRACE=new RewriteRuleTokenStream(adaptor,"token RBRACE");
		RewriteRuleTokenStream stream_ELLIPSIS=new RewriteRuleTokenStream(adaptor,"token ELLIPSIS");
		RewriteRuleTokenStream stream_PERCENT=new RewriteRuleTokenStream(adaptor,"token PERCENT");
		RewriteRuleTokenStream stream_SPEC_XOR=new RewriteRuleTokenStream(adaptor,"token SPEC_XOR");
		RewriteRuleTokenStream stream_LESS=new RewriteRuleTokenStream(adaptor,"token LESS");
		RewriteRuleTokenStream stream_TILDE=new RewriteRuleTokenStream(adaptor,"token TILDE");
		RewriteRuleTokenStream stream_SPEC_AND=new RewriteRuleTokenStream(adaptor,"token SPEC_AND");
		RewriteRuleTokenStream stream_GREATEQUAL=new RewriteRuleTokenStream(adaptor,"token GREATEQUAL");
		RewriteRuleTokenStream stream_LBRACE=new RewriteRuleTokenStream(adaptor,"token LBRACE");
		RewriteRuleTokenStream stream_BOOL_OR=new RewriteRuleTokenStream(adaptor,"token BOOL_OR");
		RewriteRuleTokenStream stream_PLUS=new RewriteRuleTokenStream(adaptor,"token PLUS");

		try {
			// DisplayParser.g:45:2: (lc= DISPCHAR -> ^( OP_STRING[$lc, \"DISPCHAR\"] DISPCHAR ) |lc= LINECOMMENT -> ^( OP_STRING[$lc, \"LINECOMMENT\"] LINECOMMENT ) |lc= LBRACE -> ^( OP_STRING[$lc, \"LBRACE\"] LBRACE ) |lc= RBRACE -> ^( OP_STRING[$lc, \"RBRACE\"] RBRACE ) |lc= LBRACKET -> ^( OP_STRING[$lc, \"LBRACKET\"] LBRACKET ) |lc= RBRACKET -> ^( OP_STRING[$lc, \"RBRACKET\"] RBRACKET ) |lc= LPAREN -> ^( OP_STRING[$lc, \"LPAREN\"] LPAREN ) |lc= RPAREN -> ^( OP_STRING[$lc, \"RPAREN\"] RPAREN ) |lc= ELLIPSIS -> ^( OP_STRING[$lc, \"ELLIPSIS\"] ELLIPSIS ) |lc= EQUAL -> ^( OP_STRING[$lc, \"EQUAL\"] EQUAL ) |lc= NOTEQUAL -> ^( OP_STRING[$lc, \"NOTEQUAL\"] NOTEQUAL ) |lc= LESS -> ^( OP_STRING[$lc, \"LESS\"] LESS ) |lc= GREAT -> ^( OP_STRING[$lc, \"GREAT\"] GREAT ) |lc= LESSEQUAL -> ^( OP_STRING[$lc, \"LESSEQUAL\"] LESSEQUAL ) |lc= GREATEQUAL -> ^( OP_STRING[$lc, \"GREATEQUAL\"] GREATEQUAL ) |lc= ASSIGN -> ^( OP_STRING[$lc, \"ASSIGN\"] ASSIGN ) |lc= COLON -> ^( OP_STRING[$lc, \"COLON\"] COLON ) |lc= COMMA -> ^( OP_STRING[$lc, \"COMMA\"] COMMA ) |lc= ASTERISK -> ^( OP_STRING[$lc, \"ASTERISK\"] ASTERISK ) |lc= BOOL_OR -> ^( OP_STRING[$lc, \"BOOL_OR\"] BOOL_OR ) |lc= BOOL_XOR -> ^( OP_STRING[$lc, \"BOOL_XOR\"] BOOL_XOR ) |lc= BOOL_AND -> ^( OP_STRING[$lc, \"BOOL_AND\"] BOOL_AND ) |lc= PIPE -> ^( OP_STRING[$lc, \"PIPE\"] PIPE ) |lc= AMPERSAND -> ^( OP_STRING[$lc, \"AMPERSAND\"] AMPERSAND ) |lc= LEFT -> ^( OP_STRING[$lc, \"LEFT\"] LEFT ) |lc= RIGHT -> ^( OP_STRING[$lc, \"RIGHT\"] RIGHT ) |lc= PLUS -> ^( OP_STRING[$lc, \"PLUS\"] PLUS ) |lc= MINUS -> ^( OP_STRING[$lc, \"MINUS\"] MINUS ) |lc= SLASH -> ^( OP_STRING[$lc, \"SLASH\"] SLASH ) |lc= PERCENT -> ^( OP_STRING[$lc, \"PERCENT\"] PERCENT ) |lc= EXCLAIM -> ^( OP_STRING[$lc, \"EXCLAIM\"] EXCLAIM ) |lc= TILDE -> ^( OP_STRING[$lc, \"TILDE\"] TILDE ) |lc= SEMI -> ^( OP_STRING[$lc, \"SEMI\"] SEMI ) |lc= SPEC_OR -> ^( OP_STRING[$lc, \"SPEC_OR\"] SPEC_OR ) |lc= SPEC_AND -> ^( OP_STRING[$lc, \"SPEC_AND\"] SPEC_AND ) |lc= SPEC_XOR -> ^( OP_STRING[$lc, \"SPEC_XOR\"] SPEC_XOR ) |lc= DEC_INT -> ^( OP_STRING[$lc, \"DEC_INT\"] DEC_INT ) |lc= HEX_INT -> ^( OP_STRING[$lc, \"HEX_INT\"] HEX_INT ) |lc= BIN_INT -> ^( OP_STRING[$lc, \"BIN_INT\"] BIN_INT ) )
			int alt3=39;
			switch ( input.LA(1) ) {
			case DISPCHAR:
				{
				alt3=1;
				}
				break;
			case LINECOMMENT:
				{
				alt3=2;
				}
				break;
			case LBRACE:
				{
				alt3=3;
				}
				break;
			case RBRACE:
				{
				alt3=4;
				}
				break;
			case LBRACKET:
				{
				alt3=5;
				}
				break;
			case RBRACKET:
				{
				alt3=6;
				}
				break;
			case LPAREN:
				{
				alt3=7;
				}
				break;
			case RPAREN:
				{
				alt3=8;
				}
				break;
			case ELLIPSIS:
				{
				alt3=9;
				}
				break;
			case EQUAL:
				{
				alt3=10;
				}
				break;
			case NOTEQUAL:
				{
				alt3=11;
				}
				break;
			case LESS:
				{
				alt3=12;
				}
				break;
			case GREAT:
				{
				alt3=13;
				}
				break;
			case LESSEQUAL:
				{
				alt3=14;
				}
				break;
			case GREATEQUAL:
				{
				alt3=15;
				}
				break;
			case ASSIGN:
				{
				alt3=16;
				}
				break;
			case COLON:
				{
				alt3=17;
				}
				break;
			case COMMA:
				{
				alt3=18;
				}
				break;
			case ASTERISK:
				{
				alt3=19;
				}
				break;
			case BOOL_OR:
				{
				alt3=20;
				}
				break;
			case BOOL_XOR:
				{
				alt3=21;
				}
				break;
			case BOOL_AND:
				{
				alt3=22;
				}
				break;
			case PIPE:
				{
				alt3=23;
				}
				break;
			case AMPERSAND:
				{
				alt3=24;
				}
				break;
			case LEFT:
				{
				alt3=25;
				}
				break;
			case RIGHT:
				{
				alt3=26;
				}
				break;
			case PLUS:
				{
				alt3=27;
				}
				break;
			case MINUS:
				{
				alt3=28;
				}
				break;
			case SLASH:
				{
				alt3=29;
				}
				break;
			case PERCENT:
				{
				alt3=30;
				}
				break;
			case EXCLAIM:
				{
				alt3=31;
				}
				break;
			case TILDE:
				{
				alt3=32;
				}
				break;
			case SEMI:
				{
				alt3=33;
				}
				break;
			case SPEC_OR:
				{
				alt3=34;
				}
				break;
			case SPEC_AND:
				{
				alt3=35;
				}
				break;
			case SPEC_XOR:
				{
				alt3=36;
				}
				break;
			case DEC_INT:
				{
				alt3=37;
				}
				break;
			case HEX_INT:
				{
				alt3=38;
				}
				break;
			case BIN_INT:
				{
				alt3=39;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 3, 0, input);
				throw nvae;
			}
			switch (alt3) {
				case 1 :
					// DisplayParser.g:45:4: lc= DISPCHAR
					{
					lc=(Token)match(input,DISPCHAR,FOLLOW_DISPCHAR_in_special168);  
					stream_DISPCHAR.add(lc);

					// AST REWRITE
					// elements: DISPCHAR
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 45:18: -> ^( OP_STRING[$lc, \"DISPCHAR\"] DISPCHAR )
					{
						// DisplayParser.g:45:21: ^( OP_STRING[$lc, \"DISPCHAR\"] DISPCHAR )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "DISPCHAR"), root_1);
						adaptor.addChild(root_1, stream_DISPCHAR.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 2 :
					// DisplayParser.g:46:4: lc= LINECOMMENT
					{
					lc=(Token)match(input,LINECOMMENT,FOLLOW_LINECOMMENT_in_special186);  
					stream_LINECOMMENT.add(lc);

					// AST REWRITE
					// elements: LINECOMMENT
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 46:20: -> ^( OP_STRING[$lc, \"LINECOMMENT\"] LINECOMMENT )
					{
						// DisplayParser.g:46:23: ^( OP_STRING[$lc, \"LINECOMMENT\"] LINECOMMENT )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "LINECOMMENT"), root_1);
						adaptor.addChild(root_1, stream_LINECOMMENT.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 3 :
					// DisplayParser.g:47:4: lc= LBRACE
					{
					lc=(Token)match(input,LBRACE,FOLLOW_LBRACE_in_special204);  
					stream_LBRACE.add(lc);

					// AST REWRITE
					// elements: LBRACE
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 47:16: -> ^( OP_STRING[$lc, \"LBRACE\"] LBRACE )
					{
						// DisplayParser.g:47:19: ^( OP_STRING[$lc, \"LBRACE\"] LBRACE )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "LBRACE"), root_1);
						adaptor.addChild(root_1, stream_LBRACE.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 4 :
					// DisplayParser.g:48:4: lc= RBRACE
					{
					lc=(Token)match(input,RBRACE,FOLLOW_RBRACE_in_special222);  
					stream_RBRACE.add(lc);

					// AST REWRITE
					// elements: RBRACE
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 48:16: -> ^( OP_STRING[$lc, \"RBRACE\"] RBRACE )
					{
						// DisplayParser.g:48:19: ^( OP_STRING[$lc, \"RBRACE\"] RBRACE )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "RBRACE"), root_1);
						adaptor.addChild(root_1, stream_RBRACE.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 5 :
					// DisplayParser.g:49:4: lc= LBRACKET
					{
					lc=(Token)match(input,LBRACKET,FOLLOW_LBRACKET_in_special240);  
					stream_LBRACKET.add(lc);

					// AST REWRITE
					// elements: LBRACKET
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 49:18: -> ^( OP_STRING[$lc, \"LBRACKET\"] LBRACKET )
					{
						// DisplayParser.g:49:21: ^( OP_STRING[$lc, \"LBRACKET\"] LBRACKET )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "LBRACKET"), root_1);
						adaptor.addChild(root_1, stream_LBRACKET.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 6 :
					// DisplayParser.g:50:4: lc= RBRACKET
					{
					lc=(Token)match(input,RBRACKET,FOLLOW_RBRACKET_in_special258);  
					stream_RBRACKET.add(lc);

					// AST REWRITE
					// elements: RBRACKET
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 50:18: -> ^( OP_STRING[$lc, \"RBRACKET\"] RBRACKET )
					{
						// DisplayParser.g:50:21: ^( OP_STRING[$lc, \"RBRACKET\"] RBRACKET )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "RBRACKET"), root_1);
						adaptor.addChild(root_1, stream_RBRACKET.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 7 :
					// DisplayParser.g:51:4: lc= LPAREN
					{
					lc=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_special276);  
					stream_LPAREN.add(lc);

					// AST REWRITE
					// elements: LPAREN
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 51:16: -> ^( OP_STRING[$lc, \"LPAREN\"] LPAREN )
					{
						// DisplayParser.g:51:19: ^( OP_STRING[$lc, \"LPAREN\"] LPAREN )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "LPAREN"), root_1);
						adaptor.addChild(root_1, stream_LPAREN.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 8 :
					// DisplayParser.g:52:4: lc= RPAREN
					{
					lc=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_special294);  
					stream_RPAREN.add(lc);

					// AST REWRITE
					// elements: RPAREN
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 52:16: -> ^( OP_STRING[$lc, \"RPAREN\"] RPAREN )
					{
						// DisplayParser.g:52:19: ^( OP_STRING[$lc, \"RPAREN\"] RPAREN )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "RPAREN"), root_1);
						adaptor.addChild(root_1, stream_RPAREN.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 9 :
					// DisplayParser.g:53:4: lc= ELLIPSIS
					{
					lc=(Token)match(input,ELLIPSIS,FOLLOW_ELLIPSIS_in_special312);  
					stream_ELLIPSIS.add(lc);

					// AST REWRITE
					// elements: ELLIPSIS
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 53:18: -> ^( OP_STRING[$lc, \"ELLIPSIS\"] ELLIPSIS )
					{
						// DisplayParser.g:53:21: ^( OP_STRING[$lc, \"ELLIPSIS\"] ELLIPSIS )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "ELLIPSIS"), root_1);
						adaptor.addChild(root_1, stream_ELLIPSIS.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 10 :
					// DisplayParser.g:54:4: lc= EQUAL
					{
					lc=(Token)match(input,EQUAL,FOLLOW_EQUAL_in_special330);  
					stream_EQUAL.add(lc);

					// AST REWRITE
					// elements: EQUAL
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 54:15: -> ^( OP_STRING[$lc, \"EQUAL\"] EQUAL )
					{
						// DisplayParser.g:54:18: ^( OP_STRING[$lc, \"EQUAL\"] EQUAL )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "EQUAL"), root_1);
						adaptor.addChild(root_1, stream_EQUAL.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 11 :
					// DisplayParser.g:55:4: lc= NOTEQUAL
					{
					lc=(Token)match(input,NOTEQUAL,FOLLOW_NOTEQUAL_in_special348);  
					stream_NOTEQUAL.add(lc);

					// AST REWRITE
					// elements: NOTEQUAL
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 55:18: -> ^( OP_STRING[$lc, \"NOTEQUAL\"] NOTEQUAL )
					{
						// DisplayParser.g:55:21: ^( OP_STRING[$lc, \"NOTEQUAL\"] NOTEQUAL )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "NOTEQUAL"), root_1);
						adaptor.addChild(root_1, stream_NOTEQUAL.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 12 :
					// DisplayParser.g:56:4: lc= LESS
					{
					lc=(Token)match(input,LESS,FOLLOW_LESS_in_special366);  
					stream_LESS.add(lc);

					// AST REWRITE
					// elements: LESS
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 56:15: -> ^( OP_STRING[$lc, \"LESS\"] LESS )
					{
						// DisplayParser.g:56:18: ^( OP_STRING[$lc, \"LESS\"] LESS )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "LESS"), root_1);
						adaptor.addChild(root_1, stream_LESS.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 13 :
					// DisplayParser.g:57:4: lc= GREAT
					{
					lc=(Token)match(input,GREAT,FOLLOW_GREAT_in_special385);  
					stream_GREAT.add(lc);

					// AST REWRITE
					// elements: GREAT
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 57:15: -> ^( OP_STRING[$lc, \"GREAT\"] GREAT )
					{
						// DisplayParser.g:57:18: ^( OP_STRING[$lc, \"GREAT\"] GREAT )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "GREAT"), root_1);
						adaptor.addChild(root_1, stream_GREAT.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 14 :
					// DisplayParser.g:58:4: lc= LESSEQUAL
					{
					lc=(Token)match(input,LESSEQUAL,FOLLOW_LESSEQUAL_in_special403);  
					stream_LESSEQUAL.add(lc);

					// AST REWRITE
					// elements: LESSEQUAL
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 58:18: -> ^( OP_STRING[$lc, \"LESSEQUAL\"] LESSEQUAL )
					{
						// DisplayParser.g:58:21: ^( OP_STRING[$lc, \"LESSEQUAL\"] LESSEQUAL )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "LESSEQUAL"), root_1);
						adaptor.addChild(root_1, stream_LESSEQUAL.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 15 :
					// DisplayParser.g:59:4: lc= GREATEQUAL
					{
					lc=(Token)match(input,GREATEQUAL,FOLLOW_GREATEQUAL_in_special420);  
					stream_GREATEQUAL.add(lc);

					// AST REWRITE
					// elements: GREATEQUAL
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 59:19: -> ^( OP_STRING[$lc, \"GREATEQUAL\"] GREATEQUAL )
					{
						// DisplayParser.g:59:22: ^( OP_STRING[$lc, \"GREATEQUAL\"] GREATEQUAL )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "GREATEQUAL"), root_1);
						adaptor.addChild(root_1, stream_GREATEQUAL.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 16 :
					// DisplayParser.g:60:4: lc= ASSIGN
					{
					lc=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_special437);  
					stream_ASSIGN.add(lc);

					// AST REWRITE
					// elements: ASSIGN
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 60:16: -> ^( OP_STRING[$lc, \"ASSIGN\"] ASSIGN )
					{
						// DisplayParser.g:60:19: ^( OP_STRING[$lc, \"ASSIGN\"] ASSIGN )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "ASSIGN"), root_1);
						adaptor.addChild(root_1, stream_ASSIGN.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 17 :
					// DisplayParser.g:61:4: lc= COLON
					{
					lc=(Token)match(input,COLON,FOLLOW_COLON_in_special455);  
					stream_COLON.add(lc);

					// AST REWRITE
					// elements: COLON
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 61:15: -> ^( OP_STRING[$lc, \"COLON\"] COLON )
					{
						// DisplayParser.g:61:18: ^( OP_STRING[$lc, \"COLON\"] COLON )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "COLON"), root_1);
						adaptor.addChild(root_1, stream_COLON.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 18 :
					// DisplayParser.g:62:4: lc= COMMA
					{
					lc=(Token)match(input,COMMA,FOLLOW_COMMA_in_special473);  
					stream_COMMA.add(lc);

					// AST REWRITE
					// elements: COMMA
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 62:15: -> ^( OP_STRING[$lc, \"COMMA\"] COMMA )
					{
						// DisplayParser.g:62:18: ^( OP_STRING[$lc, \"COMMA\"] COMMA )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "COMMA"), root_1);
						adaptor.addChild(root_1, stream_COMMA.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 19 :
					// DisplayParser.g:63:4: lc= ASTERISK
					{
					lc=(Token)match(input,ASTERISK,FOLLOW_ASTERISK_in_special491);  
					stream_ASTERISK.add(lc);

					// AST REWRITE
					// elements: ASTERISK
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 63:18: -> ^( OP_STRING[$lc, \"ASTERISK\"] ASTERISK )
					{
						// DisplayParser.g:63:21: ^( OP_STRING[$lc, \"ASTERISK\"] ASTERISK )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "ASTERISK"), root_1);
						adaptor.addChild(root_1, stream_ASTERISK.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 20 :
					// DisplayParser.g:64:4: lc= BOOL_OR
					{
					lc=(Token)match(input,BOOL_OR,FOLLOW_BOOL_OR_in_special509);  
					stream_BOOL_OR.add(lc);

					// AST REWRITE
					// elements: BOOL_OR
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 64:17: -> ^( OP_STRING[$lc, \"BOOL_OR\"] BOOL_OR )
					{
						// DisplayParser.g:64:20: ^( OP_STRING[$lc, \"BOOL_OR\"] BOOL_OR )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "BOOL_OR"), root_1);
						adaptor.addChild(root_1, stream_BOOL_OR.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 21 :
					// DisplayParser.g:65:4: lc= BOOL_XOR
					{
					lc=(Token)match(input,BOOL_XOR,FOLLOW_BOOL_XOR_in_special527);  
					stream_BOOL_XOR.add(lc);

					// AST REWRITE
					// elements: BOOL_XOR
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 65:18: -> ^( OP_STRING[$lc, \"BOOL_XOR\"] BOOL_XOR )
					{
						// DisplayParser.g:65:21: ^( OP_STRING[$lc, \"BOOL_XOR\"] BOOL_XOR )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "BOOL_XOR"), root_1);
						adaptor.addChild(root_1, stream_BOOL_XOR.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 22 :
					// DisplayParser.g:66:4: lc= BOOL_AND
					{
					lc=(Token)match(input,BOOL_AND,FOLLOW_BOOL_AND_in_special545);  
					stream_BOOL_AND.add(lc);

					// AST REWRITE
					// elements: BOOL_AND
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 66:18: -> ^( OP_STRING[$lc, \"BOOL_AND\"] BOOL_AND )
					{
						// DisplayParser.g:66:21: ^( OP_STRING[$lc, \"BOOL_AND\"] BOOL_AND )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "BOOL_AND"), root_1);
						adaptor.addChild(root_1, stream_BOOL_AND.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 23 :
					// DisplayParser.g:67:4: lc= PIPE
					{
					lc=(Token)match(input,PIPE,FOLLOW_PIPE_in_special563);  
					stream_PIPE.add(lc);

					// AST REWRITE
					// elements: PIPE
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 67:15: -> ^( OP_STRING[$lc, \"PIPE\"] PIPE )
					{
						// DisplayParser.g:67:18: ^( OP_STRING[$lc, \"PIPE\"] PIPE )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "PIPE"), root_1);
						adaptor.addChild(root_1, stream_PIPE.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 24 :
					// DisplayParser.g:68:4: lc= AMPERSAND
					{
					lc=(Token)match(input,AMPERSAND,FOLLOW_AMPERSAND_in_special582);  
					stream_AMPERSAND.add(lc);

					// AST REWRITE
					// elements: AMPERSAND
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 68:18: -> ^( OP_STRING[$lc, \"AMPERSAND\"] AMPERSAND )
					{
						// DisplayParser.g:68:21: ^( OP_STRING[$lc, \"AMPERSAND\"] AMPERSAND )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "AMPERSAND"), root_1);
						adaptor.addChild(root_1, stream_AMPERSAND.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 25 :
					// DisplayParser.g:69:4: lc= LEFT
					{
					lc=(Token)match(input,LEFT,FOLLOW_LEFT_in_special599);  
					stream_LEFT.add(lc);

					// AST REWRITE
					// elements: LEFT
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 69:15: -> ^( OP_STRING[$lc, \"LEFT\"] LEFT )
					{
						// DisplayParser.g:69:18: ^( OP_STRING[$lc, \"LEFT\"] LEFT )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "LEFT"), root_1);
						adaptor.addChild(root_1, stream_LEFT.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 26 :
					// DisplayParser.g:70:4: lc= RIGHT
					{
					lc=(Token)match(input,RIGHT,FOLLOW_RIGHT_in_special618);  
					stream_RIGHT.add(lc);

					// AST REWRITE
					// elements: RIGHT
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 70:15: -> ^( OP_STRING[$lc, \"RIGHT\"] RIGHT )
					{
						// DisplayParser.g:70:18: ^( OP_STRING[$lc, \"RIGHT\"] RIGHT )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "RIGHT"), root_1);
						adaptor.addChild(root_1, stream_RIGHT.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 27 :
					// DisplayParser.g:71:4: lc= PLUS
					{
					lc=(Token)match(input,PLUS,FOLLOW_PLUS_in_special636);  
					stream_PLUS.add(lc);

					// AST REWRITE
					// elements: PLUS
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 71:15: -> ^( OP_STRING[$lc, \"PLUS\"] PLUS )
					{
						// DisplayParser.g:71:18: ^( OP_STRING[$lc, \"PLUS\"] PLUS )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "PLUS"), root_1);
						adaptor.addChild(root_1, stream_PLUS.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 28 :
					// DisplayParser.g:72:4: lc= MINUS
					{
					lc=(Token)match(input,MINUS,FOLLOW_MINUS_in_special655);  
					stream_MINUS.add(lc);

					// AST REWRITE
					// elements: MINUS
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 72:15: -> ^( OP_STRING[$lc, \"MINUS\"] MINUS )
					{
						// DisplayParser.g:72:18: ^( OP_STRING[$lc, \"MINUS\"] MINUS )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "MINUS"), root_1);
						adaptor.addChild(root_1, stream_MINUS.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 29 :
					// DisplayParser.g:73:4: lc= SLASH
					{
					lc=(Token)match(input,SLASH,FOLLOW_SLASH_in_special673);  
					stream_SLASH.add(lc);

					// AST REWRITE
					// elements: SLASH
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 73:15: -> ^( OP_STRING[$lc, \"SLASH\"] SLASH )
					{
						// DisplayParser.g:73:18: ^( OP_STRING[$lc, \"SLASH\"] SLASH )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "SLASH"), root_1);
						adaptor.addChild(root_1, stream_SLASH.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 30 :
					// DisplayParser.g:74:4: lc= PERCENT
					{
					lc=(Token)match(input,PERCENT,FOLLOW_PERCENT_in_special691);  
					stream_PERCENT.add(lc);

					// AST REWRITE
					// elements: PERCENT
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 74:17: -> ^( OP_STRING[$lc, \"PERCENT\"] PERCENT )
					{
						// DisplayParser.g:74:20: ^( OP_STRING[$lc, \"PERCENT\"] PERCENT )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "PERCENT"), root_1);
						adaptor.addChild(root_1, stream_PERCENT.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 31 :
					// DisplayParser.g:75:4: lc= EXCLAIM
					{
					lc=(Token)match(input,EXCLAIM,FOLLOW_EXCLAIM_in_special709);  
					stream_EXCLAIM.add(lc);

					// AST REWRITE
					// elements: EXCLAIM
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 75:17: -> ^( OP_STRING[$lc, \"EXCLAIM\"] EXCLAIM )
					{
						// DisplayParser.g:75:20: ^( OP_STRING[$lc, \"EXCLAIM\"] EXCLAIM )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "EXCLAIM"), root_1);
						adaptor.addChild(root_1, stream_EXCLAIM.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 32 :
					// DisplayParser.g:76:4: lc= TILDE
					{
					lc=(Token)match(input,TILDE,FOLLOW_TILDE_in_special727);  
					stream_TILDE.add(lc);

					// AST REWRITE
					// elements: TILDE
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 76:15: -> ^( OP_STRING[$lc, \"TILDE\"] TILDE )
					{
						// DisplayParser.g:76:18: ^( OP_STRING[$lc, \"TILDE\"] TILDE )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "TILDE"), root_1);
						adaptor.addChild(root_1, stream_TILDE.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 33 :
					// DisplayParser.g:77:4: lc= SEMI
					{
					lc=(Token)match(input,SEMI,FOLLOW_SEMI_in_special745);  
					stream_SEMI.add(lc);

					// AST REWRITE
					// elements: SEMI
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 77:15: -> ^( OP_STRING[$lc, \"SEMI\"] SEMI )
					{
						// DisplayParser.g:77:18: ^( OP_STRING[$lc, \"SEMI\"] SEMI )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "SEMI"), root_1);
						adaptor.addChild(root_1, stream_SEMI.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 34 :
					// DisplayParser.g:78:4: lc= SPEC_OR
					{
					lc=(Token)match(input,SPEC_OR,FOLLOW_SPEC_OR_in_special764);  
					stream_SPEC_OR.add(lc);

					// AST REWRITE
					// elements: SPEC_OR
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 78:17: -> ^( OP_STRING[$lc, \"SPEC_OR\"] SPEC_OR )
					{
						// DisplayParser.g:78:20: ^( OP_STRING[$lc, \"SPEC_OR\"] SPEC_OR )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "SPEC_OR"), root_1);
						adaptor.addChild(root_1, stream_SPEC_OR.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 35 :
					// DisplayParser.g:79:4: lc= SPEC_AND
					{
					lc=(Token)match(input,SPEC_AND,FOLLOW_SPEC_AND_in_special782);  
					stream_SPEC_AND.add(lc);

					// AST REWRITE
					// elements: SPEC_AND
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 79:18: -> ^( OP_STRING[$lc, \"SPEC_AND\"] SPEC_AND )
					{
						// DisplayParser.g:79:21: ^( OP_STRING[$lc, \"SPEC_AND\"] SPEC_AND )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "SPEC_AND"), root_1);
						adaptor.addChild(root_1, stream_SPEC_AND.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 36 :
					// DisplayParser.g:80:4: lc= SPEC_XOR
					{
					lc=(Token)match(input,SPEC_XOR,FOLLOW_SPEC_XOR_in_special800);  
					stream_SPEC_XOR.add(lc);

					// AST REWRITE
					// elements: SPEC_XOR
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 80:18: -> ^( OP_STRING[$lc, \"SPEC_XOR\"] SPEC_XOR )
					{
						// DisplayParser.g:80:21: ^( OP_STRING[$lc, \"SPEC_XOR\"] SPEC_XOR )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "SPEC_XOR"), root_1);
						adaptor.addChild(root_1, stream_SPEC_XOR.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 37 :
					// DisplayParser.g:81:4: lc= DEC_INT
					{
					lc=(Token)match(input,DEC_INT,FOLLOW_DEC_INT_in_special818);  
					stream_DEC_INT.add(lc);

					// AST REWRITE
					// elements: DEC_INT
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 81:17: -> ^( OP_STRING[$lc, \"DEC_INT\"] DEC_INT )
					{
						// DisplayParser.g:81:20: ^( OP_STRING[$lc, \"DEC_INT\"] DEC_INT )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "DEC_INT"), root_1);
						adaptor.addChild(root_1, stream_DEC_INT.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 38 :
					// DisplayParser.g:82:4: lc= HEX_INT
					{
					lc=(Token)match(input,HEX_INT,FOLLOW_HEX_INT_in_special836);  
					stream_HEX_INT.add(lc);

					// AST REWRITE
					// elements: HEX_INT
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 82:17: -> ^( OP_STRING[$lc, \"HEX_INT\"] HEX_INT )
					{
						// DisplayParser.g:82:20: ^( OP_STRING[$lc, \"HEX_INT\"] HEX_INT )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "HEX_INT"), root_1);
						adaptor.addChild(root_1, stream_HEX_INT.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 39 :
					// DisplayParser.g:83:4: lc= BIN_INT
					{
					lc=(Token)match(input,BIN_INT,FOLLOW_BIN_INT_in_special854);  
					stream_BIN_INT.add(lc);

					// AST REWRITE
					// elements: BIN_INT
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 83:17: -> ^( OP_STRING[$lc, \"BIN_INT\"] BIN_INT )
					{
						// DisplayParser.g:83:20: ^( OP_STRING[$lc, \"BIN_INT\"] BIN_INT )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_STRING, lc, "BIN_INT"), root_1);
						adaptor.addChild(root_1, stream_BIN_INT.nextNode());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;

			}
			retval.stop = input.LT(-1);

			retval.tree = (CommonTree)adaptor.rulePostProcessing(root_0);
			adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop);

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
	// $ANTLR end "special"

	// Delegated rules



	public static final BitSet FOLLOW_COLON_in_display32 = new BitSet(new long[]{0xFFFFFFB002B5FDC0L,0x000000000003FFFFL,0x0000000000000000L,0x000021392D738000L});
	public static final BitSet FOLLOW_pieces_in_display34 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000001000000L});
	public static final BitSet FOLLOW_RES_IS_in_display36 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_printpiece_in_pieces57 = new BitSet(new long[]{0xFFFFFFB002B5FDC2L,0x000000000003FFFFL,0x0000000000000000L,0x000021392C738000L});
	public static final BitSet FOLLOW_identifier_in_printpiece69 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_whitespace_in_printpiece74 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_concatenate_in_printpiece79 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_qstring_in_printpiece84 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_special_in_printpiece89 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_WS_in_whitespace102 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_CARET_in_concatenate126 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_DISPCHAR_in_special168 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LINECOMMENT_in_special186 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LBRACE_in_special204 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_RBRACE_in_special222 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LBRACKET_in_special240 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_RBRACKET_in_special258 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LPAREN_in_special276 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_RPAREN_in_special294 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_ELLIPSIS_in_special312 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_EQUAL_in_special330 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_NOTEQUAL_in_special348 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LESS_in_special366 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_GREAT_in_special385 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LESSEQUAL_in_special403 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_GREATEQUAL_in_special420 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_ASSIGN_in_special437 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_COLON_in_special455 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_COMMA_in_special473 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_ASTERISK_in_special491 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_BOOL_OR_in_special509 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_BOOL_XOR_in_special527 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_BOOL_AND_in_special545 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_PIPE_in_special563 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_AMPERSAND_in_special582 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LEFT_in_special599 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_RIGHT_in_special618 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_PLUS_in_special636 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_MINUS_in_special655 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SLASH_in_special673 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_PERCENT_in_special691 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_EXCLAIM_in_special709 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_TILDE_in_special727 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SEMI_in_special745 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SPEC_OR_in_special764 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SPEC_AND_in_special782 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SPEC_XOR_in_special800 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_DEC_INT_in_special818 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_HEX_INT_in_special836 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_BIN_INT_in_special854 = new BitSet(new long[]{0x0000000000000002L});
}
