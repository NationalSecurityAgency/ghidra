package ghidra.sleigh.grammar;
// $ANTLR 3.5.2 SemanticParser.g 2019-02-28 12:48:47

import org.antlr.runtime.*;
import java.util.Stack;
import java.util.List;
import java.util.ArrayList;

import org.antlr.runtime.tree.*;


@SuppressWarnings("all")
public class SleighParser_SemanticParser extends AbstractSleighParser {
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


	public SleighParser_SemanticParser(TokenStream input, SleighParser gSleighParser) {
		this(input, new RecognizerSharedState(), gSleighParser);
	}
	public SleighParser_SemanticParser(TokenStream input, RecognizerSharedState state, SleighParser gSleighParser) {
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
	@Override public String getGrammarFileName() { return "SemanticParser.g"; }


	public static class semanticbody_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "semanticbody"
	// SemanticParser.g:13:1: semanticbody : LBRACE semantic RBRACE -> semantic ;
	public final SleighParser_SemanticParser.semanticbody_return semanticbody() throws RecognitionException {
		SleighParser_SemanticParser.semanticbody_return retval = new SleighParser_SemanticParser.semanticbody_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token LBRACE1=null;
		Token RBRACE3=null;
		ParserRuleReturnScope semantic2 =null;

		CommonTree LBRACE1_tree=null;
		CommonTree RBRACE3_tree=null;
		RewriteRuleTokenStream stream_RBRACE=new RewriteRuleTokenStream(adaptor,"token RBRACE");
		RewriteRuleTokenStream stream_LBRACE=new RewriteRuleTokenStream(adaptor,"token LBRACE");
		RewriteRuleSubtreeStream stream_semantic=new RewriteRuleSubtreeStream(adaptor,"rule semantic");

		try {
			// SemanticParser.g:14:2: ( LBRACE semantic RBRACE -> semantic )
			// SemanticParser.g:14:4: LBRACE semantic RBRACE
			{
			LBRACE1=(Token)match(input,LBRACE,FOLLOW_LBRACE_in_semanticbody30);  
			stream_LBRACE.add(LBRACE1);

			 lexer.pushMode(SEMANTIC); 
			pushFollow(FOLLOW_semantic_in_semanticbody34);
			semantic2=semantic();
			state._fsp--;

			stream_semantic.add(semantic2.getTree());
			RBRACE3=(Token)match(input,RBRACE,FOLLOW_RBRACE_in_semanticbody36);  
			stream_RBRACE.add(RBRACE3);

			 lexer.popMode(); 
			// AST REWRITE
			// elements: semantic
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 14:78: -> semantic
			{
				adaptor.addChild(root_0, stream_semantic.nextTree());
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
	// $ANTLR end "semanticbody"


	public static class semantic_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "semantic"
	// SemanticParser.g:17:1: semantic : code_block -> ^( OP_SEMANTIC code_block ) ;
	public final SleighParser_SemanticParser.semantic_return semantic() throws RecognitionException {
		SleighParser_SemanticParser.semantic_return retval = new SleighParser_SemanticParser.semantic_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope code_block4 =null;

		RewriteRuleSubtreeStream stream_code_block=new RewriteRuleSubtreeStream(adaptor,"rule code_block");

		try {
			// SemanticParser.g:18:2: ( code_block -> ^( OP_SEMANTIC code_block ) )
			// SemanticParser.g:18:4: code_block
			{
			pushFollow(FOLLOW_code_block_in_semantic53);
			code_block4=code_block();
			state._fsp--;

			stream_code_block.add(code_block4.getTree());
			// AST REWRITE
			// elements: code_block
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 18:15: -> ^( OP_SEMANTIC code_block )
			{
				// SemanticParser.g:18:18: ^( OP_SEMANTIC code_block )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SEMANTIC, "OP_SEMANTIC"), root_1);
				adaptor.addChild(root_1, stream_code_block.nextTree());
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
	// $ANTLR end "semantic"


	public static class code_block_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "code_block"
	// SemanticParser.g:21:1: code_block : ( statements | -> ^( OP_NOP ) );
	public final SleighParser_SemanticParser.code_block_return code_block() throws RecognitionException {
		SleighParser_SemanticParser.code_block_return retval = new SleighParser_SemanticParser.code_block_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope statements5 =null;


		try {
			// SemanticParser.g:22:2: ( statements | -> ^( OP_NOP ) )
			int alt1=2;
			int LA1_0 = input.LA(1);
			if ( ((LA1_0 >= AMPERSAND && LA1_0 <= ASTERISK)||(LA1_0 >= BOOL_AND && LA1_0 <= COMMA)||LA1_0==EQUAL||(LA1_0 >= FDIV && LA1_0 <= FPLUS)||LA1_0==GREATEQUAL||(LA1_0 >= IDENTIFIER && LA1_0 <= KEY_WORDSIZE)||(LA1_0 >= LEFT && LA1_0 <= LESSEQUAL)||(LA1_0 >= LPAREN && LA1_0 <= NOTEQUAL)||(LA1_0 >= PERCENT && LA1_0 <= PLUS)||(LA1_0 >= RBRACKET && LA1_0 <= RES_IF)||(LA1_0 >= RPAREN && LA1_0 <= SLESSEQUAL)||(LA1_0 >= SREM && LA1_0 <= TILDE)) ) {
				alt1=1;
			}
			else if ( (LA1_0==RBRACE) ) {
				alt1=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 1, 0, input);
				throw nvae;
			}

			switch (alt1) {
				case 1 :
					// SemanticParser.g:22:4: statements
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_statements_in_code_block72);
					statements5=statements();
					state._fsp--;

					adaptor.addChild(root_0, statements5.getTree());

					}
					break;
				case 2 :
					// SemanticParser.g:23:4: 
					{
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
					// 23:4: -> ^( OP_NOP )
					{
						// SemanticParser.g:23:7: ^( OP_NOP )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_NOP, "OP_NOP"), root_1);
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
	// $ANTLR end "code_block"


	public static class statements_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "statements"
	// SemanticParser.g:29:1: statements : ( statement )+ ;
	public final SleighParser_SemanticParser.statements_return statements() throws RecognitionException {
		SleighParser_SemanticParser.statements_return retval = new SleighParser_SemanticParser.statements_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope statement6 =null;


		try {
			// SemanticParser.g:30:2: ( ( statement )+ )
			// SemanticParser.g:30:4: ( statement )+
			{
			root_0 = (CommonTree)adaptor.nil();


			// SemanticParser.g:30:4: ( statement )+
			int cnt2=0;
			loop2:
			while (true) {
				int alt2=2;
				int LA2_0 = input.LA(1);
				if ( ((LA2_0 >= AMPERSAND && LA2_0 <= ASTERISK)||(LA2_0 >= BOOL_AND && LA2_0 <= COMMA)||LA2_0==EQUAL||(LA2_0 >= FDIV && LA2_0 <= FPLUS)||LA2_0==GREATEQUAL||(LA2_0 >= IDENTIFIER && LA2_0 <= KEY_WORDSIZE)||(LA2_0 >= LEFT && LA2_0 <= LESSEQUAL)||(LA2_0 >= LPAREN && LA2_0 <= NOTEQUAL)||(LA2_0 >= PERCENT && LA2_0 <= PLUS)||(LA2_0 >= RBRACKET && LA2_0 <= RES_IF)||(LA2_0 >= RPAREN && LA2_0 <= SLESSEQUAL)||(LA2_0 >= SREM && LA2_0 <= TILDE)) ) {
					alt2=1;
				}

				switch (alt2) {
				case 1 :
					// SemanticParser.g:30:4: statement
					{
					pushFollow(FOLLOW_statement_in_statements95);
					statement6=statement();
					state._fsp--;

					adaptor.addChild(root_0, statement6.getTree());

					}
					break;

				default :
					if ( cnt2 >= 1 ) break loop2;
					EarlyExitException eee = new EarlyExitException(2, input);
					throw eee;
				}
				cnt2++;
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
	// $ANTLR end "statements"


	public static class label_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "label"
	// SemanticParser.g:33:1: label : lc= LESS identifier GREAT -> ^( OP_LABEL[$lc] identifier ) ;
	public final SleighParser_SemanticParser.label_return label() throws RecognitionException {
		SleighParser_SemanticParser.label_return retval = new SleighParser_SemanticParser.label_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token GREAT8=null;
		ParserRuleReturnScope identifier7 =null;

		CommonTree lc_tree=null;
		CommonTree GREAT8_tree=null;
		RewriteRuleTokenStream stream_GREAT=new RewriteRuleTokenStream(adaptor,"token GREAT");
		RewriteRuleTokenStream stream_LESS=new RewriteRuleTokenStream(adaptor,"token LESS");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");

		try {
			// SemanticParser.g:34:2: (lc= LESS identifier GREAT -> ^( OP_LABEL[$lc] identifier ) )
			// SemanticParser.g:34:4: lc= LESS identifier GREAT
			{
			lc=(Token)match(input,LESS,FOLLOW_LESS_in_label109);  
			stream_LESS.add(lc);

			pushFollow(FOLLOW_identifier_in_label111);
			identifier7=gSleighParser.identifier();
			state._fsp--;

			stream_identifier.add(identifier7.getTree());
			GREAT8=(Token)match(input,GREAT,FOLLOW_GREAT_in_label113);  
			stream_GREAT.add(GREAT8);

			// AST REWRITE
			// elements: identifier
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 34:29: -> ^( OP_LABEL[$lc] identifier )
			{
				// SemanticParser.g:34:32: ^( OP_LABEL[$lc] identifier )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_LABEL, lc), root_1);
				adaptor.addChild(root_1, stream_identifier.nextTree());
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
	// $ANTLR end "label"


	public static class section_def_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "section_def"
	// SemanticParser.g:37:1: section_def : lc= LEFT identifier RIGHT -> ^( OP_SECTION_LABEL[$lc] identifier ) ;
	public final SleighParser_SemanticParser.section_def_return section_def() throws RecognitionException {
		SleighParser_SemanticParser.section_def_return retval = new SleighParser_SemanticParser.section_def_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token RIGHT10=null;
		ParserRuleReturnScope identifier9 =null;

		CommonTree lc_tree=null;
		CommonTree RIGHT10_tree=null;
		RewriteRuleTokenStream stream_LEFT=new RewriteRuleTokenStream(adaptor,"token LEFT");
		RewriteRuleTokenStream stream_RIGHT=new RewriteRuleTokenStream(adaptor,"token RIGHT");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");

		try {
			// SemanticParser.g:38:2: (lc= LEFT identifier RIGHT -> ^( OP_SECTION_LABEL[$lc] identifier ) )
			// SemanticParser.g:38:4: lc= LEFT identifier RIGHT
			{
			lc=(Token)match(input,LEFT,FOLLOW_LEFT_in_section_def135);  
			stream_LEFT.add(lc);

			pushFollow(FOLLOW_identifier_in_section_def137);
			identifier9=gSleighParser.identifier();
			state._fsp--;

			stream_identifier.add(identifier9.getTree());
			RIGHT10=(Token)match(input,RIGHT,FOLLOW_RIGHT_in_section_def139);  
			stream_RIGHT.add(RIGHT10);

			// AST REWRITE
			// elements: identifier
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 38:29: -> ^( OP_SECTION_LABEL[$lc] identifier )
			{
				// SemanticParser.g:38:32: ^( OP_SECTION_LABEL[$lc] identifier )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SECTION_LABEL, lc), root_1);
				adaptor.addChild(root_1, stream_identifier.nextTree());
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
	// $ANTLR end "section_def"


	public static class statement_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "statement"
	// SemanticParser.g:41:1: statement : ( ( assignment | declaration | funcall | build_stmt | crossbuild_stmt | goto_stmt | cond_stmt | call_stmt | export | return_stmt |) lc= SEMI !| label | section_def | outererror );
	public final SleighParser_SemanticParser.statement_return statement() throws RecognitionException {
		SleighParser_SemanticParser.statement_return retval = new SleighParser_SemanticParser.statement_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		ParserRuleReturnScope assignment11 =null;
		ParserRuleReturnScope declaration12 =null;
		ParserRuleReturnScope funcall13 =null;
		ParserRuleReturnScope build_stmt14 =null;
		ParserRuleReturnScope crossbuild_stmt15 =null;
		ParserRuleReturnScope goto_stmt16 =null;
		ParserRuleReturnScope cond_stmt17 =null;
		ParserRuleReturnScope call_stmt18 =null;
		ParserRuleReturnScope export19 =null;
		ParserRuleReturnScope return_stmt20 =null;
		ParserRuleReturnScope label21 =null;
		ParserRuleReturnScope section_def22 =null;
		ParserRuleReturnScope outererror23 =null;

		CommonTree lc_tree=null;


				boolean empty = false;
			
		try {
			// SemanticParser.g:45:2: ( ( assignment | declaration | funcall | build_stmt | crossbuild_stmt | goto_stmt | cond_stmt | call_stmt | export | return_stmt |) lc= SEMI !| label | section_def | outererror )
			int alt4=4;
			switch ( input.LA(1) ) {
			case ASTERISK:
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
			case RES_IF:
			case SEMI:
				{
				alt4=1;
				}
				break;
			case LESS:
				{
				alt4=2;
				}
				break;
			case LEFT:
				{
				alt4=3;
				}
				break;
			case AMPERSAND:
			case ASSIGN:
			case BOOL_AND:
			case BOOL_OR:
			case BOOL_XOR:
			case CARET:
			case COLON:
			case COMMA:
			case EQUAL:
			case FDIV:
			case FEQUAL:
			case FGREAT:
			case FGREATEQUAL:
			case FLESS:
			case FLESSEQUAL:
			case FMINUS:
			case FMULT:
			case FNOTEQUAL:
			case FPLUS:
			case GREATEQUAL:
			case LESSEQUAL:
			case LPAREN:
			case MINUS:
			case NOTEQUAL:
			case PERCENT:
			case PIPE:
			case PLUS:
			case RBRACKET:
			case RPAREN:
			case SDIV:
			case SGREAT:
			case SGREATEQUAL:
			case SLASH:
			case SLESS:
			case SLESSEQUAL:
			case SREM:
			case SRIGHT:
			case TILDE:
				{
				alt4=4;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 4, 0, input);
				throw nvae;
			}
			switch (alt4) {
				case 1 :
					// SemanticParser.g:45:4: ( assignment | declaration | funcall | build_stmt | crossbuild_stmt | goto_stmt | cond_stmt | call_stmt | export | return_stmt |) lc= SEMI !
					{
					root_0 = (CommonTree)adaptor.nil();


					// SemanticParser.g:45:4: ( assignment | declaration | funcall | build_stmt | crossbuild_stmt | goto_stmt | cond_stmt | call_stmt | export | return_stmt |)
					int alt3=11;
					alt3 = dfa3.predict(input);
					switch (alt3) {
						case 1 :
							// SemanticParser.g:45:6: assignment
							{
							pushFollow(FOLLOW_assignment_in_statement167);
							assignment11=assignment();
							state._fsp--;

							adaptor.addChild(root_0, assignment11.getTree());

							}
							break;
						case 2 :
							// SemanticParser.g:46:5: declaration
							{
							pushFollow(FOLLOW_declaration_in_statement173);
							declaration12=declaration();
							state._fsp--;

							adaptor.addChild(root_0, declaration12.getTree());

							}
							break;
						case 3 :
							// SemanticParser.g:47:5: funcall
							{
							pushFollow(FOLLOW_funcall_in_statement179);
							funcall13=funcall();
							state._fsp--;

							adaptor.addChild(root_0, funcall13.getTree());

							}
							break;
						case 4 :
							// SemanticParser.g:48:5: build_stmt
							{
							pushFollow(FOLLOW_build_stmt_in_statement185);
							build_stmt14=build_stmt();
							state._fsp--;

							adaptor.addChild(root_0, build_stmt14.getTree());

							}
							break;
						case 5 :
							// SemanticParser.g:49:5: crossbuild_stmt
							{
							pushFollow(FOLLOW_crossbuild_stmt_in_statement191);
							crossbuild_stmt15=crossbuild_stmt();
							state._fsp--;

							adaptor.addChild(root_0, crossbuild_stmt15.getTree());

							}
							break;
						case 6 :
							// SemanticParser.g:50:5: goto_stmt
							{
							pushFollow(FOLLOW_goto_stmt_in_statement197);
							goto_stmt16=goto_stmt();
							state._fsp--;

							adaptor.addChild(root_0, goto_stmt16.getTree());

							}
							break;
						case 7 :
							// SemanticParser.g:51:5: cond_stmt
							{
							pushFollow(FOLLOW_cond_stmt_in_statement203);
							cond_stmt17=cond_stmt();
							state._fsp--;

							adaptor.addChild(root_0, cond_stmt17.getTree());

							}
							break;
						case 8 :
							// SemanticParser.g:52:5: call_stmt
							{
							pushFollow(FOLLOW_call_stmt_in_statement209);
							call_stmt18=call_stmt();
							state._fsp--;

							adaptor.addChild(root_0, call_stmt18.getTree());

							}
							break;
						case 9 :
							// SemanticParser.g:53:5: export
							{
							pushFollow(FOLLOW_export_in_statement215);
							export19=export();
							state._fsp--;

							adaptor.addChild(root_0, export19.getTree());

							}
							break;
						case 10 :
							// SemanticParser.g:54:5: return_stmt
							{
							pushFollow(FOLLOW_return_stmt_in_statement221);
							return_stmt20=return_stmt();
							state._fsp--;

							adaptor.addChild(root_0, return_stmt20.getTree());

							}
							break;
						case 11 :
							// SemanticParser.g:55:5: 
							{

											empty = true;
										
							}
							break;

					}

					lc=(Token)match(input,SEMI,FOLLOW_SEMI_in_statement235); 

								if(empty)
									bail("Empty statement at " + ((SleighToken) lc).getLocation());
							
					}
					break;
				case 2 :
					// SemanticParser.g:62:4: label
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_label_in_statement243);
					label21=label();
					state._fsp--;

					adaptor.addChild(root_0, label21.getTree());

					}
					break;
				case 3 :
					// SemanticParser.g:63:4: section_def
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_section_def_in_statement248);
					section_def22=section_def();
					state._fsp--;

					adaptor.addChild(root_0, section_def22.getTree());

					}
					break;
				case 4 :
					// SemanticParser.g:64:4: outererror
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_outererror_in_statement253);
					outererror23=outererror();
					state._fsp--;

					adaptor.addChild(root_0, outererror23.getTree());

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
	// $ANTLR end "statement"


	public static class outererror_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "outererror"
	// SemanticParser.g:67:1: outererror : (lc= EQUAL |lc= NOTEQUAL |lc= FEQUAL |lc= FNOTEQUAL |lc= LESSEQUAL |lc= GREATEQUAL |lc= SLESS |lc= SGREAT |lc= SLESSEQUAL |lc= SGREATEQUAL |lc= FLESS |lc= FGREAT |lc= FLESSEQUAL |lc= FGREATEQUAL |lc= ASSIGN |lc= COLON |lc= COMMA |lc= RBRACKET |lc= BOOL_OR |lc= BOOL_XOR |lc= BOOL_AND |lc= PIPE |lc= CARET |lc= AMPERSAND |lc= SRIGHT |lc= PLUS |lc= MINUS |lc= FPLUS |lc= FMINUS |lc= SLASH |lc= PERCENT |lc= SDIV |lc= SREM |lc= FMULT |lc= FDIV |lc= TILDE |lc= LPAREN |lc= RPAREN ) ;
	public final SleighParser_SemanticParser.outererror_return outererror() throws RecognitionException {
		SleighParser_SemanticParser.outererror_return retval = new SleighParser_SemanticParser.outererror_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;

		try {
			// SemanticParser.g:68:2: ( (lc= EQUAL |lc= NOTEQUAL |lc= FEQUAL |lc= FNOTEQUAL |lc= LESSEQUAL |lc= GREATEQUAL |lc= SLESS |lc= SGREAT |lc= SLESSEQUAL |lc= SGREATEQUAL |lc= FLESS |lc= FGREAT |lc= FLESSEQUAL |lc= FGREATEQUAL |lc= ASSIGN |lc= COLON |lc= COMMA |lc= RBRACKET |lc= BOOL_OR |lc= BOOL_XOR |lc= BOOL_AND |lc= PIPE |lc= CARET |lc= AMPERSAND |lc= SRIGHT |lc= PLUS |lc= MINUS |lc= FPLUS |lc= FMINUS |lc= SLASH |lc= PERCENT |lc= SDIV |lc= SREM |lc= FMULT |lc= FDIV |lc= TILDE |lc= LPAREN |lc= RPAREN ) )
			// SemanticParser.g:68:4: (lc= EQUAL |lc= NOTEQUAL |lc= FEQUAL |lc= FNOTEQUAL |lc= LESSEQUAL |lc= GREATEQUAL |lc= SLESS |lc= SGREAT |lc= SLESSEQUAL |lc= SGREATEQUAL |lc= FLESS |lc= FGREAT |lc= FLESSEQUAL |lc= FGREATEQUAL |lc= ASSIGN |lc= COLON |lc= COMMA |lc= RBRACKET |lc= BOOL_OR |lc= BOOL_XOR |lc= BOOL_AND |lc= PIPE |lc= CARET |lc= AMPERSAND |lc= SRIGHT |lc= PLUS |lc= MINUS |lc= FPLUS |lc= FMINUS |lc= SLASH |lc= PERCENT |lc= SDIV |lc= SREM |lc= FMULT |lc= FDIV |lc= TILDE |lc= LPAREN |lc= RPAREN )
			{
			root_0 = (CommonTree)adaptor.nil();


			// SemanticParser.g:68:4: (lc= EQUAL |lc= NOTEQUAL |lc= FEQUAL |lc= FNOTEQUAL |lc= LESSEQUAL |lc= GREATEQUAL |lc= SLESS |lc= SGREAT |lc= SLESSEQUAL |lc= SGREATEQUAL |lc= FLESS |lc= FGREAT |lc= FLESSEQUAL |lc= FGREATEQUAL |lc= ASSIGN |lc= COLON |lc= COMMA |lc= RBRACKET |lc= BOOL_OR |lc= BOOL_XOR |lc= BOOL_AND |lc= PIPE |lc= CARET |lc= AMPERSAND |lc= SRIGHT |lc= PLUS |lc= MINUS |lc= FPLUS |lc= FMINUS |lc= SLASH |lc= PERCENT |lc= SDIV |lc= SREM |lc= FMULT |lc= FDIV |lc= TILDE |lc= LPAREN |lc= RPAREN )
			int alt5=38;
			switch ( input.LA(1) ) {
			case EQUAL:
				{
				alt5=1;
				}
				break;
			case NOTEQUAL:
				{
				alt5=2;
				}
				break;
			case FEQUAL:
				{
				alt5=3;
				}
				break;
			case FNOTEQUAL:
				{
				alt5=4;
				}
				break;
			case LESSEQUAL:
				{
				alt5=5;
				}
				break;
			case GREATEQUAL:
				{
				alt5=6;
				}
				break;
			case SLESS:
				{
				alt5=7;
				}
				break;
			case SGREAT:
				{
				alt5=8;
				}
				break;
			case SLESSEQUAL:
				{
				alt5=9;
				}
				break;
			case SGREATEQUAL:
				{
				alt5=10;
				}
				break;
			case FLESS:
				{
				alt5=11;
				}
				break;
			case FGREAT:
				{
				alt5=12;
				}
				break;
			case FLESSEQUAL:
				{
				alt5=13;
				}
				break;
			case FGREATEQUAL:
				{
				alt5=14;
				}
				break;
			case ASSIGN:
				{
				alt5=15;
				}
				break;
			case COLON:
				{
				alt5=16;
				}
				break;
			case COMMA:
				{
				alt5=17;
				}
				break;
			case RBRACKET:
				{
				alt5=18;
				}
				break;
			case BOOL_OR:
				{
				alt5=19;
				}
				break;
			case BOOL_XOR:
				{
				alt5=20;
				}
				break;
			case BOOL_AND:
				{
				alt5=21;
				}
				break;
			case PIPE:
				{
				alt5=22;
				}
				break;
			case CARET:
				{
				alt5=23;
				}
				break;
			case AMPERSAND:
				{
				alt5=24;
				}
				break;
			case SRIGHT:
				{
				alt5=25;
				}
				break;
			case PLUS:
				{
				alt5=26;
				}
				break;
			case MINUS:
				{
				alt5=27;
				}
				break;
			case FPLUS:
				{
				alt5=28;
				}
				break;
			case FMINUS:
				{
				alt5=29;
				}
				break;
			case SLASH:
				{
				alt5=30;
				}
				break;
			case PERCENT:
				{
				alt5=31;
				}
				break;
			case SDIV:
				{
				alt5=32;
				}
				break;
			case SREM:
				{
				alt5=33;
				}
				break;
			case FMULT:
				{
				alt5=34;
				}
				break;
			case FDIV:
				{
				alt5=35;
				}
				break;
			case TILDE:
				{
				alt5=36;
				}
				break;
			case LPAREN:
				{
				alt5=37;
				}
				break;
			case RPAREN:
				{
				alt5=38;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 5, 0, input);
				throw nvae;
			}
			switch (alt5) {
				case 1 :
					// SemanticParser.g:68:5: lc= EQUAL
					{
					lc=(Token)match(input,EQUAL,FOLLOW_EQUAL_in_outererror267); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 2 :
					// SemanticParser.g:69:4: lc= NOTEQUAL
					{
					lc=(Token)match(input,NOTEQUAL,FOLLOW_NOTEQUAL_in_outererror274); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 3 :
					// SemanticParser.g:70:4: lc= FEQUAL
					{
					lc=(Token)match(input,FEQUAL,FOLLOW_FEQUAL_in_outererror281); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 4 :
					// SemanticParser.g:71:4: lc= FNOTEQUAL
					{
					lc=(Token)match(input,FNOTEQUAL,FOLLOW_FNOTEQUAL_in_outererror288); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 5 :
					// SemanticParser.g:72:4: lc= LESSEQUAL
					{
					lc=(Token)match(input,LESSEQUAL,FOLLOW_LESSEQUAL_in_outererror295); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 6 :
					// SemanticParser.g:73:4: lc= GREATEQUAL
					{
					lc=(Token)match(input,GREATEQUAL,FOLLOW_GREATEQUAL_in_outererror302); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 7 :
					// SemanticParser.g:74:4: lc= SLESS
					{
					lc=(Token)match(input,SLESS,FOLLOW_SLESS_in_outererror309); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 8 :
					// SemanticParser.g:75:4: lc= SGREAT
					{
					lc=(Token)match(input,SGREAT,FOLLOW_SGREAT_in_outererror316); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 9 :
					// SemanticParser.g:76:4: lc= SLESSEQUAL
					{
					lc=(Token)match(input,SLESSEQUAL,FOLLOW_SLESSEQUAL_in_outererror323); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 10 :
					// SemanticParser.g:77:4: lc= SGREATEQUAL
					{
					lc=(Token)match(input,SGREATEQUAL,FOLLOW_SGREATEQUAL_in_outererror330); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 11 :
					// SemanticParser.g:78:4: lc= FLESS
					{
					lc=(Token)match(input,FLESS,FOLLOW_FLESS_in_outererror337); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 12 :
					// SemanticParser.g:79:4: lc= FGREAT
					{
					lc=(Token)match(input,FGREAT,FOLLOW_FGREAT_in_outererror344); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 13 :
					// SemanticParser.g:80:4: lc= FLESSEQUAL
					{
					lc=(Token)match(input,FLESSEQUAL,FOLLOW_FLESSEQUAL_in_outererror351); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 14 :
					// SemanticParser.g:81:4: lc= FGREATEQUAL
					{
					lc=(Token)match(input,FGREATEQUAL,FOLLOW_FGREATEQUAL_in_outererror358); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 15 :
					// SemanticParser.g:82:4: lc= ASSIGN
					{
					lc=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_outererror365); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 16 :
					// SemanticParser.g:83:4: lc= COLON
					{
					lc=(Token)match(input,COLON,FOLLOW_COLON_in_outererror372); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 17 :
					// SemanticParser.g:84:4: lc= COMMA
					{
					lc=(Token)match(input,COMMA,FOLLOW_COMMA_in_outererror379); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 18 :
					// SemanticParser.g:85:4: lc= RBRACKET
					{
					lc=(Token)match(input,RBRACKET,FOLLOW_RBRACKET_in_outererror386); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 19 :
					// SemanticParser.g:86:4: lc= BOOL_OR
					{
					lc=(Token)match(input,BOOL_OR,FOLLOW_BOOL_OR_in_outererror393); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 20 :
					// SemanticParser.g:87:4: lc= BOOL_XOR
					{
					lc=(Token)match(input,BOOL_XOR,FOLLOW_BOOL_XOR_in_outererror400); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 21 :
					// SemanticParser.g:88:4: lc= BOOL_AND
					{
					lc=(Token)match(input,BOOL_AND,FOLLOW_BOOL_AND_in_outererror407); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 22 :
					// SemanticParser.g:89:4: lc= PIPE
					{
					lc=(Token)match(input,PIPE,FOLLOW_PIPE_in_outererror414); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 23 :
					// SemanticParser.g:90:4: lc= CARET
					{
					lc=(Token)match(input,CARET,FOLLOW_CARET_in_outererror421); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 24 :
					// SemanticParser.g:91:4: lc= AMPERSAND
					{
					lc=(Token)match(input,AMPERSAND,FOLLOW_AMPERSAND_in_outererror428); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 25 :
					// SemanticParser.g:92:4: lc= SRIGHT
					{
					lc=(Token)match(input,SRIGHT,FOLLOW_SRIGHT_in_outererror435); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 26 :
					// SemanticParser.g:93:4: lc= PLUS
					{
					lc=(Token)match(input,PLUS,FOLLOW_PLUS_in_outererror442); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 27 :
					// SemanticParser.g:94:4: lc= MINUS
					{
					lc=(Token)match(input,MINUS,FOLLOW_MINUS_in_outererror449); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 28 :
					// SemanticParser.g:95:4: lc= FPLUS
					{
					lc=(Token)match(input,FPLUS,FOLLOW_FPLUS_in_outererror456); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 29 :
					// SemanticParser.g:96:4: lc= FMINUS
					{
					lc=(Token)match(input,FMINUS,FOLLOW_FMINUS_in_outererror463); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 30 :
					// SemanticParser.g:97:4: lc= SLASH
					{
					lc=(Token)match(input,SLASH,FOLLOW_SLASH_in_outererror470); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 31 :
					// SemanticParser.g:98:4: lc= PERCENT
					{
					lc=(Token)match(input,PERCENT,FOLLOW_PERCENT_in_outererror477); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 32 :
					// SemanticParser.g:99:4: lc= SDIV
					{
					lc=(Token)match(input,SDIV,FOLLOW_SDIV_in_outererror484); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 33 :
					// SemanticParser.g:100:4: lc= SREM
					{
					lc=(Token)match(input,SREM,FOLLOW_SREM_in_outererror491); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 34 :
					// SemanticParser.g:101:4: lc= FMULT
					{
					lc=(Token)match(input,FMULT,FOLLOW_FMULT_in_outererror498); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 35 :
					// SemanticParser.g:102:4: lc= FDIV
					{
					lc=(Token)match(input,FDIV,FOLLOW_FDIV_in_outererror505); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 36 :
					// SemanticParser.g:103:4: lc= TILDE
					{
					lc=(Token)match(input,TILDE,FOLLOW_TILDE_in_outererror512); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 37 :
					// SemanticParser.g:104:4: lc= LPAREN
					{
					lc=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_outererror519); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;
				case 38 :
					// SemanticParser.g:105:4: lc= RPAREN
					{
					lc=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_outererror526); 
					lc_tree = (CommonTree)adaptor.create(lc);
					adaptor.addChild(root_0, lc_tree);

					}
					break;

			}


						UnwantedTokenException ute = new UnwantedTokenException(0, input);
						ute.token = lc;
						reportError(ute);
				
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
	// $ANTLR end "outererror"


	public static class assignment_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "assignment"
	// SemanticParser.g:112:1: assignment : (lb= KEY_LOCAL lvalue lc= ASSIGN expr -> ^( OP_LOCAL[$lb] OP_ASSIGN[$lc] lvalue expr ) | lvalue lc= ASSIGN expr -> ^( OP_ASSIGN[$lc] lvalue expr ) );
	public final SleighParser_SemanticParser.assignment_return assignment() throws RecognitionException {
		SleighParser_SemanticParser.assignment_return retval = new SleighParser_SemanticParser.assignment_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lb=null;
		Token lc=null;
		ParserRuleReturnScope lvalue24 =null;
		ParserRuleReturnScope expr25 =null;
		ParserRuleReturnScope lvalue26 =null;
		ParserRuleReturnScope expr27 =null;

		CommonTree lb_tree=null;
		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_KEY_LOCAL=new RewriteRuleTokenStream(adaptor,"token KEY_LOCAL");
		RewriteRuleTokenStream stream_ASSIGN=new RewriteRuleTokenStream(adaptor,"token ASSIGN");
		RewriteRuleSubtreeStream stream_lvalue=new RewriteRuleSubtreeStream(adaptor,"rule lvalue");
		RewriteRuleSubtreeStream stream_expr=new RewriteRuleSubtreeStream(adaptor,"rule expr");

		try {
			// SemanticParser.g:113:2: (lb= KEY_LOCAL lvalue lc= ASSIGN expr -> ^( OP_LOCAL[$lb] OP_ASSIGN[$lc] lvalue expr ) | lvalue lc= ASSIGN expr -> ^( OP_ASSIGN[$lc] lvalue expr ) )
			int alt6=2;
			int LA6_0 = input.LA(1);
			if ( (LA6_0==KEY_LOCAL) ) {
				int LA6_1 = input.LA(2);
				if ( (LA6_1==ASTERISK||(LA6_1 >= IDENTIFIER && LA6_1 <= KEY_WORDSIZE)) ) {
					alt6=1;
				}
				else if ( (LA6_1==ASSIGN||LA6_1==COLON||LA6_1==LBRACKET) ) {
					alt6=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 6, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

			}
			else if ( (LA6_0==ASTERISK||(LA6_0 >= IDENTIFIER && LA6_0 <= KEY_LITTLE)||(LA6_0 >= KEY_MACRO && LA6_0 <= KEY_WORDSIZE)) ) {
				alt6=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 6, 0, input);
				throw nvae;
			}

			switch (alt6) {
				case 1 :
					// SemanticParser.g:113:4: lb= KEY_LOCAL lvalue lc= ASSIGN expr
					{
					lb=(Token)match(input,KEY_LOCAL,FOLLOW_KEY_LOCAL_in_assignment542);  
					stream_KEY_LOCAL.add(lb);

					pushFollow(FOLLOW_lvalue_in_assignment544);
					lvalue24=lvalue();
					state._fsp--;

					stream_lvalue.add(lvalue24.getTree());
					lc=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_assignment548);  
					stream_ASSIGN.add(lc);

					pushFollow(FOLLOW_expr_in_assignment550);
					expr25=expr();
					state._fsp--;

					stream_expr.add(expr25.getTree());
					// AST REWRITE
					// elements: expr, lvalue
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 113:39: -> ^( OP_LOCAL[$lb] OP_ASSIGN[$lc] lvalue expr )
					{
						// SemanticParser.g:113:42: ^( OP_LOCAL[$lb] OP_ASSIGN[$lc] lvalue expr )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_LOCAL, lb), root_1);
						adaptor.addChild(root_1, (CommonTree)adaptor.create(OP_ASSIGN, lc));
						adaptor.addChild(root_1, stream_lvalue.nextTree());
						adaptor.addChild(root_1, stream_expr.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 2 :
					// SemanticParser.g:114:4: lvalue lc= ASSIGN expr
					{
					pushFollow(FOLLOW_lvalue_in_assignment569);
					lvalue26=lvalue();
					state._fsp--;

					stream_lvalue.add(lvalue26.getTree());
					lc=(Token)match(input,ASSIGN,FOLLOW_ASSIGN_in_assignment573);  
					stream_ASSIGN.add(lc);

					pushFollow(FOLLOW_expr_in_assignment575);
					expr27=expr();
					state._fsp--;

					stream_expr.add(expr27.getTree());
					// AST REWRITE
					// elements: lvalue, expr
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 114:26: -> ^( OP_ASSIGN[$lc] lvalue expr )
					{
						// SemanticParser.g:114:29: ^( OP_ASSIGN[$lc] lvalue expr )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_ASSIGN, lc), root_1);
						adaptor.addChild(root_1, stream_lvalue.nextTree());
						adaptor.addChild(root_1, stream_expr.nextTree());
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
	// $ANTLR end "assignment"


	public static class declaration_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "declaration"
	// SemanticParser.g:117:1: declaration : (lb= KEY_LOCAL identifier lc= COLON constant -> ^( OP_LOCAL[$lb] identifier constant ) |lb= KEY_LOCAL identifier -> ^( OP_LOCAL[$lb] identifier ) );
	public final SleighParser_SemanticParser.declaration_return declaration() throws RecognitionException {
		SleighParser_SemanticParser.declaration_return retval = new SleighParser_SemanticParser.declaration_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lb=null;
		Token lc=null;
		ParserRuleReturnScope identifier28 =null;
		ParserRuleReturnScope constant29 =null;
		ParserRuleReturnScope identifier30 =null;

		CommonTree lb_tree=null;
		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_KEY_LOCAL=new RewriteRuleTokenStream(adaptor,"token KEY_LOCAL");
		RewriteRuleTokenStream stream_COLON=new RewriteRuleTokenStream(adaptor,"token COLON");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_constant=new RewriteRuleSubtreeStream(adaptor,"rule constant");

		try {
			// SemanticParser.g:118:2: (lb= KEY_LOCAL identifier lc= COLON constant -> ^( OP_LOCAL[$lb] identifier constant ) |lb= KEY_LOCAL identifier -> ^( OP_LOCAL[$lb] identifier ) )
			int alt7=2;
			int LA7_0 = input.LA(1);
			if ( (LA7_0==KEY_LOCAL) ) {
				switch ( input.LA(2) ) {
				case IDENTIFIER:
					{
					int LA7_2 = input.LA(3);
					if ( (LA7_2==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_2==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 2, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_ALIGNMENT:
					{
					int LA7_3 = input.LA(3);
					if ( (LA7_3==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_3==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 3, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_ATTACH:
					{
					int LA7_4 = input.LA(3);
					if ( (LA7_4==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_4==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 4, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_BIG:
					{
					int LA7_5 = input.LA(3);
					if ( (LA7_5==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_5==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 5, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_BITRANGE:
					{
					int LA7_6 = input.LA(3);
					if ( (LA7_6==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_6==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 6, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_BUILD:
					{
					int LA7_7 = input.LA(3);
					if ( (LA7_7==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_7==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 7, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_CALL:
					{
					int LA7_8 = input.LA(3);
					if ( (LA7_8==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_8==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 8, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_CONTEXT:
					{
					int LA7_9 = input.LA(3);
					if ( (LA7_9==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_9==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 9, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_CROSSBUILD:
					{
					int LA7_10 = input.LA(3);
					if ( (LA7_10==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_10==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 10, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_DEC:
					{
					int LA7_11 = input.LA(3);
					if ( (LA7_11==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_11==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 11, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_DEFAULT:
					{
					int LA7_12 = input.LA(3);
					if ( (LA7_12==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_12==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 12, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_DEFINE:
					{
					int LA7_13 = input.LA(3);
					if ( (LA7_13==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_13==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 13, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_ENDIAN:
					{
					int LA7_14 = input.LA(3);
					if ( (LA7_14==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_14==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 14, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_EXPORT:
					{
					int LA7_15 = input.LA(3);
					if ( (LA7_15==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_15==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 15, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_GOTO:
					{
					int LA7_16 = input.LA(3);
					if ( (LA7_16==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_16==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 16, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_HEX:
					{
					int LA7_17 = input.LA(3);
					if ( (LA7_17==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_17==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 17, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_LITTLE:
					{
					int LA7_18 = input.LA(3);
					if ( (LA7_18==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_18==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 18, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_LOCAL:
					{
					int LA7_19 = input.LA(3);
					if ( (LA7_19==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_19==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 19, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_MACRO:
					{
					int LA7_20 = input.LA(3);
					if ( (LA7_20==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_20==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 20, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_NAMES:
					{
					int LA7_21 = input.LA(3);
					if ( (LA7_21==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_21==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 21, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_NOFLOW:
					{
					int LA7_22 = input.LA(3);
					if ( (LA7_22==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_22==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 22, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_OFFSET:
					{
					int LA7_23 = input.LA(3);
					if ( (LA7_23==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_23==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 23, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_PCODEOP:
					{
					int LA7_24 = input.LA(3);
					if ( (LA7_24==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_24==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 24, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_RETURN:
					{
					int LA7_25 = input.LA(3);
					if ( (LA7_25==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_25==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 25, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_SIGNED:
					{
					int LA7_26 = input.LA(3);
					if ( (LA7_26==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_26==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 26, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_SIZE:
					{
					int LA7_27 = input.LA(3);
					if ( (LA7_27==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_27==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 27, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_SPACE:
					{
					int LA7_28 = input.LA(3);
					if ( (LA7_28==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_28==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 28, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_TOKEN:
					{
					int LA7_29 = input.LA(3);
					if ( (LA7_29==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_29==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 29, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_TYPE:
					{
					int LA7_30 = input.LA(3);
					if ( (LA7_30==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_30==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 30, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_UNIMPL:
					{
					int LA7_31 = input.LA(3);
					if ( (LA7_31==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_31==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 31, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_VALUES:
					{
					int LA7_32 = input.LA(3);
					if ( (LA7_32==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_32==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 32, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_VARIABLES:
					{
					int LA7_33 = input.LA(3);
					if ( (LA7_33==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_33==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 33, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				case KEY_WORDSIZE:
					{
					int LA7_34 = input.LA(3);
					if ( (LA7_34==COLON) ) {
						alt7=1;
					}
					else if ( (LA7_34==SEMI) ) {
						alt7=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 7, 34, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 7, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 7, 0, input);
				throw nvae;
			}

			switch (alt7) {
				case 1 :
					// SemanticParser.g:118:4: lb= KEY_LOCAL identifier lc= COLON constant
					{
					lb=(Token)match(input,KEY_LOCAL,FOLLOW_KEY_LOCAL_in_declaration599);  
					stream_KEY_LOCAL.add(lb);

					pushFollow(FOLLOW_identifier_in_declaration601);
					identifier28=gSleighParser.identifier();
					state._fsp--;

					stream_identifier.add(identifier28.getTree());
					lc=(Token)match(input,COLON,FOLLOW_COLON_in_declaration605);  
					stream_COLON.add(lc);

					pushFollow(FOLLOW_constant_in_declaration607);
					constant29=constant();
					state._fsp--;

					stream_constant.add(constant29.getTree());
					// AST REWRITE
					// elements: identifier, constant
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 118:46: -> ^( OP_LOCAL[$lb] identifier constant )
					{
						// SemanticParser.g:118:49: ^( OP_LOCAL[$lb] identifier constant )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_LOCAL, lb), root_1);
						adaptor.addChild(root_1, stream_identifier.nextTree());
						adaptor.addChild(root_1, stream_constant.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 2 :
					// SemanticParser.g:119:4: lb= KEY_LOCAL identifier
					{
					lb=(Token)match(input,KEY_LOCAL,FOLLOW_KEY_LOCAL_in_declaration625);  
					stream_KEY_LOCAL.add(lb);

					pushFollow(FOLLOW_identifier_in_declaration627);
					identifier30=gSleighParser.identifier();
					state._fsp--;

					stream_identifier.add(identifier30.getTree());
					// AST REWRITE
					// elements: identifier
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 119:28: -> ^( OP_LOCAL[$lb] identifier )
					{
						// SemanticParser.g:119:31: ^( OP_LOCAL[$lb] identifier )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_LOCAL, lb), root_1);
						adaptor.addChild(root_1, stream_identifier.nextTree());
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
	// $ANTLR end "declaration"


	public static class lvalue_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "lvalue"
	// SemanticParser.g:122:1: lvalue : ( sembitrange | identifier lc= COLON constant -> ^( OP_DECLARATIVE_SIZE[$lc] identifier constant ) | identifier | sizedstar ^ expr );
	public final SleighParser_SemanticParser.lvalue_return lvalue() throws RecognitionException {
		SleighParser_SemanticParser.lvalue_return retval = new SleighParser_SemanticParser.lvalue_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		ParserRuleReturnScope sembitrange31 =null;
		ParserRuleReturnScope identifier32 =null;
		ParserRuleReturnScope constant33 =null;
		ParserRuleReturnScope identifier34 =null;
		ParserRuleReturnScope sizedstar35 =null;
		ParserRuleReturnScope expr36 =null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_COLON=new RewriteRuleTokenStream(adaptor,"token COLON");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_constant=new RewriteRuleSubtreeStream(adaptor,"rule constant");

		try {
			// SemanticParser.g:123:2: ( sembitrange | identifier lc= COLON constant -> ^( OP_DECLARATIVE_SIZE[$lc] identifier constant ) | identifier | sizedstar ^ expr )
			int alt8=4;
			switch ( input.LA(1) ) {
			case IDENTIFIER:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_ALIGNMENT:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 2, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_ATTACH:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 3, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_BIG:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 4, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_BITRANGE:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 5, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_BUILD:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 6, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_CALL:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 7, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_CONTEXT:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 8, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_CROSSBUILD:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 9, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_DEC:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 10, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_DEFAULT:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 11, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_DEFINE:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 12, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_ENDIAN:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 13, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_EXPORT:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 14, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_GOTO:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 15, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_HEX:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 16, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_LITTLE:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 17, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_LOCAL:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 18, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_MACRO:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 19, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_NAMES:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 20, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_NOFLOW:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 21, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_OFFSET:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 22, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_PCODEOP:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 23, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_RETURN:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 24, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_SIGNED:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 25, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_SIZE:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 26, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_SPACE:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 27, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_TOKEN:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 28, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_TYPE:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 29, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_UNIMPL:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 30, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_VALUES:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 31, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_VARIABLES:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 32, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case KEY_WORDSIZE:
				{
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					alt8=1;
					}
					break;
				case COLON:
					{
					alt8=2;
					}
					break;
				case ASSIGN:
					{
					alt8=3;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 8, 33, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
				}
				break;
			case ASTERISK:
				{
				alt8=4;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 8, 0, input);
				throw nvae;
			}
			switch (alt8) {
				case 1 :
					// SemanticParser.g:123:4: sembitrange
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_sembitrange_in_lvalue647);
					sembitrange31=sembitrange();
					state._fsp--;

					adaptor.addChild(root_0, sembitrange31.getTree());

					}
					break;
				case 2 :
					// SemanticParser.g:124:4: identifier lc= COLON constant
					{
					pushFollow(FOLLOW_identifier_in_lvalue652);
					identifier32=gSleighParser.identifier();
					state._fsp--;

					stream_identifier.add(identifier32.getTree());
					lc=(Token)match(input,COLON,FOLLOW_COLON_in_lvalue656);  
					stream_COLON.add(lc);

					pushFollow(FOLLOW_constant_in_lvalue658);
					constant33=constant();
					state._fsp--;

					stream_constant.add(constant33.getTree());
					// AST REWRITE
					// elements: identifier, constant
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 124:33: -> ^( OP_DECLARATIVE_SIZE[$lc] identifier constant )
					{
						// SemanticParser.g:124:36: ^( OP_DECLARATIVE_SIZE[$lc] identifier constant )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_DECLARATIVE_SIZE, lc), root_1);
						adaptor.addChild(root_1, stream_identifier.nextTree());
						adaptor.addChild(root_1, stream_constant.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 3 :
					// SemanticParser.g:125:4: identifier
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_identifier_in_lvalue674);
					identifier34=gSleighParser.identifier();
					state._fsp--;

					adaptor.addChild(root_0, identifier34.getTree());

					}
					break;
				case 4 :
					// SemanticParser.g:126:4: sizedstar ^ expr
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_sizedstar_in_lvalue679);
					sizedstar35=sizedstar();
					state._fsp--;

					root_0 = (CommonTree)adaptor.becomeRoot(sizedstar35.getTree(), root_0);
					pushFollow(FOLLOW_expr_in_lvalue682);
					expr36=expr();
					state._fsp--;

					adaptor.addChild(root_0, expr36.getTree());

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
	// $ANTLR end "lvalue"


	public static class sembitrange_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "sembitrange"
	// SemanticParser.g:129:1: sembitrange : identifier lc= LBRACKET a= constant COMMA b= constant RBRACKET -> ^( OP_BITRANGE[$lc] identifier $a $b) ;
	public final SleighParser_SemanticParser.sembitrange_return sembitrange() throws RecognitionException {
		SleighParser_SemanticParser.sembitrange_return retval = new SleighParser_SemanticParser.sembitrange_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token COMMA38=null;
		Token RBRACKET39=null;
		ParserRuleReturnScope a =null;
		ParserRuleReturnScope b =null;
		ParserRuleReturnScope identifier37 =null;

		CommonTree lc_tree=null;
		CommonTree COMMA38_tree=null;
		CommonTree RBRACKET39_tree=null;
		RewriteRuleTokenStream stream_COMMA=new RewriteRuleTokenStream(adaptor,"token COMMA");
		RewriteRuleTokenStream stream_LBRACKET=new RewriteRuleTokenStream(adaptor,"token LBRACKET");
		RewriteRuleTokenStream stream_RBRACKET=new RewriteRuleTokenStream(adaptor,"token RBRACKET");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_constant=new RewriteRuleSubtreeStream(adaptor,"rule constant");

		try {
			// SemanticParser.g:130:2: ( identifier lc= LBRACKET a= constant COMMA b= constant RBRACKET -> ^( OP_BITRANGE[$lc] identifier $a $b) )
			// SemanticParser.g:130:4: identifier lc= LBRACKET a= constant COMMA b= constant RBRACKET
			{
			pushFollow(FOLLOW_identifier_in_sembitrange693);
			identifier37=gSleighParser.identifier();
			state._fsp--;

			stream_identifier.add(identifier37.getTree());
			lc=(Token)match(input,LBRACKET,FOLLOW_LBRACKET_in_sembitrange697);  
			stream_LBRACKET.add(lc);

			pushFollow(FOLLOW_constant_in_sembitrange701);
			a=constant();
			state._fsp--;

			stream_constant.add(a.getTree());
			COMMA38=(Token)match(input,COMMA,FOLLOW_COMMA_in_sembitrange703);  
			stream_COMMA.add(COMMA38);

			pushFollow(FOLLOW_constant_in_sembitrange707);
			b=constant();
			state._fsp--;

			stream_constant.add(b.getTree());
			RBRACKET39=(Token)match(input,RBRACKET,FOLLOW_RBRACKET_in_sembitrange709);  
			stream_RBRACKET.add(RBRACKET39);

			// AST REWRITE
			// elements: identifier, a, b
			// token labels: 
			// rule labels: a, b, retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_a=new RewriteRuleSubtreeStream(adaptor,"rule a",a!=null?a.getTree():null);
			RewriteRuleSubtreeStream stream_b=new RewriteRuleSubtreeStream(adaptor,"rule b",b!=null?b.getTree():null);
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 130:64: -> ^( OP_BITRANGE[$lc] identifier $a $b)
			{
				// SemanticParser.g:130:67: ^( OP_BITRANGE[$lc] identifier $a $b)
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_BITRANGE, lc), root_1);
				adaptor.addChild(root_1, stream_identifier.nextTree());
				adaptor.addChild(root_1, stream_a.nextTree());
				adaptor.addChild(root_1, stream_b.nextTree());
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
	// $ANTLR end "sembitrange"


	public static class sizedstar_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "sizedstar"
	// SemanticParser.g:133:1: sizedstar : (lc= ASTERISK LBRACKET identifier RBRACKET COLON constant -> ^( OP_DEREFERENCE[$lc] identifier constant ) |lc= ASTERISK LBRACKET identifier RBRACKET -> ^( OP_DEREFERENCE[$lc] identifier ) |lc= ASTERISK COLON constant -> ^( OP_DEREFERENCE[$lc] constant ) |lc= ASTERISK -> ^( OP_DEREFERENCE[$lc] ) );
	public final SleighParser_SemanticParser.sizedstar_return sizedstar() throws RecognitionException {
		SleighParser_SemanticParser.sizedstar_return retval = new SleighParser_SemanticParser.sizedstar_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token LBRACKET40=null;
		Token RBRACKET42=null;
		Token COLON43=null;
		Token LBRACKET45=null;
		Token RBRACKET47=null;
		Token COLON48=null;
		ParserRuleReturnScope identifier41 =null;
		ParserRuleReturnScope constant44 =null;
		ParserRuleReturnScope identifier46 =null;
		ParserRuleReturnScope constant49 =null;

		CommonTree lc_tree=null;
		CommonTree LBRACKET40_tree=null;
		CommonTree RBRACKET42_tree=null;
		CommonTree COLON43_tree=null;
		CommonTree LBRACKET45_tree=null;
		CommonTree RBRACKET47_tree=null;
		CommonTree COLON48_tree=null;
		RewriteRuleTokenStream stream_ASTERISK=new RewriteRuleTokenStream(adaptor,"token ASTERISK");
		RewriteRuleTokenStream stream_LBRACKET=new RewriteRuleTokenStream(adaptor,"token LBRACKET");
		RewriteRuleTokenStream stream_RBRACKET=new RewriteRuleTokenStream(adaptor,"token RBRACKET");
		RewriteRuleTokenStream stream_COLON=new RewriteRuleTokenStream(adaptor,"token COLON");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_constant=new RewriteRuleSubtreeStream(adaptor,"rule constant");

		try {
			// SemanticParser.g:134:2: (lc= ASTERISK LBRACKET identifier RBRACKET COLON constant -> ^( OP_DEREFERENCE[$lc] identifier constant ) |lc= ASTERISK LBRACKET identifier RBRACKET -> ^( OP_DEREFERENCE[$lc] identifier ) |lc= ASTERISK COLON constant -> ^( OP_DEREFERENCE[$lc] constant ) |lc= ASTERISK -> ^( OP_DEREFERENCE[$lc] ) )
			int alt9=4;
			int LA9_0 = input.LA(1);
			if ( (LA9_0==ASTERISK) ) {
				switch ( input.LA(2) ) {
				case LBRACKET:
					{
					switch ( input.LA(3) ) {
					case IDENTIFIER:
						{
						int LA9_5 = input.LA(4);
						if ( (LA9_5==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 5, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_ALIGNMENT:
						{
						int LA9_6 = input.LA(4);
						if ( (LA9_6==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 6, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_ATTACH:
						{
						int LA9_7 = input.LA(4);
						if ( (LA9_7==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 7, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_BIG:
						{
						int LA9_8 = input.LA(4);
						if ( (LA9_8==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 8, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_BITRANGE:
						{
						int LA9_9 = input.LA(4);
						if ( (LA9_9==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 9, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_BUILD:
						{
						int LA9_10 = input.LA(4);
						if ( (LA9_10==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 10, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_CALL:
						{
						int LA9_11 = input.LA(4);
						if ( (LA9_11==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 11, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_CONTEXT:
						{
						int LA9_12 = input.LA(4);
						if ( (LA9_12==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 12, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_CROSSBUILD:
						{
						int LA9_13 = input.LA(4);
						if ( (LA9_13==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 13, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_DEC:
						{
						int LA9_14 = input.LA(4);
						if ( (LA9_14==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 14, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_DEFAULT:
						{
						int LA9_15 = input.LA(4);
						if ( (LA9_15==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 15, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_DEFINE:
						{
						int LA9_16 = input.LA(4);
						if ( (LA9_16==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 16, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_ENDIAN:
						{
						int LA9_17 = input.LA(4);
						if ( (LA9_17==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 17, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_EXPORT:
						{
						int LA9_18 = input.LA(4);
						if ( (LA9_18==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 18, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_GOTO:
						{
						int LA9_19 = input.LA(4);
						if ( (LA9_19==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 19, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_HEX:
						{
						int LA9_20 = input.LA(4);
						if ( (LA9_20==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 20, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_LITTLE:
						{
						int LA9_21 = input.LA(4);
						if ( (LA9_21==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 21, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_LOCAL:
						{
						int LA9_22 = input.LA(4);
						if ( (LA9_22==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 22, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_MACRO:
						{
						int LA9_23 = input.LA(4);
						if ( (LA9_23==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 23, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_NAMES:
						{
						int LA9_24 = input.LA(4);
						if ( (LA9_24==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 24, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_NOFLOW:
						{
						int LA9_25 = input.LA(4);
						if ( (LA9_25==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 25, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_OFFSET:
						{
						int LA9_26 = input.LA(4);
						if ( (LA9_26==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 26, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_PCODEOP:
						{
						int LA9_27 = input.LA(4);
						if ( (LA9_27==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 27, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_RETURN:
						{
						int LA9_28 = input.LA(4);
						if ( (LA9_28==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 28, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_SIGNED:
						{
						int LA9_29 = input.LA(4);
						if ( (LA9_29==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 29, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_SIZE:
						{
						int LA9_30 = input.LA(4);
						if ( (LA9_30==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 30, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_SPACE:
						{
						int LA9_31 = input.LA(4);
						if ( (LA9_31==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 31, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_TOKEN:
						{
						int LA9_32 = input.LA(4);
						if ( (LA9_32==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 32, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_TYPE:
						{
						int LA9_33 = input.LA(4);
						if ( (LA9_33==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 33, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_UNIMPL:
						{
						int LA9_34 = input.LA(4);
						if ( (LA9_34==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 34, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_VALUES:
						{
						int LA9_35 = input.LA(4);
						if ( (LA9_35==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 35, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_VARIABLES:
						{
						int LA9_36 = input.LA(4);
						if ( (LA9_36==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 36, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					case KEY_WORDSIZE:
						{
						int LA9_37 = input.LA(4);
						if ( (LA9_37==RBRACKET) ) {
							int LA9_38 = input.LA(5);
							if ( (LA9_38==COLON) ) {
								alt9=1;
							}
							else if ( (LA9_38==AMPERSAND||LA9_38==ASTERISK||LA9_38==BIN_INT||LA9_38==DEC_INT||LA9_38==EXCLAIM||LA9_38==FMINUS||(LA9_38 >= HEX_INT && LA9_38 <= KEY_WORDSIZE)||(LA9_38 >= LPAREN && LA9_38 <= MINUS)||LA9_38==TILDE) ) {
								alt9=2;
							}

							else {
								int nvaeMark = input.mark();
								try {
									for (int nvaeConsume = 0; nvaeConsume < 5 - 1; nvaeConsume++) {
										input.consume();
									}
									NoViableAltException nvae =
										new NoViableAltException("", 9, 38, input);
									throw nvae;
								} finally {
									input.rewind(nvaeMark);
								}
							}

						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 9, 37, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

						}
						break;
					default:
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 9, 2, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}
					}
					break;
				case COLON:
					{
					alt9=3;
					}
					break;
				case AMPERSAND:
				case ASTERISK:
				case BIN_INT:
				case DEC_INT:
				case EXCLAIM:
				case FMINUS:
				case HEX_INT:
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
				case LPAREN:
				case MINUS:
				case TILDE:
					{
					alt9=4;
					}
					break;
				default:
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 9, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 9, 0, input);
				throw nvae;
			}

			switch (alt9) {
				case 1 :
					// SemanticParser.g:134:4: lc= ASTERISK LBRACKET identifier RBRACKET COLON constant
					{
					lc=(Token)match(input,ASTERISK,FOLLOW_ASTERISK_in_sizedstar737);  
					stream_ASTERISK.add(lc);

					LBRACKET40=(Token)match(input,LBRACKET,FOLLOW_LBRACKET_in_sizedstar739);  
					stream_LBRACKET.add(LBRACKET40);

					pushFollow(FOLLOW_identifier_in_sizedstar741);
					identifier41=gSleighParser.identifier();
					state._fsp--;

					stream_identifier.add(identifier41.getTree());
					RBRACKET42=(Token)match(input,RBRACKET,FOLLOW_RBRACKET_in_sizedstar743);  
					stream_RBRACKET.add(RBRACKET42);

					COLON43=(Token)match(input,COLON,FOLLOW_COLON_in_sizedstar745);  
					stream_COLON.add(COLON43);

					pushFollow(FOLLOW_constant_in_sizedstar747);
					constant44=constant();
					state._fsp--;

					stream_constant.add(constant44.getTree());
					// AST REWRITE
					// elements: identifier, constant
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 134:60: -> ^( OP_DEREFERENCE[$lc] identifier constant )
					{
						// SemanticParser.g:134:63: ^( OP_DEREFERENCE[$lc] identifier constant )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_DEREFERENCE, lc), root_1);
						adaptor.addChild(root_1, stream_identifier.nextTree());
						adaptor.addChild(root_1, stream_constant.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 2 :
					// SemanticParser.g:135:4: lc= ASTERISK LBRACKET identifier RBRACKET
					{
					lc=(Token)match(input,ASTERISK,FOLLOW_ASTERISK_in_sizedstar765);  
					stream_ASTERISK.add(lc);

					LBRACKET45=(Token)match(input,LBRACKET,FOLLOW_LBRACKET_in_sizedstar767);  
					stream_LBRACKET.add(LBRACKET45);

					pushFollow(FOLLOW_identifier_in_sizedstar769);
					identifier46=gSleighParser.identifier();
					state._fsp--;

					stream_identifier.add(identifier46.getTree());
					RBRACKET47=(Token)match(input,RBRACKET,FOLLOW_RBRACKET_in_sizedstar771);  
					stream_RBRACKET.add(RBRACKET47);

					// AST REWRITE
					// elements: identifier
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 135:60: -> ^( OP_DEREFERENCE[$lc] identifier )
					{
						// SemanticParser.g:135:63: ^( OP_DEREFERENCE[$lc] identifier )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_DEREFERENCE, lc), root_1);
						adaptor.addChild(root_1, stream_identifier.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 3 :
					// SemanticParser.g:136:4: lc= ASTERISK COLON constant
					{
					lc=(Token)match(input,ASTERISK,FOLLOW_ASTERISK_in_sizedstar802);  
					stream_ASTERISK.add(lc);

					COLON48=(Token)match(input,COLON,FOLLOW_COLON_in_sizedstar833);  
					stream_COLON.add(COLON48);

					pushFollow(FOLLOW_constant_in_sizedstar835);
					constant49=constant();
					state._fsp--;

					stream_constant.add(constant49.getTree());
					// AST REWRITE
					// elements: constant
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 136:60: -> ^( OP_DEREFERENCE[$lc] constant )
					{
						// SemanticParser.g:136:63: ^( OP_DEREFERENCE[$lc] constant )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_DEREFERENCE, lc), root_1);
						adaptor.addChild(root_1, stream_constant.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 4 :
					// SemanticParser.g:137:4: lc= ASTERISK
					{
					lc=(Token)match(input,ASTERISK,FOLLOW_ASTERISK_in_sizedstar851);  
					stream_ASTERISK.add(lc);

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
					// 137:60: -> ^( OP_DEREFERENCE[$lc] )
					{
						// SemanticParser.g:137:63: ^( OP_DEREFERENCE[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_DEREFERENCE, lc), root_1);
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
	// $ANTLR end "sizedstar"


	public static class funcall_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "funcall"
	// SemanticParser.g:140:1: funcall : expr_apply ;
	public final SleighParser_SemanticParser.funcall_return funcall() throws RecognitionException {
		SleighParser_SemanticParser.funcall_return retval = new SleighParser_SemanticParser.funcall_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope expr_apply50 =null;


		try {
			// SemanticParser.g:141:2: ( expr_apply )
			// SemanticParser.g:141:4: expr_apply
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_expr_apply_in_funcall913);
			expr_apply50=expr_apply();
			state._fsp--;

			adaptor.addChild(root_0, expr_apply50.getTree());

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
	// $ANTLR end "funcall"


	public static class build_stmt_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "build_stmt"
	// SemanticParser.g:144:1: build_stmt : lc= KEY_BUILD identifier -> ^( OP_BUILD[$lc] identifier ) ;
	public final SleighParser_SemanticParser.build_stmt_return build_stmt() throws RecognitionException {
		SleighParser_SemanticParser.build_stmt_return retval = new SleighParser_SemanticParser.build_stmt_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		ParserRuleReturnScope identifier51 =null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_KEY_BUILD=new RewriteRuleTokenStream(adaptor,"token KEY_BUILD");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");

		try {
			// SemanticParser.g:145:2: (lc= KEY_BUILD identifier -> ^( OP_BUILD[$lc] identifier ) )
			// SemanticParser.g:145:4: lc= KEY_BUILD identifier
			{
			lc=(Token)match(input,KEY_BUILD,FOLLOW_KEY_BUILD_in_build_stmt926);  
			stream_KEY_BUILD.add(lc);

			pushFollow(FOLLOW_identifier_in_build_stmt928);
			identifier51=gSleighParser.identifier();
			state._fsp--;

			stream_identifier.add(identifier51.getTree());
			// AST REWRITE
			// elements: identifier
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 145:28: -> ^( OP_BUILD[$lc] identifier )
			{
				// SemanticParser.g:145:31: ^( OP_BUILD[$lc] identifier )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_BUILD, lc), root_1);
				adaptor.addChild(root_1, stream_identifier.nextTree());
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
	// $ANTLR end "build_stmt"


	public static class crossbuild_stmt_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "crossbuild_stmt"
	// SemanticParser.g:148:1: crossbuild_stmt : lc= KEY_CROSSBUILD varnode COMMA identifier -> ^( OP_CROSSBUILD[$lc] varnode identifier ) ;
	public final SleighParser_SemanticParser.crossbuild_stmt_return crossbuild_stmt() throws RecognitionException {
		SleighParser_SemanticParser.crossbuild_stmt_return retval = new SleighParser_SemanticParser.crossbuild_stmt_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token COMMA53=null;
		ParserRuleReturnScope varnode52 =null;
		ParserRuleReturnScope identifier54 =null;

		CommonTree lc_tree=null;
		CommonTree COMMA53_tree=null;
		RewriteRuleTokenStream stream_COMMA=new RewriteRuleTokenStream(adaptor,"token COMMA");
		RewriteRuleTokenStream stream_KEY_CROSSBUILD=new RewriteRuleTokenStream(adaptor,"token KEY_CROSSBUILD");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_varnode=new RewriteRuleSubtreeStream(adaptor,"rule varnode");

		try {
			// SemanticParser.g:149:2: (lc= KEY_CROSSBUILD varnode COMMA identifier -> ^( OP_CROSSBUILD[$lc] varnode identifier ) )
			// SemanticParser.g:149:4: lc= KEY_CROSSBUILD varnode COMMA identifier
			{
			lc=(Token)match(input,KEY_CROSSBUILD,FOLLOW_KEY_CROSSBUILD_in_crossbuild_stmt950);  
			stream_KEY_CROSSBUILD.add(lc);

			pushFollow(FOLLOW_varnode_in_crossbuild_stmt952);
			varnode52=varnode();
			state._fsp--;

			stream_varnode.add(varnode52.getTree());
			COMMA53=(Token)match(input,COMMA,FOLLOW_COMMA_in_crossbuild_stmt954);  
			stream_COMMA.add(COMMA53);

			pushFollow(FOLLOW_identifier_in_crossbuild_stmt956);
			identifier54=gSleighParser.identifier();
			state._fsp--;

			stream_identifier.add(identifier54.getTree());
			// AST REWRITE
			// elements: identifier, varnode
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 149:46: -> ^( OP_CROSSBUILD[$lc] varnode identifier )
			{
				// SemanticParser.g:149:49: ^( OP_CROSSBUILD[$lc] varnode identifier )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_CROSSBUILD, lc), root_1);
				adaptor.addChild(root_1, stream_varnode.nextTree());
				adaptor.addChild(root_1, stream_identifier.nextTree());
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
	// $ANTLR end "crossbuild_stmt"


	public static class goto_stmt_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "goto_stmt"
	// SemanticParser.g:152:1: goto_stmt : lc= KEY_GOTO jumpdest -> ^( OP_GOTO[$lc] jumpdest ) ;
	public final SleighParser_SemanticParser.goto_stmt_return goto_stmt() throws RecognitionException {
		SleighParser_SemanticParser.goto_stmt_return retval = new SleighParser_SemanticParser.goto_stmt_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		ParserRuleReturnScope jumpdest55 =null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_KEY_GOTO=new RewriteRuleTokenStream(adaptor,"token KEY_GOTO");
		RewriteRuleSubtreeStream stream_jumpdest=new RewriteRuleSubtreeStream(adaptor,"rule jumpdest");

		try {
			// SemanticParser.g:153:2: (lc= KEY_GOTO jumpdest -> ^( OP_GOTO[$lc] jumpdest ) )
			// SemanticParser.g:153:4: lc= KEY_GOTO jumpdest
			{
			lc=(Token)match(input,KEY_GOTO,FOLLOW_KEY_GOTO_in_goto_stmt979);  
			stream_KEY_GOTO.add(lc);

			pushFollow(FOLLOW_jumpdest_in_goto_stmt981);
			jumpdest55=jumpdest();
			state._fsp--;

			stream_jumpdest.add(jumpdest55.getTree());
			// AST REWRITE
			// elements: jumpdest
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 153:25: -> ^( OP_GOTO[$lc] jumpdest )
			{
				// SemanticParser.g:153:28: ^( OP_GOTO[$lc] jumpdest )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_GOTO, lc), root_1);
				adaptor.addChild(root_1, stream_jumpdest.nextTree());
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
	// $ANTLR end "goto_stmt"


	public static class jumpdest_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "jumpdest"
	// SemanticParser.g:156:1: jumpdest : ( identifier -> ^( OP_JUMPDEST_SYMBOL identifier ) | LBRACKET expr RBRACKET -> ^( OP_JUMPDEST_DYNAMIC expr ) | integer -> ^( OP_JUMPDEST_ABSOLUTE integer ) | constant LBRACKET identifier RBRACKET -> ^( OP_JUMPDEST_RELATIVE constant identifier ) | label -> ^( OP_JUMPDEST_LABEL label ) );
	public final SleighParser_SemanticParser.jumpdest_return jumpdest() throws RecognitionException {
		SleighParser_SemanticParser.jumpdest_return retval = new SleighParser_SemanticParser.jumpdest_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token LBRACKET57=null;
		Token RBRACKET59=null;
		Token LBRACKET62=null;
		Token RBRACKET64=null;
		ParserRuleReturnScope identifier56 =null;
		ParserRuleReturnScope expr58 =null;
		ParserRuleReturnScope integer60 =null;
		ParserRuleReturnScope constant61 =null;
		ParserRuleReturnScope identifier63 =null;
		ParserRuleReturnScope label65 =null;

		CommonTree LBRACKET57_tree=null;
		CommonTree RBRACKET59_tree=null;
		CommonTree LBRACKET62_tree=null;
		CommonTree RBRACKET64_tree=null;
		RewriteRuleTokenStream stream_LBRACKET=new RewriteRuleTokenStream(adaptor,"token LBRACKET");
		RewriteRuleTokenStream stream_RBRACKET=new RewriteRuleTokenStream(adaptor,"token RBRACKET");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_constant=new RewriteRuleSubtreeStream(adaptor,"rule constant");
		RewriteRuleSubtreeStream stream_expr=new RewriteRuleSubtreeStream(adaptor,"rule expr");
		RewriteRuleSubtreeStream stream_integer=new RewriteRuleSubtreeStream(adaptor,"rule integer");
		RewriteRuleSubtreeStream stream_label=new RewriteRuleSubtreeStream(adaptor,"rule label");

		try {
			// SemanticParser.g:157:2: ( identifier -> ^( OP_JUMPDEST_SYMBOL identifier ) | LBRACKET expr RBRACKET -> ^( OP_JUMPDEST_DYNAMIC expr ) | integer -> ^( OP_JUMPDEST_ABSOLUTE integer ) | constant LBRACKET identifier RBRACKET -> ^( OP_JUMPDEST_RELATIVE constant identifier ) | label -> ^( OP_JUMPDEST_LABEL label ) )
			int alt10=5;
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
				alt10=1;
				}
				break;
			case LBRACKET:
				{
				alt10=2;
				}
				break;
			case HEX_INT:
				{
				int LA10_3 = input.LA(2);
				if ( (LA10_3==SEMI) ) {
					alt10=3;
				}
				else if ( (LA10_3==LBRACKET) ) {
					alt10=4;
				}

				else {
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
			case DEC_INT:
				{
				int LA10_4 = input.LA(2);
				if ( (LA10_4==SEMI) ) {
					alt10=3;
				}
				else if ( (LA10_4==LBRACKET) ) {
					alt10=4;
				}

				else {
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
			case BIN_INT:
				{
				int LA10_5 = input.LA(2);
				if ( (LA10_5==SEMI) ) {
					alt10=3;
				}
				else if ( (LA10_5==LBRACKET) ) {
					alt10=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 10, 5, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case LESS:
				{
				alt10=5;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 10, 0, input);
				throw nvae;
			}
			switch (alt10) {
				case 1 :
					// SemanticParser.g:157:4: identifier
					{
					pushFollow(FOLLOW_identifier_in_jumpdest1001);
					identifier56=gSleighParser.identifier();
					state._fsp--;

					stream_identifier.add(identifier56.getTree());
					// AST REWRITE
					// elements: identifier
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 157:15: -> ^( OP_JUMPDEST_SYMBOL identifier )
					{
						// SemanticParser.g:157:18: ^( OP_JUMPDEST_SYMBOL identifier )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_JUMPDEST_SYMBOL, "OP_JUMPDEST_SYMBOL"), root_1);
						adaptor.addChild(root_1, stream_identifier.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 2 :
					// SemanticParser.g:158:4: LBRACKET expr RBRACKET
					{
					LBRACKET57=(Token)match(input,LBRACKET,FOLLOW_LBRACKET_in_jumpdest1014);  
					stream_LBRACKET.add(LBRACKET57);

					pushFollow(FOLLOW_expr_in_jumpdest1016);
					expr58=expr();
					state._fsp--;

					stream_expr.add(expr58.getTree());
					RBRACKET59=(Token)match(input,RBRACKET,FOLLOW_RBRACKET_in_jumpdest1018);  
					stream_RBRACKET.add(RBRACKET59);

					// AST REWRITE
					// elements: expr
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 158:27: -> ^( OP_JUMPDEST_DYNAMIC expr )
					{
						// SemanticParser.g:158:30: ^( OP_JUMPDEST_DYNAMIC expr )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_JUMPDEST_DYNAMIC, "OP_JUMPDEST_DYNAMIC"), root_1);
						adaptor.addChild(root_1, stream_expr.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 3 :
					// SemanticParser.g:159:4: integer
					{
					pushFollow(FOLLOW_integer_in_jumpdest1031);
					integer60=gSleighParser.integer();
					state._fsp--;

					stream_integer.add(integer60.getTree());
					// AST REWRITE
					// elements: integer
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 159:12: -> ^( OP_JUMPDEST_ABSOLUTE integer )
					{
						// SemanticParser.g:159:15: ^( OP_JUMPDEST_ABSOLUTE integer )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_JUMPDEST_ABSOLUTE, "OP_JUMPDEST_ABSOLUTE"), root_1);
						adaptor.addChild(root_1, stream_integer.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 4 :
					// SemanticParser.g:160:4: constant LBRACKET identifier RBRACKET
					{
					pushFollow(FOLLOW_constant_in_jumpdest1044);
					constant61=constant();
					state._fsp--;

					stream_constant.add(constant61.getTree());
					LBRACKET62=(Token)match(input,LBRACKET,FOLLOW_LBRACKET_in_jumpdest1046);  
					stream_LBRACKET.add(LBRACKET62);

					pushFollow(FOLLOW_identifier_in_jumpdest1048);
					identifier63=gSleighParser.identifier();
					state._fsp--;

					stream_identifier.add(identifier63.getTree());
					RBRACKET64=(Token)match(input,RBRACKET,FOLLOW_RBRACKET_in_jumpdest1050);  
					stream_RBRACKET.add(RBRACKET64);

					// AST REWRITE
					// elements: identifier, constant
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 160:42: -> ^( OP_JUMPDEST_RELATIVE constant identifier )
					{
						// SemanticParser.g:160:45: ^( OP_JUMPDEST_RELATIVE constant identifier )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_JUMPDEST_RELATIVE, "OP_JUMPDEST_RELATIVE"), root_1);
						adaptor.addChild(root_1, stream_constant.nextTree());
						adaptor.addChild(root_1, stream_identifier.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 5 :
					// SemanticParser.g:161:4: label
					{
					pushFollow(FOLLOW_label_in_jumpdest1065);
					label65=label();
					state._fsp--;

					stream_label.add(label65.getTree());
					// AST REWRITE
					// elements: label
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 161:10: -> ^( OP_JUMPDEST_LABEL label )
					{
						// SemanticParser.g:161:13: ^( OP_JUMPDEST_LABEL label )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_JUMPDEST_LABEL, "OP_JUMPDEST_LABEL"), root_1);
						adaptor.addChild(root_1, stream_label.nextTree());
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
	// $ANTLR end "jumpdest"


	public static class cond_stmt_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "cond_stmt"
	// SemanticParser.g:164:1: cond_stmt : lc= RES_IF expr goto_stmt -> ^( OP_IF[$lc] expr goto_stmt ) ;
	public final SleighParser_SemanticParser.cond_stmt_return cond_stmt() throws RecognitionException {
		SleighParser_SemanticParser.cond_stmt_return retval = new SleighParser_SemanticParser.cond_stmt_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		ParserRuleReturnScope expr66 =null;
		ParserRuleReturnScope goto_stmt67 =null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_RES_IF=new RewriteRuleTokenStream(adaptor,"token RES_IF");
		RewriteRuleSubtreeStream stream_expr=new RewriteRuleSubtreeStream(adaptor,"rule expr");
		RewriteRuleSubtreeStream stream_goto_stmt=new RewriteRuleSubtreeStream(adaptor,"rule goto_stmt");

		try {
			// SemanticParser.g:165:2: (lc= RES_IF expr goto_stmt -> ^( OP_IF[$lc] expr goto_stmt ) )
			// SemanticParser.g:165:4: lc= RES_IF expr goto_stmt
			{
			lc=(Token)match(input,RES_IF,FOLLOW_RES_IF_in_cond_stmt1086);  
			stream_RES_IF.add(lc);

			pushFollow(FOLLOW_expr_in_cond_stmt1088);
			expr66=expr();
			state._fsp--;

			stream_expr.add(expr66.getTree());
			pushFollow(FOLLOW_goto_stmt_in_cond_stmt1090);
			goto_stmt67=goto_stmt();
			state._fsp--;

			stream_goto_stmt.add(goto_stmt67.getTree());
			// AST REWRITE
			// elements: goto_stmt, expr
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 165:29: -> ^( OP_IF[$lc] expr goto_stmt )
			{
				// SemanticParser.g:165:32: ^( OP_IF[$lc] expr goto_stmt )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_IF, lc), root_1);
				adaptor.addChild(root_1, stream_expr.nextTree());
				adaptor.addChild(root_1, stream_goto_stmt.nextTree());
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
	// $ANTLR end "cond_stmt"


	public static class call_stmt_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "call_stmt"
	// SemanticParser.g:168:1: call_stmt : lc= KEY_CALL jumpdest -> ^( OP_CALL[$lc] jumpdest ) ;
	public final SleighParser_SemanticParser.call_stmt_return call_stmt() throws RecognitionException {
		SleighParser_SemanticParser.call_stmt_return retval = new SleighParser_SemanticParser.call_stmt_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		ParserRuleReturnScope jumpdest68 =null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_KEY_CALL=new RewriteRuleTokenStream(adaptor,"token KEY_CALL");
		RewriteRuleSubtreeStream stream_jumpdest=new RewriteRuleSubtreeStream(adaptor,"rule jumpdest");

		try {
			// SemanticParser.g:169:2: (lc= KEY_CALL jumpdest -> ^( OP_CALL[$lc] jumpdest ) )
			// SemanticParser.g:169:4: lc= KEY_CALL jumpdest
			{
			lc=(Token)match(input,KEY_CALL,FOLLOW_KEY_CALL_in_call_stmt1114);  
			stream_KEY_CALL.add(lc);

			pushFollow(FOLLOW_jumpdest_in_call_stmt1116);
			jumpdest68=jumpdest();
			state._fsp--;

			stream_jumpdest.add(jumpdest68.getTree());
			// AST REWRITE
			// elements: jumpdest
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 169:25: -> ^( OP_CALL[$lc] jumpdest )
			{
				// SemanticParser.g:169:28: ^( OP_CALL[$lc] jumpdest )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_CALL, lc), root_1);
				adaptor.addChild(root_1, stream_jumpdest.nextTree());
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
	// $ANTLR end "call_stmt"


	public static class return_stmt_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "return_stmt"
	// SemanticParser.g:172:1: return_stmt : lc= KEY_RETURN LBRACKET expr RBRACKET -> ^( OP_RETURN[$lc] expr ) ;
	public final SleighParser_SemanticParser.return_stmt_return return_stmt() throws RecognitionException {
		SleighParser_SemanticParser.return_stmt_return retval = new SleighParser_SemanticParser.return_stmt_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token LBRACKET69=null;
		Token RBRACKET71=null;
		ParserRuleReturnScope expr70 =null;

		CommonTree lc_tree=null;
		CommonTree LBRACKET69_tree=null;
		CommonTree RBRACKET71_tree=null;
		RewriteRuleTokenStream stream_LBRACKET=new RewriteRuleTokenStream(adaptor,"token LBRACKET");
		RewriteRuleTokenStream stream_RBRACKET=new RewriteRuleTokenStream(adaptor,"token RBRACKET");
		RewriteRuleTokenStream stream_KEY_RETURN=new RewriteRuleTokenStream(adaptor,"token KEY_RETURN");
		RewriteRuleSubtreeStream stream_expr=new RewriteRuleSubtreeStream(adaptor,"rule expr");

		try {
			// SemanticParser.g:173:2: (lc= KEY_RETURN LBRACKET expr RBRACKET -> ^( OP_RETURN[$lc] expr ) )
			// SemanticParser.g:173:4: lc= KEY_RETURN LBRACKET expr RBRACKET
			{
			lc=(Token)match(input,KEY_RETURN,FOLLOW_KEY_RETURN_in_return_stmt1138);  
			stream_KEY_RETURN.add(lc);

			LBRACKET69=(Token)match(input,LBRACKET,FOLLOW_LBRACKET_in_return_stmt1140);  
			stream_LBRACKET.add(LBRACKET69);

			pushFollow(FOLLOW_expr_in_return_stmt1142);
			expr70=expr();
			state._fsp--;

			stream_expr.add(expr70.getTree());
			RBRACKET71=(Token)match(input,RBRACKET,FOLLOW_RBRACKET_in_return_stmt1144);  
			stream_RBRACKET.add(RBRACKET71);

			// AST REWRITE
			// elements: expr
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 173:41: -> ^( OP_RETURN[$lc] expr )
			{
				// SemanticParser.g:173:44: ^( OP_RETURN[$lc] expr )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_RETURN, lc), root_1);
				adaptor.addChild(root_1, stream_expr.nextTree());
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
	// $ANTLR end "return_stmt"


	public static class sizedexport_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "sizedexport"
	// SemanticParser.g:176:1: sizedexport : sizedstar ^ identifier ;
	public final SleighParser_SemanticParser.sizedexport_return sizedexport() throws RecognitionException {
		SleighParser_SemanticParser.sizedexport_return retval = new SleighParser_SemanticParser.sizedexport_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope sizedstar72 =null;
		ParserRuleReturnScope identifier73 =null;


		try {
			// SemanticParser.g:177:2: ( sizedstar ^ identifier )
			// SemanticParser.g:177:4: sizedstar ^ identifier
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_sizedstar_in_sizedexport1164);
			sizedstar72=sizedstar();
			state._fsp--;

			root_0 = (CommonTree)adaptor.becomeRoot(sizedstar72.getTree(), root_0);
			pushFollow(FOLLOW_identifier_in_sizedexport1167);
			identifier73=gSleighParser.identifier();
			state._fsp--;

			adaptor.addChild(root_0, identifier73.getTree());

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
	// $ANTLR end "sizedexport"


	public static class export_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "export"
	// SemanticParser.g:180:1: export : (lc= KEY_EXPORT sizedexport -> ^( OP_EXPORT[$lc] sizedexport ) |lc= KEY_EXPORT varnode -> ^( OP_EXPORT[$lc] varnode ) );
	public final SleighParser_SemanticParser.export_return export() throws RecognitionException {
		SleighParser_SemanticParser.export_return retval = new SleighParser_SemanticParser.export_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		ParserRuleReturnScope sizedexport74 =null;
		ParserRuleReturnScope varnode75 =null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_KEY_EXPORT=new RewriteRuleTokenStream(adaptor,"token KEY_EXPORT");
		RewriteRuleSubtreeStream stream_sizedexport=new RewriteRuleSubtreeStream(adaptor,"rule sizedexport");
		RewriteRuleSubtreeStream stream_varnode=new RewriteRuleSubtreeStream(adaptor,"rule varnode");

		try {
			// SemanticParser.g:181:2: (lc= KEY_EXPORT sizedexport -> ^( OP_EXPORT[$lc] sizedexport ) |lc= KEY_EXPORT varnode -> ^( OP_EXPORT[$lc] varnode ) )
			int alt11=2;
			int LA11_0 = input.LA(1);
			if ( (LA11_0==KEY_EXPORT) ) {
				int LA11_1 = input.LA(2);
				if ( (LA11_1==ASTERISK) ) {
					alt11=1;
				}
				else if ( (LA11_1==AMPERSAND||LA11_1==BIN_INT||LA11_1==DEC_INT||(LA11_1 >= HEX_INT && LA11_1 <= KEY_WORDSIZE)) ) {
					alt11=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 11, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 11, 0, input);
				throw nvae;
			}

			switch (alt11) {
				case 1 :
					// SemanticParser.g:181:4: lc= KEY_EXPORT sizedexport
					{
					lc=(Token)match(input,KEY_EXPORT,FOLLOW_KEY_EXPORT_in_export1180);  
					stream_KEY_EXPORT.add(lc);

					pushFollow(FOLLOW_sizedexport_in_export1182);
					sizedexport74=sizedexport();
					state._fsp--;

					stream_sizedexport.add(sizedexport74.getTree());
					// AST REWRITE
					// elements: sizedexport
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 181:30: -> ^( OP_EXPORT[$lc] sizedexport )
					{
						// SemanticParser.g:181:33: ^( OP_EXPORT[$lc] sizedexport )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_EXPORT, lc), root_1);
						adaptor.addChild(root_1, stream_sizedexport.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 2 :
					// SemanticParser.g:182:4: lc= KEY_EXPORT varnode
					{
					lc=(Token)match(input,KEY_EXPORT,FOLLOW_KEY_EXPORT_in_export1198);  
					stream_KEY_EXPORT.add(lc);

					pushFollow(FOLLOW_varnode_in_export1200);
					varnode75=varnode();
					state._fsp--;

					stream_varnode.add(varnode75.getTree());
					// AST REWRITE
					// elements: varnode
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 182:26: -> ^( OP_EXPORT[$lc] varnode )
					{
						// SemanticParser.g:182:29: ^( OP_EXPORT[$lc] varnode )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_EXPORT, lc), root_1);
						adaptor.addChild(root_1, stream_varnode.nextTree());
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
	// $ANTLR end "export"


	public static class expr_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "expr"
	// SemanticParser.g:185:1: expr : expr_boolor ;
	public final SleighParser_SemanticParser.expr_return expr() throws RecognitionException {
		SleighParser_SemanticParser.expr_return retval = new SleighParser_SemanticParser.expr_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope expr_boolor76 =null;


		try {
			// SemanticParser.g:186:2: ( expr_boolor )
			// SemanticParser.g:186:4: expr_boolor
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_expr_boolor_in_expr1220);
			expr_boolor76=expr_boolor();
			state._fsp--;

			adaptor.addChild(root_0, expr_boolor76.getTree());

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
	// $ANTLR end "expr"


	public static class expr_boolor_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "expr_boolor"
	// SemanticParser.g:189:1: expr_boolor : expr_booland ( expr_boolor_op ^ expr_booland )* ;
	public final SleighParser_SemanticParser.expr_boolor_return expr_boolor() throws RecognitionException {
		SleighParser_SemanticParser.expr_boolor_return retval = new SleighParser_SemanticParser.expr_boolor_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope expr_booland77 =null;
		ParserRuleReturnScope expr_boolor_op78 =null;
		ParserRuleReturnScope expr_booland79 =null;


		try {
			// SemanticParser.g:190:2: ( expr_booland ( expr_boolor_op ^ expr_booland )* )
			// SemanticParser.g:190:4: expr_booland ( expr_boolor_op ^ expr_booland )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_expr_booland_in_expr_boolor1231);
			expr_booland77=expr_booland();
			state._fsp--;

			adaptor.addChild(root_0, expr_booland77.getTree());

			// SemanticParser.g:190:17: ( expr_boolor_op ^ expr_booland )*
			loop12:
			while (true) {
				int alt12=2;
				int LA12_0 = input.LA(1);
				if ( (LA12_0==BOOL_OR) ) {
					alt12=1;
				}

				switch (alt12) {
				case 1 :
					// SemanticParser.g:190:19: expr_boolor_op ^ expr_booland
					{
					pushFollow(FOLLOW_expr_boolor_op_in_expr_boolor1235);
					expr_boolor_op78=expr_boolor_op();
					state._fsp--;

					root_0 = (CommonTree)adaptor.becomeRoot(expr_boolor_op78.getTree(), root_0);
					pushFollow(FOLLOW_expr_booland_in_expr_boolor1238);
					expr_booland79=expr_booland();
					state._fsp--;

					adaptor.addChild(root_0, expr_booland79.getTree());

					}
					break;

				default :
					break loop12;
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
	// $ANTLR end "expr_boolor"


	public static class expr_boolor_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "expr_boolor_op"
	// SemanticParser.g:193:1: expr_boolor_op : lc= BOOL_OR -> ^( OP_BOOL_OR[$lc] ) ;
	public final SleighParser_SemanticParser.expr_boolor_op_return expr_boolor_op() throws RecognitionException {
		SleighParser_SemanticParser.expr_boolor_op_return retval = new SleighParser_SemanticParser.expr_boolor_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_BOOL_OR=new RewriteRuleTokenStream(adaptor,"token BOOL_OR");

		try {
			// SemanticParser.g:194:2: (lc= BOOL_OR -> ^( OP_BOOL_OR[$lc] ) )
			// SemanticParser.g:194:4: lc= BOOL_OR
			{
			lc=(Token)match(input,BOOL_OR,FOLLOW_BOOL_OR_in_expr_boolor_op1254);  
			stream_BOOL_OR.add(lc);

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
			// 194:15: -> ^( OP_BOOL_OR[$lc] )
			{
				// SemanticParser.g:194:18: ^( OP_BOOL_OR[$lc] )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_BOOL_OR, lc), root_1);
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
	// $ANTLR end "expr_boolor_op"


	public static class expr_booland_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "expr_booland"
	// SemanticParser.g:197:1: expr_booland : expr_or ( booland_op ^ expr_or )* ;
	public final SleighParser_SemanticParser.expr_booland_return expr_booland() throws RecognitionException {
		SleighParser_SemanticParser.expr_booland_return retval = new SleighParser_SemanticParser.expr_booland_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope expr_or80 =null;
		ParserRuleReturnScope booland_op81 =null;
		ParserRuleReturnScope expr_or82 =null;


		try {
			// SemanticParser.g:198:2: ( expr_or ( booland_op ^ expr_or )* )
			// SemanticParser.g:198:4: expr_or ( booland_op ^ expr_or )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_expr_or_in_expr_booland1272);
			expr_or80=expr_or();
			state._fsp--;

			adaptor.addChild(root_0, expr_or80.getTree());

			// SemanticParser.g:198:12: ( booland_op ^ expr_or )*
			loop13:
			while (true) {
				int alt13=2;
				int LA13_0 = input.LA(1);
				if ( (LA13_0==BOOL_AND||LA13_0==BOOL_XOR) ) {
					alt13=1;
				}

				switch (alt13) {
				case 1 :
					// SemanticParser.g:198:14: booland_op ^ expr_or
					{
					pushFollow(FOLLOW_booland_op_in_expr_booland1276);
					booland_op81=booland_op();
					state._fsp--;

					root_0 = (CommonTree)adaptor.becomeRoot(booland_op81.getTree(), root_0);
					pushFollow(FOLLOW_expr_or_in_expr_booland1279);
					expr_or82=expr_or();
					state._fsp--;

					adaptor.addChild(root_0, expr_or82.getTree());

					}
					break;

				default :
					break loop13;
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
	// $ANTLR end "expr_booland"


	public static class booland_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "booland_op"
	// SemanticParser.g:201:1: booland_op : (lc= BOOL_AND -> ^( OP_BOOL_AND[$lc] ) |lc= BOOL_XOR -> ^( OP_BOOL_XOR[$lc] ) );
	public final SleighParser_SemanticParser.booland_op_return booland_op() throws RecognitionException {
		SleighParser_SemanticParser.booland_op_return retval = new SleighParser_SemanticParser.booland_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_BOOL_AND=new RewriteRuleTokenStream(adaptor,"token BOOL_AND");
		RewriteRuleTokenStream stream_BOOL_XOR=new RewriteRuleTokenStream(adaptor,"token BOOL_XOR");

		try {
			// SemanticParser.g:202:2: (lc= BOOL_AND -> ^( OP_BOOL_AND[$lc] ) |lc= BOOL_XOR -> ^( OP_BOOL_XOR[$lc] ) )
			int alt14=2;
			int LA14_0 = input.LA(1);
			if ( (LA14_0==BOOL_AND) ) {
				alt14=1;
			}
			else if ( (LA14_0==BOOL_XOR) ) {
				alt14=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 14, 0, input);
				throw nvae;
			}

			switch (alt14) {
				case 1 :
					// SemanticParser.g:202:4: lc= BOOL_AND
					{
					lc=(Token)match(input,BOOL_AND,FOLLOW_BOOL_AND_in_booland_op1295);  
					stream_BOOL_AND.add(lc);

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
					// 202:16: -> ^( OP_BOOL_AND[$lc] )
					{
						// SemanticParser.g:202:19: ^( OP_BOOL_AND[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_BOOL_AND, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 2 :
					// SemanticParser.g:203:4: lc= BOOL_XOR
					{
					lc=(Token)match(input,BOOL_XOR,FOLLOW_BOOL_XOR_in_booland_op1309);  
					stream_BOOL_XOR.add(lc);

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
					// 203:16: -> ^( OP_BOOL_XOR[$lc] )
					{
						// SemanticParser.g:203:19: ^( OP_BOOL_XOR[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_BOOL_XOR, lc), root_1);
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
	// $ANTLR end "booland_op"


	public static class expr_or_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "expr_or"
	// SemanticParser.g:206:1: expr_or : expr_xor ( expr_or_op ^ expr_xor )* ;
	public final SleighParser_SemanticParser.expr_or_return expr_or() throws RecognitionException {
		SleighParser_SemanticParser.expr_or_return retval = new SleighParser_SemanticParser.expr_or_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope expr_xor83 =null;
		ParserRuleReturnScope expr_or_op84 =null;
		ParserRuleReturnScope expr_xor85 =null;


		try {
			// SemanticParser.g:207:2: ( expr_xor ( expr_or_op ^ expr_xor )* )
			// SemanticParser.g:207:4: expr_xor ( expr_or_op ^ expr_xor )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_expr_xor_in_expr_or1327);
			expr_xor83=expr_xor();
			state._fsp--;

			adaptor.addChild(root_0, expr_xor83.getTree());

			// SemanticParser.g:207:13: ( expr_or_op ^ expr_xor )*
			loop15:
			while (true) {
				int alt15=2;
				int LA15_0 = input.LA(1);
				if ( (LA15_0==PIPE) ) {
					alt15=1;
				}

				switch (alt15) {
				case 1 :
					// SemanticParser.g:207:15: expr_or_op ^ expr_xor
					{
					pushFollow(FOLLOW_expr_or_op_in_expr_or1331);
					expr_or_op84=expr_or_op();
					state._fsp--;

					root_0 = (CommonTree)adaptor.becomeRoot(expr_or_op84.getTree(), root_0);
					pushFollow(FOLLOW_expr_xor_in_expr_or1334);
					expr_xor85=expr_xor();
					state._fsp--;

					adaptor.addChild(root_0, expr_xor85.getTree());

					}
					break;

				default :
					break loop15;
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
	// $ANTLR end "expr_or"


	public static class expr_or_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "expr_or_op"
	// SemanticParser.g:210:1: expr_or_op : lc= PIPE -> ^( OP_OR[$lc] ) ;
	public final SleighParser_SemanticParser.expr_or_op_return expr_or_op() throws RecognitionException {
		SleighParser_SemanticParser.expr_or_op_return retval = new SleighParser_SemanticParser.expr_or_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_PIPE=new RewriteRuleTokenStream(adaptor,"token PIPE");

		try {
			// SemanticParser.g:211:2: (lc= PIPE -> ^( OP_OR[$lc] ) )
			// SemanticParser.g:211:4: lc= PIPE
			{
			lc=(Token)match(input,PIPE,FOLLOW_PIPE_in_expr_or_op1350);  
			stream_PIPE.add(lc);

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
			// 211:12: -> ^( OP_OR[$lc] )
			{
				// SemanticParser.g:211:15: ^( OP_OR[$lc] )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_OR, lc), root_1);
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
	// $ANTLR end "expr_or_op"


	public static class expr_xor_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "expr_xor"
	// SemanticParser.g:214:1: expr_xor : expr_and ( expr_xor_op ^ expr_and )* ;
	public final SleighParser_SemanticParser.expr_xor_return expr_xor() throws RecognitionException {
		SleighParser_SemanticParser.expr_xor_return retval = new SleighParser_SemanticParser.expr_xor_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope expr_and86 =null;
		ParserRuleReturnScope expr_xor_op87 =null;
		ParserRuleReturnScope expr_and88 =null;


		try {
			// SemanticParser.g:215:2: ( expr_and ( expr_xor_op ^ expr_and )* )
			// SemanticParser.g:215:4: expr_and ( expr_xor_op ^ expr_and )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_expr_and_in_expr_xor1368);
			expr_and86=expr_and();
			state._fsp--;

			adaptor.addChild(root_0, expr_and86.getTree());

			// SemanticParser.g:215:13: ( expr_xor_op ^ expr_and )*
			loop16:
			while (true) {
				int alt16=2;
				int LA16_0 = input.LA(1);
				if ( (LA16_0==CARET) ) {
					alt16=1;
				}

				switch (alt16) {
				case 1 :
					// SemanticParser.g:215:15: expr_xor_op ^ expr_and
					{
					pushFollow(FOLLOW_expr_xor_op_in_expr_xor1372);
					expr_xor_op87=expr_xor_op();
					state._fsp--;

					root_0 = (CommonTree)adaptor.becomeRoot(expr_xor_op87.getTree(), root_0);
					pushFollow(FOLLOW_expr_and_in_expr_xor1375);
					expr_and88=expr_and();
					state._fsp--;

					adaptor.addChild(root_0, expr_and88.getTree());

					}
					break;

				default :
					break loop16;
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
	// $ANTLR end "expr_xor"


	public static class expr_xor_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "expr_xor_op"
	// SemanticParser.g:218:1: expr_xor_op : lc= CARET -> ^( OP_XOR[$lc] ) ;
	public final SleighParser_SemanticParser.expr_xor_op_return expr_xor_op() throws RecognitionException {
		SleighParser_SemanticParser.expr_xor_op_return retval = new SleighParser_SemanticParser.expr_xor_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_CARET=new RewriteRuleTokenStream(adaptor,"token CARET");

		try {
			// SemanticParser.g:219:2: (lc= CARET -> ^( OP_XOR[$lc] ) )
			// SemanticParser.g:219:4: lc= CARET
			{
			lc=(Token)match(input,CARET,FOLLOW_CARET_in_expr_xor_op1391);  
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
			// 219:13: -> ^( OP_XOR[$lc] )
			{
				// SemanticParser.g:219:16: ^( OP_XOR[$lc] )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_XOR, lc), root_1);
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
	// $ANTLR end "expr_xor_op"


	public static class expr_and_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "expr_and"
	// SemanticParser.g:222:1: expr_and : expr_eq ( expr_and_op ^ expr_eq )* ;
	public final SleighParser_SemanticParser.expr_and_return expr_and() throws RecognitionException {
		SleighParser_SemanticParser.expr_and_return retval = new SleighParser_SemanticParser.expr_and_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope expr_eq89 =null;
		ParserRuleReturnScope expr_and_op90 =null;
		ParserRuleReturnScope expr_eq91 =null;


		try {
			// SemanticParser.g:223:2: ( expr_eq ( expr_and_op ^ expr_eq )* )
			// SemanticParser.g:223:4: expr_eq ( expr_and_op ^ expr_eq )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_expr_eq_in_expr_and1409);
			expr_eq89=expr_eq();
			state._fsp--;

			adaptor.addChild(root_0, expr_eq89.getTree());

			// SemanticParser.g:223:12: ( expr_and_op ^ expr_eq )*
			loop17:
			while (true) {
				int alt17=2;
				int LA17_0 = input.LA(1);
				if ( (LA17_0==AMPERSAND) ) {
					alt17=1;
				}

				switch (alt17) {
				case 1 :
					// SemanticParser.g:223:14: expr_and_op ^ expr_eq
					{
					pushFollow(FOLLOW_expr_and_op_in_expr_and1413);
					expr_and_op90=expr_and_op();
					state._fsp--;

					root_0 = (CommonTree)adaptor.becomeRoot(expr_and_op90.getTree(), root_0);
					pushFollow(FOLLOW_expr_eq_in_expr_and1416);
					expr_eq91=expr_eq();
					state._fsp--;

					adaptor.addChild(root_0, expr_eq91.getTree());

					}
					break;

				default :
					break loop17;
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
	// $ANTLR end "expr_and"


	public static class expr_and_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "expr_and_op"
	// SemanticParser.g:226:1: expr_and_op : lc= AMPERSAND -> ^( OP_AND[$lc] ) ;
	public final SleighParser_SemanticParser.expr_and_op_return expr_and_op() throws RecognitionException {
		SleighParser_SemanticParser.expr_and_op_return retval = new SleighParser_SemanticParser.expr_and_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_AMPERSAND=new RewriteRuleTokenStream(adaptor,"token AMPERSAND");

		try {
			// SemanticParser.g:227:2: (lc= AMPERSAND -> ^( OP_AND[$lc] ) )
			// SemanticParser.g:227:4: lc= AMPERSAND
			{
			lc=(Token)match(input,AMPERSAND,FOLLOW_AMPERSAND_in_expr_and_op1432);  
			stream_AMPERSAND.add(lc);

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
			// 227:17: -> ^( OP_AND[$lc] )
			{
				// SemanticParser.g:227:20: ^( OP_AND[$lc] )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_AND, lc), root_1);
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
	// $ANTLR end "expr_and_op"


	public static class expr_eq_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "expr_eq"
	// SemanticParser.g:230:1: expr_eq : expr_comp ( eq_op ^ expr_comp )* ;
	public final SleighParser_SemanticParser.expr_eq_return expr_eq() throws RecognitionException {
		SleighParser_SemanticParser.expr_eq_return retval = new SleighParser_SemanticParser.expr_eq_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope expr_comp92 =null;
		ParserRuleReturnScope eq_op93 =null;
		ParserRuleReturnScope expr_comp94 =null;


		try {
			// SemanticParser.g:231:2: ( expr_comp ( eq_op ^ expr_comp )* )
			// SemanticParser.g:231:4: expr_comp ( eq_op ^ expr_comp )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_expr_comp_in_expr_eq1450);
			expr_comp92=expr_comp();
			state._fsp--;

			adaptor.addChild(root_0, expr_comp92.getTree());

			// SemanticParser.g:231:14: ( eq_op ^ expr_comp )*
			loop18:
			while (true) {
				int alt18=2;
				int LA18_0 = input.LA(1);
				if ( (LA18_0==EQUAL||LA18_0==FEQUAL||LA18_0==FNOTEQUAL||LA18_0==NOTEQUAL) ) {
					alt18=1;
				}

				switch (alt18) {
				case 1 :
					// SemanticParser.g:231:16: eq_op ^ expr_comp
					{
					pushFollow(FOLLOW_eq_op_in_expr_eq1454);
					eq_op93=eq_op();
					state._fsp--;

					root_0 = (CommonTree)adaptor.becomeRoot(eq_op93.getTree(), root_0);
					pushFollow(FOLLOW_expr_comp_in_expr_eq1457);
					expr_comp94=expr_comp();
					state._fsp--;

					adaptor.addChild(root_0, expr_comp94.getTree());

					}
					break;

				default :
					break loop18;
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
	// $ANTLR end "expr_eq"


	public static class eq_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "eq_op"
	// SemanticParser.g:234:1: eq_op : (lc= EQUAL -> ^( OP_EQUAL[$lc] ) |lc= NOTEQUAL -> ^( OP_NOTEQUAL[$lc] ) |lc= FEQUAL -> ^( OP_FEQUAL[$lc] ) |lc= FNOTEQUAL -> ^( OP_FNOTEQUAL[$lc] ) );
	public final SleighParser_SemanticParser.eq_op_return eq_op() throws RecognitionException {
		SleighParser_SemanticParser.eq_op_return retval = new SleighParser_SemanticParser.eq_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_NOTEQUAL=new RewriteRuleTokenStream(adaptor,"token NOTEQUAL");
		RewriteRuleTokenStream stream_FNOTEQUAL=new RewriteRuleTokenStream(adaptor,"token FNOTEQUAL");
		RewriteRuleTokenStream stream_EQUAL=new RewriteRuleTokenStream(adaptor,"token EQUAL");
		RewriteRuleTokenStream stream_FEQUAL=new RewriteRuleTokenStream(adaptor,"token FEQUAL");

		try {
			// SemanticParser.g:235:2: (lc= EQUAL -> ^( OP_EQUAL[$lc] ) |lc= NOTEQUAL -> ^( OP_NOTEQUAL[$lc] ) |lc= FEQUAL -> ^( OP_FEQUAL[$lc] ) |lc= FNOTEQUAL -> ^( OP_FNOTEQUAL[$lc] ) )
			int alt19=4;
			switch ( input.LA(1) ) {
			case EQUAL:
				{
				alt19=1;
				}
				break;
			case NOTEQUAL:
				{
				alt19=2;
				}
				break;
			case FEQUAL:
				{
				alt19=3;
				}
				break;
			case FNOTEQUAL:
				{
				alt19=4;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 19, 0, input);
				throw nvae;
			}
			switch (alt19) {
				case 1 :
					// SemanticParser.g:235:4: lc= EQUAL
					{
					lc=(Token)match(input,EQUAL,FOLLOW_EQUAL_in_eq_op1473);  
					stream_EQUAL.add(lc);

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
					// 235:13: -> ^( OP_EQUAL[$lc] )
					{
						// SemanticParser.g:235:16: ^( OP_EQUAL[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_EQUAL, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 2 :
					// SemanticParser.g:236:4: lc= NOTEQUAL
					{
					lc=(Token)match(input,NOTEQUAL,FOLLOW_NOTEQUAL_in_eq_op1487);  
					stream_NOTEQUAL.add(lc);

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
					// 236:16: -> ^( OP_NOTEQUAL[$lc] )
					{
						// SemanticParser.g:236:19: ^( OP_NOTEQUAL[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_NOTEQUAL, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 3 :
					// SemanticParser.g:237:4: lc= FEQUAL
					{
					lc=(Token)match(input,FEQUAL,FOLLOW_FEQUAL_in_eq_op1501);  
					stream_FEQUAL.add(lc);

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
					// 237:14: -> ^( OP_FEQUAL[$lc] )
					{
						// SemanticParser.g:237:17: ^( OP_FEQUAL[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FEQUAL, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 4 :
					// SemanticParser.g:238:4: lc= FNOTEQUAL
					{
					lc=(Token)match(input,FNOTEQUAL,FOLLOW_FNOTEQUAL_in_eq_op1515);  
					stream_FNOTEQUAL.add(lc);

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
					// 238:17: -> ^( OP_FNOTEQUAL[$lc] )
					{
						// SemanticParser.g:238:20: ^( OP_FNOTEQUAL[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FNOTEQUAL, lc), root_1);
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
	// $ANTLR end "eq_op"


	public static class expr_comp_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "expr_comp"
	// SemanticParser.g:241:1: expr_comp : expr_shift ( compare_op ^ expr_shift )* ;
	public final SleighParser_SemanticParser.expr_comp_return expr_comp() throws RecognitionException {
		SleighParser_SemanticParser.expr_comp_return retval = new SleighParser_SemanticParser.expr_comp_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope expr_shift95 =null;
		ParserRuleReturnScope compare_op96 =null;
		ParserRuleReturnScope expr_shift97 =null;


		try {
			// SemanticParser.g:242:2: ( expr_shift ( compare_op ^ expr_shift )* )
			// SemanticParser.g:242:4: expr_shift ( compare_op ^ expr_shift )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_expr_shift_in_expr_comp1533);
			expr_shift95=expr_shift();
			state._fsp--;

			adaptor.addChild(root_0, expr_shift95.getTree());

			// SemanticParser.g:242:15: ( compare_op ^ expr_shift )*
			loop20:
			while (true) {
				int alt20=2;
				int LA20_0 = input.LA(1);
				if ( ((LA20_0 >= FGREAT && LA20_0 <= FLESSEQUAL)||(LA20_0 >= GREAT && LA20_0 <= GREATEQUAL)||(LA20_0 >= LESS && LA20_0 <= LESSEQUAL)||(LA20_0 >= SGREAT && LA20_0 <= SGREATEQUAL)||(LA20_0 >= SLESS && LA20_0 <= SLESSEQUAL)) ) {
					alt20=1;
				}

				switch (alt20) {
				case 1 :
					// SemanticParser.g:242:17: compare_op ^ expr_shift
					{
					pushFollow(FOLLOW_compare_op_in_expr_comp1537);
					compare_op96=compare_op();
					state._fsp--;

					root_0 = (CommonTree)adaptor.becomeRoot(compare_op96.getTree(), root_0);
					pushFollow(FOLLOW_expr_shift_in_expr_comp1540);
					expr_shift97=expr_shift();
					state._fsp--;

					adaptor.addChild(root_0, expr_shift97.getTree());

					}
					break;

				default :
					break loop20;
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
	// $ANTLR end "expr_comp"


	public static class compare_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "compare_op"
	// SemanticParser.g:245:1: compare_op : (lc= LESS -> ^( OP_LESS[$lc] ) |lc= GREATEQUAL -> ^( OP_GREATEQUAL[$lc] ) |lc= LESSEQUAL -> ^( OP_LESSEQUAL[$lc] ) |lc= GREAT -> ^( OP_GREAT[$lc] ) |lc= SLESS -> ^( OP_SLESS[$lc] ) |lc= SGREATEQUAL -> ^( OP_SGREATEQUAL[$lc] ) |lc= SLESSEQUAL -> ^( OP_SLESSEQUAL[$lc] ) |lc= SGREAT -> ^( OP_SGREAT[$lc] ) |lc= FLESS -> ^( OP_FLESS[$lc] ) |lc= FGREATEQUAL -> ^( OP_FGREATEQUAL[$lc] ) |lc= FLESSEQUAL -> ^( OP_FLESSEQUAL[$lc] ) |lc= FGREAT -> ^( OP_FGREAT[$lc] ) );
	public final SleighParser_SemanticParser.compare_op_return compare_op() throws RecognitionException {
		SleighParser_SemanticParser.compare_op_return retval = new SleighParser_SemanticParser.compare_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_LESSEQUAL=new RewriteRuleTokenStream(adaptor,"token LESSEQUAL");
		RewriteRuleTokenStream stream_FLESS=new RewriteRuleTokenStream(adaptor,"token FLESS");
		RewriteRuleTokenStream stream_GREAT=new RewriteRuleTokenStream(adaptor,"token GREAT");
		RewriteRuleTokenStream stream_SLESSEQUAL=new RewriteRuleTokenStream(adaptor,"token SLESSEQUAL");
		RewriteRuleTokenStream stream_SGREATEQUAL=new RewriteRuleTokenStream(adaptor,"token SGREATEQUAL");
		RewriteRuleTokenStream stream_FLESSEQUAL=new RewriteRuleTokenStream(adaptor,"token FLESSEQUAL");
		RewriteRuleTokenStream stream_FGREAT=new RewriteRuleTokenStream(adaptor,"token FGREAT");
		RewriteRuleTokenStream stream_SLESS=new RewriteRuleTokenStream(adaptor,"token SLESS");
		RewriteRuleTokenStream stream_LESS=new RewriteRuleTokenStream(adaptor,"token LESS");
		RewriteRuleTokenStream stream_SGREAT=new RewriteRuleTokenStream(adaptor,"token SGREAT");
		RewriteRuleTokenStream stream_GREATEQUAL=new RewriteRuleTokenStream(adaptor,"token GREATEQUAL");
		RewriteRuleTokenStream stream_FGREATEQUAL=new RewriteRuleTokenStream(adaptor,"token FGREATEQUAL");

		try {
			// SemanticParser.g:246:2: (lc= LESS -> ^( OP_LESS[$lc] ) |lc= GREATEQUAL -> ^( OP_GREATEQUAL[$lc] ) |lc= LESSEQUAL -> ^( OP_LESSEQUAL[$lc] ) |lc= GREAT -> ^( OP_GREAT[$lc] ) |lc= SLESS -> ^( OP_SLESS[$lc] ) |lc= SGREATEQUAL -> ^( OP_SGREATEQUAL[$lc] ) |lc= SLESSEQUAL -> ^( OP_SLESSEQUAL[$lc] ) |lc= SGREAT -> ^( OP_SGREAT[$lc] ) |lc= FLESS -> ^( OP_FLESS[$lc] ) |lc= FGREATEQUAL -> ^( OP_FGREATEQUAL[$lc] ) |lc= FLESSEQUAL -> ^( OP_FLESSEQUAL[$lc] ) |lc= FGREAT -> ^( OP_FGREAT[$lc] ) )
			int alt21=12;
			switch ( input.LA(1) ) {
			case LESS:
				{
				alt21=1;
				}
				break;
			case GREATEQUAL:
				{
				alt21=2;
				}
				break;
			case LESSEQUAL:
				{
				alt21=3;
				}
				break;
			case GREAT:
				{
				alt21=4;
				}
				break;
			case SLESS:
				{
				alt21=5;
				}
				break;
			case SGREATEQUAL:
				{
				alt21=6;
				}
				break;
			case SLESSEQUAL:
				{
				alt21=7;
				}
				break;
			case SGREAT:
				{
				alt21=8;
				}
				break;
			case FLESS:
				{
				alt21=9;
				}
				break;
			case FGREATEQUAL:
				{
				alt21=10;
				}
				break;
			case FLESSEQUAL:
				{
				alt21=11;
				}
				break;
			case FGREAT:
				{
				alt21=12;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 21, 0, input);
				throw nvae;
			}
			switch (alt21) {
				case 1 :
					// SemanticParser.g:246:4: lc= LESS
					{
					lc=(Token)match(input,LESS,FOLLOW_LESS_in_compare_op1556);  
					stream_LESS.add(lc);

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
					// 246:12: -> ^( OP_LESS[$lc] )
					{
						// SemanticParser.g:246:15: ^( OP_LESS[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_LESS, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 2 :
					// SemanticParser.g:247:4: lc= GREATEQUAL
					{
					lc=(Token)match(input,GREATEQUAL,FOLLOW_GREATEQUAL_in_compare_op1570);  
					stream_GREATEQUAL.add(lc);

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
					// 247:18: -> ^( OP_GREATEQUAL[$lc] )
					{
						// SemanticParser.g:247:21: ^( OP_GREATEQUAL[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_GREATEQUAL, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 3 :
					// SemanticParser.g:248:4: lc= LESSEQUAL
					{
					lc=(Token)match(input,LESSEQUAL,FOLLOW_LESSEQUAL_in_compare_op1584);  
					stream_LESSEQUAL.add(lc);

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
					// 248:17: -> ^( OP_LESSEQUAL[$lc] )
					{
						// SemanticParser.g:248:20: ^( OP_LESSEQUAL[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_LESSEQUAL, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 4 :
					// SemanticParser.g:249:4: lc= GREAT
					{
					lc=(Token)match(input,GREAT,FOLLOW_GREAT_in_compare_op1598);  
					stream_GREAT.add(lc);

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
					// 249:13: -> ^( OP_GREAT[$lc] )
					{
						// SemanticParser.g:249:16: ^( OP_GREAT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_GREAT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 5 :
					// SemanticParser.g:250:4: lc= SLESS
					{
					lc=(Token)match(input,SLESS,FOLLOW_SLESS_in_compare_op1612);  
					stream_SLESS.add(lc);

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
					// 250:13: -> ^( OP_SLESS[$lc] )
					{
						// SemanticParser.g:250:16: ^( OP_SLESS[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SLESS, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 6 :
					// SemanticParser.g:251:4: lc= SGREATEQUAL
					{
					lc=(Token)match(input,SGREATEQUAL,FOLLOW_SGREATEQUAL_in_compare_op1626);  
					stream_SGREATEQUAL.add(lc);

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
					// 251:19: -> ^( OP_SGREATEQUAL[$lc] )
					{
						// SemanticParser.g:251:22: ^( OP_SGREATEQUAL[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SGREATEQUAL, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 7 :
					// SemanticParser.g:252:4: lc= SLESSEQUAL
					{
					lc=(Token)match(input,SLESSEQUAL,FOLLOW_SLESSEQUAL_in_compare_op1640);  
					stream_SLESSEQUAL.add(lc);

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
					// 252:18: -> ^( OP_SLESSEQUAL[$lc] )
					{
						// SemanticParser.g:252:21: ^( OP_SLESSEQUAL[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SLESSEQUAL, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 8 :
					// SemanticParser.g:253:4: lc= SGREAT
					{
					lc=(Token)match(input,SGREAT,FOLLOW_SGREAT_in_compare_op1654);  
					stream_SGREAT.add(lc);

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
					// 253:14: -> ^( OP_SGREAT[$lc] )
					{
						// SemanticParser.g:253:17: ^( OP_SGREAT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SGREAT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 9 :
					// SemanticParser.g:254:4: lc= FLESS
					{
					lc=(Token)match(input,FLESS,FOLLOW_FLESS_in_compare_op1668);  
					stream_FLESS.add(lc);

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
					// 254:13: -> ^( OP_FLESS[$lc] )
					{
						// SemanticParser.g:254:16: ^( OP_FLESS[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FLESS, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 10 :
					// SemanticParser.g:255:4: lc= FGREATEQUAL
					{
					lc=(Token)match(input,FGREATEQUAL,FOLLOW_FGREATEQUAL_in_compare_op1682);  
					stream_FGREATEQUAL.add(lc);

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
					// 255:19: -> ^( OP_FGREATEQUAL[$lc] )
					{
						// SemanticParser.g:255:22: ^( OP_FGREATEQUAL[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FGREATEQUAL, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 11 :
					// SemanticParser.g:256:4: lc= FLESSEQUAL
					{
					lc=(Token)match(input,FLESSEQUAL,FOLLOW_FLESSEQUAL_in_compare_op1696);  
					stream_FLESSEQUAL.add(lc);

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
					// 256:18: -> ^( OP_FLESSEQUAL[$lc] )
					{
						// SemanticParser.g:256:21: ^( OP_FLESSEQUAL[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FLESSEQUAL, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 12 :
					// SemanticParser.g:257:4: lc= FGREAT
					{
					lc=(Token)match(input,FGREAT,FOLLOW_FGREAT_in_compare_op1710);  
					stream_FGREAT.add(lc);

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
					// 257:14: -> ^( OP_FGREAT[$lc] )
					{
						// SemanticParser.g:257:17: ^( OP_FGREAT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FGREAT, lc), root_1);
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
	// $ANTLR end "compare_op"


	public static class expr_shift_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "expr_shift"
	// SemanticParser.g:260:1: expr_shift : expr_add ( shift_op ^ expr_add )* ;
	public final SleighParser_SemanticParser.expr_shift_return expr_shift() throws RecognitionException {
		SleighParser_SemanticParser.expr_shift_return retval = new SleighParser_SemanticParser.expr_shift_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope expr_add98 =null;
		ParserRuleReturnScope shift_op99 =null;
		ParserRuleReturnScope expr_add100 =null;


		try {
			// SemanticParser.g:261:2: ( expr_add ( shift_op ^ expr_add )* )
			// SemanticParser.g:261:4: expr_add ( shift_op ^ expr_add )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_expr_add_in_expr_shift1728);
			expr_add98=expr_add();
			state._fsp--;

			adaptor.addChild(root_0, expr_add98.getTree());

			// SemanticParser.g:261:13: ( shift_op ^ expr_add )*
			loop22:
			while (true) {
				int alt22=2;
				int LA22_0 = input.LA(1);
				if ( (LA22_0==LEFT||LA22_0==RIGHT||LA22_0==SRIGHT) ) {
					alt22=1;
				}

				switch (alt22) {
				case 1 :
					// SemanticParser.g:261:15: shift_op ^ expr_add
					{
					pushFollow(FOLLOW_shift_op_in_expr_shift1732);
					shift_op99=shift_op();
					state._fsp--;

					root_0 = (CommonTree)adaptor.becomeRoot(shift_op99.getTree(), root_0);
					pushFollow(FOLLOW_expr_add_in_expr_shift1735);
					expr_add100=expr_add();
					state._fsp--;

					adaptor.addChild(root_0, expr_add100.getTree());

					}
					break;

				default :
					break loop22;
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
	// $ANTLR end "expr_shift"


	public static class shift_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "shift_op"
	// SemanticParser.g:264:1: shift_op : (lc= LEFT -> ^( OP_LEFT[$lc] ) |lc= RIGHT -> ^( OP_RIGHT[$lc] ) |lc= SRIGHT -> ^( OP_SRIGHT[$lc] ) );
	public final SleighParser_SemanticParser.shift_op_return shift_op() throws RecognitionException {
		SleighParser_SemanticParser.shift_op_return retval = new SleighParser_SemanticParser.shift_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_SRIGHT=new RewriteRuleTokenStream(adaptor,"token SRIGHT");
		RewriteRuleTokenStream stream_LEFT=new RewriteRuleTokenStream(adaptor,"token LEFT");
		RewriteRuleTokenStream stream_RIGHT=new RewriteRuleTokenStream(adaptor,"token RIGHT");

		try {
			// SemanticParser.g:265:2: (lc= LEFT -> ^( OP_LEFT[$lc] ) |lc= RIGHT -> ^( OP_RIGHT[$lc] ) |lc= SRIGHT -> ^( OP_SRIGHT[$lc] ) )
			int alt23=3;
			switch ( input.LA(1) ) {
			case LEFT:
				{
				alt23=1;
				}
				break;
			case RIGHT:
				{
				alt23=2;
				}
				break;
			case SRIGHT:
				{
				alt23=3;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 23, 0, input);
				throw nvae;
			}
			switch (alt23) {
				case 1 :
					// SemanticParser.g:265:4: lc= LEFT
					{
					lc=(Token)match(input,LEFT,FOLLOW_LEFT_in_shift_op1751);  
					stream_LEFT.add(lc);

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
					// 265:12: -> ^( OP_LEFT[$lc] )
					{
						// SemanticParser.g:265:15: ^( OP_LEFT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_LEFT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 2 :
					// SemanticParser.g:266:4: lc= RIGHT
					{
					lc=(Token)match(input,RIGHT,FOLLOW_RIGHT_in_shift_op1765);  
					stream_RIGHT.add(lc);

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
					// 266:13: -> ^( OP_RIGHT[$lc] )
					{
						// SemanticParser.g:266:16: ^( OP_RIGHT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_RIGHT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 3 :
					// SemanticParser.g:267:4: lc= SRIGHT
					{
					lc=(Token)match(input,SRIGHT,FOLLOW_SRIGHT_in_shift_op1779);  
					stream_SRIGHT.add(lc);

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
					// 267:14: -> ^( OP_SRIGHT[$lc] )
					{
						// SemanticParser.g:267:17: ^( OP_SRIGHT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SRIGHT, lc), root_1);
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
	// $ANTLR end "shift_op"


	public static class expr_add_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "expr_add"
	// SemanticParser.g:270:1: expr_add : expr_mult ( add_op ^ expr_mult )* ;
	public final SleighParser_SemanticParser.expr_add_return expr_add() throws RecognitionException {
		SleighParser_SemanticParser.expr_add_return retval = new SleighParser_SemanticParser.expr_add_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope expr_mult101 =null;
		ParserRuleReturnScope add_op102 =null;
		ParserRuleReturnScope expr_mult103 =null;


		try {
			// SemanticParser.g:271:2: ( expr_mult ( add_op ^ expr_mult )* )
			// SemanticParser.g:271:4: expr_mult ( add_op ^ expr_mult )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_expr_mult_in_expr_add1797);
			expr_mult101=expr_mult();
			state._fsp--;

			adaptor.addChild(root_0, expr_mult101.getTree());

			// SemanticParser.g:271:14: ( add_op ^ expr_mult )*
			loop24:
			while (true) {
				int alt24=2;
				int LA24_0 = input.LA(1);
				if ( (LA24_0==FMINUS||LA24_0==FPLUS||LA24_0==MINUS||LA24_0==PLUS) ) {
					alt24=1;
				}

				switch (alt24) {
				case 1 :
					// SemanticParser.g:271:16: add_op ^ expr_mult
					{
					pushFollow(FOLLOW_add_op_in_expr_add1801);
					add_op102=add_op();
					state._fsp--;

					root_0 = (CommonTree)adaptor.becomeRoot(add_op102.getTree(), root_0);
					pushFollow(FOLLOW_expr_mult_in_expr_add1804);
					expr_mult103=expr_mult();
					state._fsp--;

					adaptor.addChild(root_0, expr_mult103.getTree());

					}
					break;

				default :
					break loop24;
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
	// $ANTLR end "expr_add"


	public static class add_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "add_op"
	// SemanticParser.g:274:1: add_op : (lc= PLUS -> ^( OP_ADD[$lc] ) |lc= MINUS -> ^( OP_SUB[$lc] ) |lc= FPLUS -> ^( OP_FADD[$lc] ) |lc= FMINUS -> ^( OP_FSUB[$lc] ) );
	public final SleighParser_SemanticParser.add_op_return add_op() throws RecognitionException {
		SleighParser_SemanticParser.add_op_return retval = new SleighParser_SemanticParser.add_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_FMINUS=new RewriteRuleTokenStream(adaptor,"token FMINUS");
		RewriteRuleTokenStream stream_PLUS=new RewriteRuleTokenStream(adaptor,"token PLUS");
		RewriteRuleTokenStream stream_MINUS=new RewriteRuleTokenStream(adaptor,"token MINUS");
		RewriteRuleTokenStream stream_FPLUS=new RewriteRuleTokenStream(adaptor,"token FPLUS");

		try {
			// SemanticParser.g:275:2: (lc= PLUS -> ^( OP_ADD[$lc] ) |lc= MINUS -> ^( OP_SUB[$lc] ) |lc= FPLUS -> ^( OP_FADD[$lc] ) |lc= FMINUS -> ^( OP_FSUB[$lc] ) )
			int alt25=4;
			switch ( input.LA(1) ) {
			case PLUS:
				{
				alt25=1;
				}
				break;
			case MINUS:
				{
				alt25=2;
				}
				break;
			case FPLUS:
				{
				alt25=3;
				}
				break;
			case FMINUS:
				{
				alt25=4;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 25, 0, input);
				throw nvae;
			}
			switch (alt25) {
				case 1 :
					// SemanticParser.g:275:4: lc= PLUS
					{
					lc=(Token)match(input,PLUS,FOLLOW_PLUS_in_add_op1820);  
					stream_PLUS.add(lc);

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
					// 275:12: -> ^( OP_ADD[$lc] )
					{
						// SemanticParser.g:275:15: ^( OP_ADD[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_ADD, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 2 :
					// SemanticParser.g:276:4: lc= MINUS
					{
					lc=(Token)match(input,MINUS,FOLLOW_MINUS_in_add_op1834);  
					stream_MINUS.add(lc);

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
					// 276:13: -> ^( OP_SUB[$lc] )
					{
						// SemanticParser.g:276:16: ^( OP_SUB[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SUB, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 3 :
					// SemanticParser.g:277:4: lc= FPLUS
					{
					lc=(Token)match(input,FPLUS,FOLLOW_FPLUS_in_add_op1848);  
					stream_FPLUS.add(lc);

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
					// 277:13: -> ^( OP_FADD[$lc] )
					{
						// SemanticParser.g:277:16: ^( OP_FADD[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FADD, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 4 :
					// SemanticParser.g:278:4: lc= FMINUS
					{
					lc=(Token)match(input,FMINUS,FOLLOW_FMINUS_in_add_op1862);  
					stream_FMINUS.add(lc);

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
					// 278:14: -> ^( OP_FSUB[$lc] )
					{
						// SemanticParser.g:278:17: ^( OP_FSUB[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FSUB, lc), root_1);
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
	// $ANTLR end "add_op"


	public static class expr_mult_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "expr_mult"
	// SemanticParser.g:281:1: expr_mult : expr_unary ( mult_op ^ expr_unary )* ;
	public final SleighParser_SemanticParser.expr_mult_return expr_mult() throws RecognitionException {
		SleighParser_SemanticParser.expr_mult_return retval = new SleighParser_SemanticParser.expr_mult_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope expr_unary104 =null;
		ParserRuleReturnScope mult_op105 =null;
		ParserRuleReturnScope expr_unary106 =null;


		try {
			// SemanticParser.g:282:2: ( expr_unary ( mult_op ^ expr_unary )* )
			// SemanticParser.g:282:4: expr_unary ( mult_op ^ expr_unary )*
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_expr_unary_in_expr_mult1880);
			expr_unary104=expr_unary();
			state._fsp--;

			adaptor.addChild(root_0, expr_unary104.getTree());

			// SemanticParser.g:282:15: ( mult_op ^ expr_unary )*
			loop26:
			while (true) {
				int alt26=2;
				int LA26_0 = input.LA(1);
				if ( (LA26_0==ASTERISK||LA26_0==FDIV||LA26_0==FMULT||LA26_0==PERCENT||LA26_0==SDIV||LA26_0==SLASH||LA26_0==SREM) ) {
					alt26=1;
				}

				switch (alt26) {
				case 1 :
					// SemanticParser.g:282:17: mult_op ^ expr_unary
					{
					pushFollow(FOLLOW_mult_op_in_expr_mult1884);
					mult_op105=mult_op();
					state._fsp--;

					root_0 = (CommonTree)adaptor.becomeRoot(mult_op105.getTree(), root_0);
					pushFollow(FOLLOW_expr_unary_in_expr_mult1887);
					expr_unary106=expr_unary();
					state._fsp--;

					adaptor.addChild(root_0, expr_unary106.getTree());

					}
					break;

				default :
					break loop26;
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
	// $ANTLR end "expr_mult"


	public static class mult_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "mult_op"
	// SemanticParser.g:285:1: mult_op : (lc= ASTERISK -> ^( OP_MULT[$lc] ) |lc= SLASH -> ^( OP_DIV[$lc] ) |lc= PERCENT -> ^( OP_REM[$lc] ) |lc= SDIV -> ^( OP_SDIV[$lc] ) |lc= SREM -> ^( OP_SREM[$lc] ) |lc= FMULT -> ^( OP_FMULT[$lc] ) |lc= FDIV -> ^( OP_FDIV[$lc] ) );
	public final SleighParser_SemanticParser.mult_op_return mult_op() throws RecognitionException {
		SleighParser_SemanticParser.mult_op_return retval = new SleighParser_SemanticParser.mult_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_SREM=new RewriteRuleTokenStream(adaptor,"token SREM");
		RewriteRuleTokenStream stream_PERCENT=new RewriteRuleTokenStream(adaptor,"token PERCENT");
		RewriteRuleTokenStream stream_SLASH=new RewriteRuleTokenStream(adaptor,"token SLASH");
		RewriteRuleTokenStream stream_SDIV=new RewriteRuleTokenStream(adaptor,"token SDIV");
		RewriteRuleTokenStream stream_FMULT=new RewriteRuleTokenStream(adaptor,"token FMULT");
		RewriteRuleTokenStream stream_ASTERISK=new RewriteRuleTokenStream(adaptor,"token ASTERISK");
		RewriteRuleTokenStream stream_FDIV=new RewriteRuleTokenStream(adaptor,"token FDIV");

		try {
			// SemanticParser.g:286:2: (lc= ASTERISK -> ^( OP_MULT[$lc] ) |lc= SLASH -> ^( OP_DIV[$lc] ) |lc= PERCENT -> ^( OP_REM[$lc] ) |lc= SDIV -> ^( OP_SDIV[$lc] ) |lc= SREM -> ^( OP_SREM[$lc] ) |lc= FMULT -> ^( OP_FMULT[$lc] ) |lc= FDIV -> ^( OP_FDIV[$lc] ) )
			int alt27=7;
			switch ( input.LA(1) ) {
			case ASTERISK:
				{
				alt27=1;
				}
				break;
			case SLASH:
				{
				alt27=2;
				}
				break;
			case PERCENT:
				{
				alt27=3;
				}
				break;
			case SDIV:
				{
				alt27=4;
				}
				break;
			case SREM:
				{
				alt27=5;
				}
				break;
			case FMULT:
				{
				alt27=6;
				}
				break;
			case FDIV:
				{
				alt27=7;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 27, 0, input);
				throw nvae;
			}
			switch (alt27) {
				case 1 :
					// SemanticParser.g:286:4: lc= ASTERISK
					{
					lc=(Token)match(input,ASTERISK,FOLLOW_ASTERISK_in_mult_op1903);  
					stream_ASTERISK.add(lc);

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
					// 286:16: -> ^( OP_MULT[$lc] )
					{
						// SemanticParser.g:286:19: ^( OP_MULT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_MULT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 2 :
					// SemanticParser.g:287:4: lc= SLASH
					{
					lc=(Token)match(input,SLASH,FOLLOW_SLASH_in_mult_op1917);  
					stream_SLASH.add(lc);

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
					// 287:13: -> ^( OP_DIV[$lc] )
					{
						// SemanticParser.g:287:16: ^( OP_DIV[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_DIV, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 3 :
					// SemanticParser.g:288:4: lc= PERCENT
					{
					lc=(Token)match(input,PERCENT,FOLLOW_PERCENT_in_mult_op1931);  
					stream_PERCENT.add(lc);

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
					// 288:15: -> ^( OP_REM[$lc] )
					{
						// SemanticParser.g:288:18: ^( OP_REM[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_REM, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 4 :
					// SemanticParser.g:289:4: lc= SDIV
					{
					lc=(Token)match(input,SDIV,FOLLOW_SDIV_in_mult_op1945);  
					stream_SDIV.add(lc);

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
					// 289:12: -> ^( OP_SDIV[$lc] )
					{
						// SemanticParser.g:289:15: ^( OP_SDIV[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SDIV, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 5 :
					// SemanticParser.g:290:4: lc= SREM
					{
					lc=(Token)match(input,SREM,FOLLOW_SREM_in_mult_op1959);  
					stream_SREM.add(lc);

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
					// 290:12: -> ^( OP_SREM[$lc] )
					{
						// SemanticParser.g:290:15: ^( OP_SREM[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SREM, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 6 :
					// SemanticParser.g:291:4: lc= FMULT
					{
					lc=(Token)match(input,FMULT,FOLLOW_FMULT_in_mult_op1973);  
					stream_FMULT.add(lc);

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
					// 291:13: -> ^( OP_FMULT[$lc] )
					{
						// SemanticParser.g:291:16: ^( OP_FMULT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FMULT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 7 :
					// SemanticParser.g:292:4: lc= FDIV
					{
					lc=(Token)match(input,FDIV,FOLLOW_FDIV_in_mult_op1987);  
					stream_FDIV.add(lc);

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
					// 292:12: -> ^( OP_FDIV[$lc] )
					{
						// SemanticParser.g:292:15: ^( OP_FDIV[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FDIV, lc), root_1);
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
	// $ANTLR end "mult_op"


	public static class expr_unary_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "expr_unary"
	// SemanticParser.g:295:1: expr_unary : ( unary_op ^)? expr_func ;
	public final SleighParser_SemanticParser.expr_unary_return expr_unary() throws RecognitionException {
		SleighParser_SemanticParser.expr_unary_return retval = new SleighParser_SemanticParser.expr_unary_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope unary_op107 =null;
		ParserRuleReturnScope expr_func108 =null;


		try {
			// SemanticParser.g:296:2: ( ( unary_op ^)? expr_func )
			// SemanticParser.g:296:4: ( unary_op ^)? expr_func
			{
			root_0 = (CommonTree)adaptor.nil();


			// SemanticParser.g:296:12: ( unary_op ^)?
			int alt28=2;
			int LA28_0 = input.LA(1);
			if ( (LA28_0==ASTERISK||LA28_0==EXCLAIM||LA28_0==FMINUS||LA28_0==MINUS||LA28_0==TILDE) ) {
				alt28=1;
			}
			switch (alt28) {
				case 1 :
					// SemanticParser.g:296:12: unary_op ^
					{
					pushFollow(FOLLOW_unary_op_in_expr_unary2005);
					unary_op107=unary_op();
					state._fsp--;

					root_0 = (CommonTree)adaptor.becomeRoot(unary_op107.getTree(), root_0);
					}
					break;

			}

			pushFollow(FOLLOW_expr_func_in_expr_unary2010);
			expr_func108=expr_func();
			state._fsp--;

			adaptor.addChild(root_0, expr_func108.getTree());

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
	// $ANTLR end "expr_unary"


	public static class unary_op_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "unary_op"
	// SemanticParser.g:299:1: unary_op : (lc= EXCLAIM -> ^( OP_NOT[$lc] ) |lc= TILDE -> ^( OP_INVERT[$lc] ) |lc= MINUS -> ^( OP_NEGATE[$lc] ) |lc= FMINUS -> ^( OP_FNEGATE[$lc] ) | sizedstar );
	public final SleighParser_SemanticParser.unary_op_return unary_op() throws RecognitionException {
		SleighParser_SemanticParser.unary_op_return retval = new SleighParser_SemanticParser.unary_op_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		ParserRuleReturnScope sizedstar109 =null;

		CommonTree lc_tree=null;
		RewriteRuleTokenStream stream_EXCLAIM=new RewriteRuleTokenStream(adaptor,"token EXCLAIM");
		RewriteRuleTokenStream stream_FMINUS=new RewriteRuleTokenStream(adaptor,"token FMINUS");
		RewriteRuleTokenStream stream_TILDE=new RewriteRuleTokenStream(adaptor,"token TILDE");
		RewriteRuleTokenStream stream_MINUS=new RewriteRuleTokenStream(adaptor,"token MINUS");

		try {
			// SemanticParser.g:300:2: (lc= EXCLAIM -> ^( OP_NOT[$lc] ) |lc= TILDE -> ^( OP_INVERT[$lc] ) |lc= MINUS -> ^( OP_NEGATE[$lc] ) |lc= FMINUS -> ^( OP_FNEGATE[$lc] ) | sizedstar )
			int alt29=5;
			switch ( input.LA(1) ) {
			case EXCLAIM:
				{
				alt29=1;
				}
				break;
			case TILDE:
				{
				alt29=2;
				}
				break;
			case MINUS:
				{
				alt29=3;
				}
				break;
			case FMINUS:
				{
				alt29=4;
				}
				break;
			case ASTERISK:
				{
				alt29=5;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 29, 0, input);
				throw nvae;
			}
			switch (alt29) {
				case 1 :
					// SemanticParser.g:300:4: lc= EXCLAIM
					{
					lc=(Token)match(input,EXCLAIM,FOLLOW_EXCLAIM_in_unary_op2023);  
					stream_EXCLAIM.add(lc);

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
					// 300:15: -> ^( OP_NOT[$lc] )
					{
						// SemanticParser.g:300:18: ^( OP_NOT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_NOT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 2 :
					// SemanticParser.g:301:4: lc= TILDE
					{
					lc=(Token)match(input,TILDE,FOLLOW_TILDE_in_unary_op2037);  
					stream_TILDE.add(lc);

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
					// 301:13: -> ^( OP_INVERT[$lc] )
					{
						// SemanticParser.g:301:16: ^( OP_INVERT[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_INVERT, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 3 :
					// SemanticParser.g:302:4: lc= MINUS
					{
					lc=(Token)match(input,MINUS,FOLLOW_MINUS_in_unary_op2051);  
					stream_MINUS.add(lc);

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
					// 302:13: -> ^( OP_NEGATE[$lc] )
					{
						// SemanticParser.g:302:16: ^( OP_NEGATE[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_NEGATE, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 4 :
					// SemanticParser.g:303:4: lc= FMINUS
					{
					lc=(Token)match(input,FMINUS,FOLLOW_FMINUS_in_unary_op2065);  
					stream_FMINUS.add(lc);

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
					// 303:14: -> ^( OP_FNEGATE[$lc] )
					{
						// SemanticParser.g:303:17: ^( OP_FNEGATE[$lc] )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_FNEGATE, lc), root_1);
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 5 :
					// SemanticParser.g:304:4: sizedstar
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_sizedstar_in_unary_op2077);
					sizedstar109=sizedstar();
					state._fsp--;

					adaptor.addChild(root_0, sizedstar109.getTree());

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
	// $ANTLR end "unary_op"


	public static class expr_func_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "expr_func"
	// SemanticParser.g:307:1: expr_func : ( expr_apply | expr_term );
	public final SleighParser_SemanticParser.expr_func_return expr_func() throws RecognitionException {
		SleighParser_SemanticParser.expr_func_return retval = new SleighParser_SemanticParser.expr_func_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope expr_apply110 =null;
		ParserRuleReturnScope expr_term111 =null;


		try {
			// SemanticParser.g:308:2: ( expr_apply | expr_term )
			int alt30=2;
			switch ( input.LA(1) ) {
			case IDENTIFIER:
				{
				int LA30_1 = input.LA(2);
				if ( (LA30_1==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_1 >= AMPERSAND && LA30_1 <= ASTERISK)||(LA30_1 >= BOOL_AND && LA30_1 <= COMMA)||LA30_1==EQUAL||(LA30_1 >= FDIV && LA30_1 <= GREATEQUAL)||LA30_1==KEY_GOTO||(LA30_1 >= LBRACKET && LA30_1 <= LESSEQUAL)||(LA30_1 >= MINUS && LA30_1 <= NOTEQUAL)||(LA30_1 >= PERCENT && LA30_1 <= PLUS)||LA30_1==RBRACKET||(LA30_1 >= RIGHT && LA30_1 <= SLESSEQUAL)||(LA30_1 >= SREM && LA30_1 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ALIGNMENT:
				{
				int LA30_2 = input.LA(2);
				if ( (LA30_2==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_2 >= AMPERSAND && LA30_2 <= ASTERISK)||(LA30_2 >= BOOL_AND && LA30_2 <= COMMA)||LA30_2==EQUAL||(LA30_2 >= FDIV && LA30_2 <= GREATEQUAL)||LA30_2==KEY_GOTO||(LA30_2 >= LBRACKET && LA30_2 <= LESSEQUAL)||(LA30_2 >= MINUS && LA30_2 <= NOTEQUAL)||(LA30_2 >= PERCENT && LA30_2 <= PLUS)||LA30_2==RBRACKET||(LA30_2 >= RIGHT && LA30_2 <= SLESSEQUAL)||(LA30_2 >= SREM && LA30_2 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 2, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ATTACH:
				{
				int LA30_3 = input.LA(2);
				if ( (LA30_3==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_3 >= AMPERSAND && LA30_3 <= ASTERISK)||(LA30_3 >= BOOL_AND && LA30_3 <= COMMA)||LA30_3==EQUAL||(LA30_3 >= FDIV && LA30_3 <= GREATEQUAL)||LA30_3==KEY_GOTO||(LA30_3 >= LBRACKET && LA30_3 <= LESSEQUAL)||(LA30_3 >= MINUS && LA30_3 <= NOTEQUAL)||(LA30_3 >= PERCENT && LA30_3 <= PLUS)||LA30_3==RBRACKET||(LA30_3 >= RIGHT && LA30_3 <= SLESSEQUAL)||(LA30_3 >= SREM && LA30_3 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 3, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BIG:
				{
				int LA30_4 = input.LA(2);
				if ( (LA30_4==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_4 >= AMPERSAND && LA30_4 <= ASTERISK)||(LA30_4 >= BOOL_AND && LA30_4 <= COMMA)||LA30_4==EQUAL||(LA30_4 >= FDIV && LA30_4 <= GREATEQUAL)||LA30_4==KEY_GOTO||(LA30_4 >= LBRACKET && LA30_4 <= LESSEQUAL)||(LA30_4 >= MINUS && LA30_4 <= NOTEQUAL)||(LA30_4 >= PERCENT && LA30_4 <= PLUS)||LA30_4==RBRACKET||(LA30_4 >= RIGHT && LA30_4 <= SLESSEQUAL)||(LA30_4 >= SREM && LA30_4 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 4, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BITRANGE:
				{
				int LA30_5 = input.LA(2);
				if ( (LA30_5==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_5 >= AMPERSAND && LA30_5 <= ASTERISK)||(LA30_5 >= BOOL_AND && LA30_5 <= COMMA)||LA30_5==EQUAL||(LA30_5 >= FDIV && LA30_5 <= GREATEQUAL)||LA30_5==KEY_GOTO||(LA30_5 >= LBRACKET && LA30_5 <= LESSEQUAL)||(LA30_5 >= MINUS && LA30_5 <= NOTEQUAL)||(LA30_5 >= PERCENT && LA30_5 <= PLUS)||LA30_5==RBRACKET||(LA30_5 >= RIGHT && LA30_5 <= SLESSEQUAL)||(LA30_5 >= SREM && LA30_5 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 5, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BUILD:
				{
				int LA30_6 = input.LA(2);
				if ( (LA30_6==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_6 >= AMPERSAND && LA30_6 <= ASTERISK)||(LA30_6 >= BOOL_AND && LA30_6 <= COMMA)||LA30_6==EQUAL||(LA30_6 >= FDIV && LA30_6 <= GREATEQUAL)||LA30_6==KEY_GOTO||(LA30_6 >= LBRACKET && LA30_6 <= LESSEQUAL)||(LA30_6 >= MINUS && LA30_6 <= NOTEQUAL)||(LA30_6 >= PERCENT && LA30_6 <= PLUS)||LA30_6==RBRACKET||(LA30_6 >= RIGHT && LA30_6 <= SLESSEQUAL)||(LA30_6 >= SREM && LA30_6 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 6, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CALL:
				{
				int LA30_7 = input.LA(2);
				if ( (LA30_7==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_7 >= AMPERSAND && LA30_7 <= ASTERISK)||(LA30_7 >= BOOL_AND && LA30_7 <= COMMA)||LA30_7==EQUAL||(LA30_7 >= FDIV && LA30_7 <= GREATEQUAL)||LA30_7==KEY_GOTO||(LA30_7 >= LBRACKET && LA30_7 <= LESSEQUAL)||(LA30_7 >= MINUS && LA30_7 <= NOTEQUAL)||(LA30_7 >= PERCENT && LA30_7 <= PLUS)||LA30_7==RBRACKET||(LA30_7 >= RIGHT && LA30_7 <= SLESSEQUAL)||(LA30_7 >= SREM && LA30_7 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 7, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CONTEXT:
				{
				int LA30_8 = input.LA(2);
				if ( (LA30_8==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_8 >= AMPERSAND && LA30_8 <= ASTERISK)||(LA30_8 >= BOOL_AND && LA30_8 <= COMMA)||LA30_8==EQUAL||(LA30_8 >= FDIV && LA30_8 <= GREATEQUAL)||LA30_8==KEY_GOTO||(LA30_8 >= LBRACKET && LA30_8 <= LESSEQUAL)||(LA30_8 >= MINUS && LA30_8 <= NOTEQUAL)||(LA30_8 >= PERCENT && LA30_8 <= PLUS)||LA30_8==RBRACKET||(LA30_8 >= RIGHT && LA30_8 <= SLESSEQUAL)||(LA30_8 >= SREM && LA30_8 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 8, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CROSSBUILD:
				{
				int LA30_9 = input.LA(2);
				if ( (LA30_9==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_9 >= AMPERSAND && LA30_9 <= ASTERISK)||(LA30_9 >= BOOL_AND && LA30_9 <= COMMA)||LA30_9==EQUAL||(LA30_9 >= FDIV && LA30_9 <= GREATEQUAL)||LA30_9==KEY_GOTO||(LA30_9 >= LBRACKET && LA30_9 <= LESSEQUAL)||(LA30_9 >= MINUS && LA30_9 <= NOTEQUAL)||(LA30_9 >= PERCENT && LA30_9 <= PLUS)||LA30_9==RBRACKET||(LA30_9 >= RIGHT && LA30_9 <= SLESSEQUAL)||(LA30_9 >= SREM && LA30_9 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 9, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEC:
				{
				int LA30_10 = input.LA(2);
				if ( (LA30_10==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_10 >= AMPERSAND && LA30_10 <= ASTERISK)||(LA30_10 >= BOOL_AND && LA30_10 <= COMMA)||LA30_10==EQUAL||(LA30_10 >= FDIV && LA30_10 <= GREATEQUAL)||LA30_10==KEY_GOTO||(LA30_10 >= LBRACKET && LA30_10 <= LESSEQUAL)||(LA30_10 >= MINUS && LA30_10 <= NOTEQUAL)||(LA30_10 >= PERCENT && LA30_10 <= PLUS)||LA30_10==RBRACKET||(LA30_10 >= RIGHT && LA30_10 <= SLESSEQUAL)||(LA30_10 >= SREM && LA30_10 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 10, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEFAULT:
				{
				int LA30_11 = input.LA(2);
				if ( (LA30_11==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_11 >= AMPERSAND && LA30_11 <= ASTERISK)||(LA30_11 >= BOOL_AND && LA30_11 <= COMMA)||LA30_11==EQUAL||(LA30_11 >= FDIV && LA30_11 <= GREATEQUAL)||LA30_11==KEY_GOTO||(LA30_11 >= LBRACKET && LA30_11 <= LESSEQUAL)||(LA30_11 >= MINUS && LA30_11 <= NOTEQUAL)||(LA30_11 >= PERCENT && LA30_11 <= PLUS)||LA30_11==RBRACKET||(LA30_11 >= RIGHT && LA30_11 <= SLESSEQUAL)||(LA30_11 >= SREM && LA30_11 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 11, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEFINE:
				{
				int LA30_12 = input.LA(2);
				if ( (LA30_12==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_12 >= AMPERSAND && LA30_12 <= ASTERISK)||(LA30_12 >= BOOL_AND && LA30_12 <= COMMA)||LA30_12==EQUAL||(LA30_12 >= FDIV && LA30_12 <= GREATEQUAL)||LA30_12==KEY_GOTO||(LA30_12 >= LBRACKET && LA30_12 <= LESSEQUAL)||(LA30_12 >= MINUS && LA30_12 <= NOTEQUAL)||(LA30_12 >= PERCENT && LA30_12 <= PLUS)||LA30_12==RBRACKET||(LA30_12 >= RIGHT && LA30_12 <= SLESSEQUAL)||(LA30_12 >= SREM && LA30_12 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 12, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ENDIAN:
				{
				int LA30_13 = input.LA(2);
				if ( (LA30_13==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_13 >= AMPERSAND && LA30_13 <= ASTERISK)||(LA30_13 >= BOOL_AND && LA30_13 <= COMMA)||LA30_13==EQUAL||(LA30_13 >= FDIV && LA30_13 <= GREATEQUAL)||LA30_13==KEY_GOTO||(LA30_13 >= LBRACKET && LA30_13 <= LESSEQUAL)||(LA30_13 >= MINUS && LA30_13 <= NOTEQUAL)||(LA30_13 >= PERCENT && LA30_13 <= PLUS)||LA30_13==RBRACKET||(LA30_13 >= RIGHT && LA30_13 <= SLESSEQUAL)||(LA30_13 >= SREM && LA30_13 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 13, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_EXPORT:
				{
				int LA30_14 = input.LA(2);
				if ( (LA30_14==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_14 >= AMPERSAND && LA30_14 <= ASTERISK)||(LA30_14 >= BOOL_AND && LA30_14 <= COMMA)||LA30_14==EQUAL||(LA30_14 >= FDIV && LA30_14 <= GREATEQUAL)||LA30_14==KEY_GOTO||(LA30_14 >= LBRACKET && LA30_14 <= LESSEQUAL)||(LA30_14 >= MINUS && LA30_14 <= NOTEQUAL)||(LA30_14 >= PERCENT && LA30_14 <= PLUS)||LA30_14==RBRACKET||(LA30_14 >= RIGHT && LA30_14 <= SLESSEQUAL)||(LA30_14 >= SREM && LA30_14 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 14, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_GOTO:
				{
				int LA30_15 = input.LA(2);
				if ( (LA30_15==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_15 >= AMPERSAND && LA30_15 <= ASTERISK)||(LA30_15 >= BOOL_AND && LA30_15 <= COMMA)||LA30_15==EQUAL||(LA30_15 >= FDIV && LA30_15 <= GREATEQUAL)||LA30_15==KEY_GOTO||(LA30_15 >= LBRACKET && LA30_15 <= LESSEQUAL)||(LA30_15 >= MINUS && LA30_15 <= NOTEQUAL)||(LA30_15 >= PERCENT && LA30_15 <= PLUS)||LA30_15==RBRACKET||(LA30_15 >= RIGHT && LA30_15 <= SLESSEQUAL)||(LA30_15 >= SREM && LA30_15 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 15, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_HEX:
				{
				int LA30_16 = input.LA(2);
				if ( (LA30_16==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_16 >= AMPERSAND && LA30_16 <= ASTERISK)||(LA30_16 >= BOOL_AND && LA30_16 <= COMMA)||LA30_16==EQUAL||(LA30_16 >= FDIV && LA30_16 <= GREATEQUAL)||LA30_16==KEY_GOTO||(LA30_16 >= LBRACKET && LA30_16 <= LESSEQUAL)||(LA30_16 >= MINUS && LA30_16 <= NOTEQUAL)||(LA30_16 >= PERCENT && LA30_16 <= PLUS)||LA30_16==RBRACKET||(LA30_16 >= RIGHT && LA30_16 <= SLESSEQUAL)||(LA30_16 >= SREM && LA30_16 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 16, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_LITTLE:
				{
				int LA30_17 = input.LA(2);
				if ( (LA30_17==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_17 >= AMPERSAND && LA30_17 <= ASTERISK)||(LA30_17 >= BOOL_AND && LA30_17 <= COMMA)||LA30_17==EQUAL||(LA30_17 >= FDIV && LA30_17 <= GREATEQUAL)||LA30_17==KEY_GOTO||(LA30_17 >= LBRACKET && LA30_17 <= LESSEQUAL)||(LA30_17 >= MINUS && LA30_17 <= NOTEQUAL)||(LA30_17 >= PERCENT && LA30_17 <= PLUS)||LA30_17==RBRACKET||(LA30_17 >= RIGHT && LA30_17 <= SLESSEQUAL)||(LA30_17 >= SREM && LA30_17 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 17, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_LOCAL:
				{
				int LA30_18 = input.LA(2);
				if ( (LA30_18==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_18 >= AMPERSAND && LA30_18 <= ASTERISK)||(LA30_18 >= BOOL_AND && LA30_18 <= COMMA)||LA30_18==EQUAL||(LA30_18 >= FDIV && LA30_18 <= GREATEQUAL)||LA30_18==KEY_GOTO||(LA30_18 >= LBRACKET && LA30_18 <= LESSEQUAL)||(LA30_18 >= MINUS && LA30_18 <= NOTEQUAL)||(LA30_18 >= PERCENT && LA30_18 <= PLUS)||LA30_18==RBRACKET||(LA30_18 >= RIGHT && LA30_18 <= SLESSEQUAL)||(LA30_18 >= SREM && LA30_18 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 18, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_MACRO:
				{
				int LA30_19 = input.LA(2);
				if ( (LA30_19==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_19 >= AMPERSAND && LA30_19 <= ASTERISK)||(LA30_19 >= BOOL_AND && LA30_19 <= COMMA)||LA30_19==EQUAL||(LA30_19 >= FDIV && LA30_19 <= GREATEQUAL)||LA30_19==KEY_GOTO||(LA30_19 >= LBRACKET && LA30_19 <= LESSEQUAL)||(LA30_19 >= MINUS && LA30_19 <= NOTEQUAL)||(LA30_19 >= PERCENT && LA30_19 <= PLUS)||LA30_19==RBRACKET||(LA30_19 >= RIGHT && LA30_19 <= SLESSEQUAL)||(LA30_19 >= SREM && LA30_19 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 19, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_NAMES:
				{
				int LA30_20 = input.LA(2);
				if ( (LA30_20==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_20 >= AMPERSAND && LA30_20 <= ASTERISK)||(LA30_20 >= BOOL_AND && LA30_20 <= COMMA)||LA30_20==EQUAL||(LA30_20 >= FDIV && LA30_20 <= GREATEQUAL)||LA30_20==KEY_GOTO||(LA30_20 >= LBRACKET && LA30_20 <= LESSEQUAL)||(LA30_20 >= MINUS && LA30_20 <= NOTEQUAL)||(LA30_20 >= PERCENT && LA30_20 <= PLUS)||LA30_20==RBRACKET||(LA30_20 >= RIGHT && LA30_20 <= SLESSEQUAL)||(LA30_20 >= SREM && LA30_20 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 20, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_NOFLOW:
				{
				int LA30_21 = input.LA(2);
				if ( (LA30_21==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_21 >= AMPERSAND && LA30_21 <= ASTERISK)||(LA30_21 >= BOOL_AND && LA30_21 <= COMMA)||LA30_21==EQUAL||(LA30_21 >= FDIV && LA30_21 <= GREATEQUAL)||LA30_21==KEY_GOTO||(LA30_21 >= LBRACKET && LA30_21 <= LESSEQUAL)||(LA30_21 >= MINUS && LA30_21 <= NOTEQUAL)||(LA30_21 >= PERCENT && LA30_21 <= PLUS)||LA30_21==RBRACKET||(LA30_21 >= RIGHT && LA30_21 <= SLESSEQUAL)||(LA30_21 >= SREM && LA30_21 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 21, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_OFFSET:
				{
				int LA30_22 = input.LA(2);
				if ( (LA30_22==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_22 >= AMPERSAND && LA30_22 <= ASTERISK)||(LA30_22 >= BOOL_AND && LA30_22 <= COMMA)||LA30_22==EQUAL||(LA30_22 >= FDIV && LA30_22 <= GREATEQUAL)||LA30_22==KEY_GOTO||(LA30_22 >= LBRACKET && LA30_22 <= LESSEQUAL)||(LA30_22 >= MINUS && LA30_22 <= NOTEQUAL)||(LA30_22 >= PERCENT && LA30_22 <= PLUS)||LA30_22==RBRACKET||(LA30_22 >= RIGHT && LA30_22 <= SLESSEQUAL)||(LA30_22 >= SREM && LA30_22 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 22, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_PCODEOP:
				{
				int LA30_23 = input.LA(2);
				if ( (LA30_23==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_23 >= AMPERSAND && LA30_23 <= ASTERISK)||(LA30_23 >= BOOL_AND && LA30_23 <= COMMA)||LA30_23==EQUAL||(LA30_23 >= FDIV && LA30_23 <= GREATEQUAL)||LA30_23==KEY_GOTO||(LA30_23 >= LBRACKET && LA30_23 <= LESSEQUAL)||(LA30_23 >= MINUS && LA30_23 <= NOTEQUAL)||(LA30_23 >= PERCENT && LA30_23 <= PLUS)||LA30_23==RBRACKET||(LA30_23 >= RIGHT && LA30_23 <= SLESSEQUAL)||(LA30_23 >= SREM && LA30_23 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 23, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_RETURN:
				{
				int LA30_24 = input.LA(2);
				if ( (LA30_24==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_24 >= AMPERSAND && LA30_24 <= ASTERISK)||(LA30_24 >= BOOL_AND && LA30_24 <= COMMA)||LA30_24==EQUAL||(LA30_24 >= FDIV && LA30_24 <= GREATEQUAL)||LA30_24==KEY_GOTO||(LA30_24 >= LBRACKET && LA30_24 <= LESSEQUAL)||(LA30_24 >= MINUS && LA30_24 <= NOTEQUAL)||(LA30_24 >= PERCENT && LA30_24 <= PLUS)||LA30_24==RBRACKET||(LA30_24 >= RIGHT && LA30_24 <= SLESSEQUAL)||(LA30_24 >= SREM && LA30_24 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 24, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SIGNED:
				{
				int LA30_25 = input.LA(2);
				if ( (LA30_25==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_25 >= AMPERSAND && LA30_25 <= ASTERISK)||(LA30_25 >= BOOL_AND && LA30_25 <= COMMA)||LA30_25==EQUAL||(LA30_25 >= FDIV && LA30_25 <= GREATEQUAL)||LA30_25==KEY_GOTO||(LA30_25 >= LBRACKET && LA30_25 <= LESSEQUAL)||(LA30_25 >= MINUS && LA30_25 <= NOTEQUAL)||(LA30_25 >= PERCENT && LA30_25 <= PLUS)||LA30_25==RBRACKET||(LA30_25 >= RIGHT && LA30_25 <= SLESSEQUAL)||(LA30_25 >= SREM && LA30_25 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 25, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SIZE:
				{
				int LA30_26 = input.LA(2);
				if ( (LA30_26==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_26 >= AMPERSAND && LA30_26 <= ASTERISK)||(LA30_26 >= BOOL_AND && LA30_26 <= COMMA)||LA30_26==EQUAL||(LA30_26 >= FDIV && LA30_26 <= GREATEQUAL)||LA30_26==KEY_GOTO||(LA30_26 >= LBRACKET && LA30_26 <= LESSEQUAL)||(LA30_26 >= MINUS && LA30_26 <= NOTEQUAL)||(LA30_26 >= PERCENT && LA30_26 <= PLUS)||LA30_26==RBRACKET||(LA30_26 >= RIGHT && LA30_26 <= SLESSEQUAL)||(LA30_26 >= SREM && LA30_26 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 26, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SPACE:
				{
				int LA30_27 = input.LA(2);
				if ( (LA30_27==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_27 >= AMPERSAND && LA30_27 <= ASTERISK)||(LA30_27 >= BOOL_AND && LA30_27 <= COMMA)||LA30_27==EQUAL||(LA30_27 >= FDIV && LA30_27 <= GREATEQUAL)||LA30_27==KEY_GOTO||(LA30_27 >= LBRACKET && LA30_27 <= LESSEQUAL)||(LA30_27 >= MINUS && LA30_27 <= NOTEQUAL)||(LA30_27 >= PERCENT && LA30_27 <= PLUS)||LA30_27==RBRACKET||(LA30_27 >= RIGHT && LA30_27 <= SLESSEQUAL)||(LA30_27 >= SREM && LA30_27 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 27, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_TOKEN:
				{
				int LA30_28 = input.LA(2);
				if ( (LA30_28==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_28 >= AMPERSAND && LA30_28 <= ASTERISK)||(LA30_28 >= BOOL_AND && LA30_28 <= COMMA)||LA30_28==EQUAL||(LA30_28 >= FDIV && LA30_28 <= GREATEQUAL)||LA30_28==KEY_GOTO||(LA30_28 >= LBRACKET && LA30_28 <= LESSEQUAL)||(LA30_28 >= MINUS && LA30_28 <= NOTEQUAL)||(LA30_28 >= PERCENT && LA30_28 <= PLUS)||LA30_28==RBRACKET||(LA30_28 >= RIGHT && LA30_28 <= SLESSEQUAL)||(LA30_28 >= SREM && LA30_28 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 28, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_TYPE:
				{
				int LA30_29 = input.LA(2);
				if ( (LA30_29==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_29 >= AMPERSAND && LA30_29 <= ASTERISK)||(LA30_29 >= BOOL_AND && LA30_29 <= COMMA)||LA30_29==EQUAL||(LA30_29 >= FDIV && LA30_29 <= GREATEQUAL)||LA30_29==KEY_GOTO||(LA30_29 >= LBRACKET && LA30_29 <= LESSEQUAL)||(LA30_29 >= MINUS && LA30_29 <= NOTEQUAL)||(LA30_29 >= PERCENT && LA30_29 <= PLUS)||LA30_29==RBRACKET||(LA30_29 >= RIGHT && LA30_29 <= SLESSEQUAL)||(LA30_29 >= SREM && LA30_29 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 29, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_UNIMPL:
				{
				int LA30_30 = input.LA(2);
				if ( (LA30_30==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_30 >= AMPERSAND && LA30_30 <= ASTERISK)||(LA30_30 >= BOOL_AND && LA30_30 <= COMMA)||LA30_30==EQUAL||(LA30_30 >= FDIV && LA30_30 <= GREATEQUAL)||LA30_30==KEY_GOTO||(LA30_30 >= LBRACKET && LA30_30 <= LESSEQUAL)||(LA30_30 >= MINUS && LA30_30 <= NOTEQUAL)||(LA30_30 >= PERCENT && LA30_30 <= PLUS)||LA30_30==RBRACKET||(LA30_30 >= RIGHT && LA30_30 <= SLESSEQUAL)||(LA30_30 >= SREM && LA30_30 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 30, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_VALUES:
				{
				int LA30_31 = input.LA(2);
				if ( (LA30_31==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_31 >= AMPERSAND && LA30_31 <= ASTERISK)||(LA30_31 >= BOOL_AND && LA30_31 <= COMMA)||LA30_31==EQUAL||(LA30_31 >= FDIV && LA30_31 <= GREATEQUAL)||LA30_31==KEY_GOTO||(LA30_31 >= LBRACKET && LA30_31 <= LESSEQUAL)||(LA30_31 >= MINUS && LA30_31 <= NOTEQUAL)||(LA30_31 >= PERCENT && LA30_31 <= PLUS)||LA30_31==RBRACKET||(LA30_31 >= RIGHT && LA30_31 <= SLESSEQUAL)||(LA30_31 >= SREM && LA30_31 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 31, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_VARIABLES:
				{
				int LA30_32 = input.LA(2);
				if ( (LA30_32==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_32 >= AMPERSAND && LA30_32 <= ASTERISK)||(LA30_32 >= BOOL_AND && LA30_32 <= COMMA)||LA30_32==EQUAL||(LA30_32 >= FDIV && LA30_32 <= GREATEQUAL)||LA30_32==KEY_GOTO||(LA30_32 >= LBRACKET && LA30_32 <= LESSEQUAL)||(LA30_32 >= MINUS && LA30_32 <= NOTEQUAL)||(LA30_32 >= PERCENT && LA30_32 <= PLUS)||LA30_32==RBRACKET||(LA30_32 >= RIGHT && LA30_32 <= SLESSEQUAL)||(LA30_32 >= SREM && LA30_32 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 32, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_WORDSIZE:
				{
				int LA30_33 = input.LA(2);
				if ( (LA30_33==LPAREN) ) {
					alt30=1;
				}
				else if ( ((LA30_33 >= AMPERSAND && LA30_33 <= ASTERISK)||(LA30_33 >= BOOL_AND && LA30_33 <= COMMA)||LA30_33==EQUAL||(LA30_33 >= FDIV && LA30_33 <= GREATEQUAL)||LA30_33==KEY_GOTO||(LA30_33 >= LBRACKET && LA30_33 <= LESSEQUAL)||(LA30_33 >= MINUS && LA30_33 <= NOTEQUAL)||(LA30_33 >= PERCENT && LA30_33 <= PLUS)||LA30_33==RBRACKET||(LA30_33 >= RIGHT && LA30_33 <= SLESSEQUAL)||(LA30_33 >= SREM && LA30_33 <= SRIGHT)) ) {
					alt30=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 30, 33, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case AMPERSAND:
			case BIN_INT:
			case DEC_INT:
			case HEX_INT:
			case LPAREN:
				{
				alt30=2;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 30, 0, input);
				throw nvae;
			}
			switch (alt30) {
				case 1 :
					// SemanticParser.g:308:4: expr_apply
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_expr_apply_in_expr_func2088);
					expr_apply110=expr_apply();
					state._fsp--;

					adaptor.addChild(root_0, expr_apply110.getTree());

					}
					break;
				case 2 :
					// SemanticParser.g:309:4: expr_term
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_expr_term_in_expr_func2093);
					expr_term111=expr_term();
					state._fsp--;

					adaptor.addChild(root_0, expr_term111.getTree());

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
	// $ANTLR end "expr_func"


	public static class expr_apply_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "expr_apply"
	// SemanticParser.g:312:1: expr_apply : identifier expr_operands -> ^( OP_APPLY identifier ( expr_operands )? ) ;
	public final SleighParser_SemanticParser.expr_apply_return expr_apply() throws RecognitionException {
		SleighParser_SemanticParser.expr_apply_return retval = new SleighParser_SemanticParser.expr_apply_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope identifier112 =null;
		ParserRuleReturnScope expr_operands113 =null;

		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_expr_operands=new RewriteRuleSubtreeStream(adaptor,"rule expr_operands");

		try {
			// SemanticParser.g:313:2: ( identifier expr_operands -> ^( OP_APPLY identifier ( expr_operands )? ) )
			// SemanticParser.g:313:4: identifier expr_operands
			{
			pushFollow(FOLLOW_identifier_in_expr_apply2104);
			identifier112=gSleighParser.identifier();
			state._fsp--;

			stream_identifier.add(identifier112.getTree());
			pushFollow(FOLLOW_expr_operands_in_expr_apply2106);
			expr_operands113=expr_operands();
			state._fsp--;

			stream_expr_operands.add(expr_operands113.getTree());
			// AST REWRITE
			// elements: expr_operands, identifier
			// token labels: 
			// rule labels: retval
			// token list labels: 
			// rule list labels: 
			// wildcard labels: 
			retval.tree = root_0;
			RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

			root_0 = (CommonTree)adaptor.nil();
			// 313:29: -> ^( OP_APPLY identifier ( expr_operands )? )
			{
				// SemanticParser.g:313:32: ^( OP_APPLY identifier ( expr_operands )? )
				{
				CommonTree root_1 = (CommonTree)adaptor.nil();
				root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_APPLY, "OP_APPLY"), root_1);
				adaptor.addChild(root_1, stream_identifier.nextTree());
				// SemanticParser.g:313:54: ( expr_operands )?
				if ( stream_expr_operands.hasNext() ) {
					adaptor.addChild(root_1, stream_expr_operands.nextTree());
				}
				stream_expr_operands.reset();

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
	// $ANTLR end "expr_apply"


	public static class expr_operands_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "expr_operands"
	// SemanticParser.g:316:1: expr_operands : LPAREN ! ( expr ( COMMA ! expr )* )? RPAREN !;
	public final SleighParser_SemanticParser.expr_operands_return expr_operands() throws RecognitionException {
		SleighParser_SemanticParser.expr_operands_return retval = new SleighParser_SemanticParser.expr_operands_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token LPAREN114=null;
		Token COMMA116=null;
		Token RPAREN118=null;
		ParserRuleReturnScope expr115 =null;
		ParserRuleReturnScope expr117 =null;

		CommonTree LPAREN114_tree=null;
		CommonTree COMMA116_tree=null;
		CommonTree RPAREN118_tree=null;

		try {
			// SemanticParser.g:317:2: ( LPAREN ! ( expr ( COMMA ! expr )* )? RPAREN !)
			// SemanticParser.g:317:4: LPAREN ! ( expr ( COMMA ! expr )* )? RPAREN !
			{
			root_0 = (CommonTree)adaptor.nil();


			LPAREN114=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_expr_operands2128); 
			// SemanticParser.g:317:12: ( expr ( COMMA ! expr )* )?
			int alt32=2;
			int LA32_0 = input.LA(1);
			if ( (LA32_0==AMPERSAND||LA32_0==ASTERISK||LA32_0==BIN_INT||LA32_0==DEC_INT||LA32_0==EXCLAIM||LA32_0==FMINUS||(LA32_0 >= HEX_INT && LA32_0 <= KEY_WORDSIZE)||(LA32_0 >= LPAREN && LA32_0 <= MINUS)||LA32_0==TILDE) ) {
				alt32=1;
			}
			switch (alt32) {
				case 1 :
					// SemanticParser.g:317:13: expr ( COMMA ! expr )*
					{
					pushFollow(FOLLOW_expr_in_expr_operands2132);
					expr115=expr();
					state._fsp--;

					adaptor.addChild(root_0, expr115.getTree());

					// SemanticParser.g:317:18: ( COMMA ! expr )*
					loop31:
					while (true) {
						int alt31=2;
						int LA31_0 = input.LA(1);
						if ( (LA31_0==COMMA) ) {
							alt31=1;
						}

						switch (alt31) {
						case 1 :
							// SemanticParser.g:317:19: COMMA ! expr
							{
							COMMA116=(Token)match(input,COMMA,FOLLOW_COMMA_in_expr_operands2135); 
							pushFollow(FOLLOW_expr_in_expr_operands2138);
							expr117=expr();
							state._fsp--;

							adaptor.addChild(root_0, expr117.getTree());

							}
							break;

						default :
							break loop31;
						}
					}

					}
					break;

			}

			RPAREN118=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_expr_operands2145); 
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
	// $ANTLR end "expr_operands"


	public static class expr_term_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "expr_term"
	// SemanticParser.g:320:1: expr_term : ( varnode | sembitrange |lc= LPAREN expr RPAREN -> ^( OP_PARENTHESIZED[$lc, \"(...)\"] expr ) );
	public final SleighParser_SemanticParser.expr_term_return expr_term() throws RecognitionException {
		SleighParser_SemanticParser.expr_term_return retval = new SleighParser_SemanticParser.expr_term_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token RPAREN122=null;
		ParserRuleReturnScope varnode119 =null;
		ParserRuleReturnScope sembitrange120 =null;
		ParserRuleReturnScope expr121 =null;

		CommonTree lc_tree=null;
		CommonTree RPAREN122_tree=null;
		RewriteRuleTokenStream stream_LPAREN=new RewriteRuleTokenStream(adaptor,"token LPAREN");
		RewriteRuleTokenStream stream_RPAREN=new RewriteRuleTokenStream(adaptor,"token RPAREN");
		RewriteRuleSubtreeStream stream_expr=new RewriteRuleSubtreeStream(adaptor,"rule expr");

		try {
			// SemanticParser.g:321:2: ( varnode | sembitrange |lc= LPAREN expr RPAREN -> ^( OP_PARENTHESIZED[$lc, \"(...)\"] expr ) )
			int alt33=3;
			switch ( input.LA(1) ) {
			case AMPERSAND:
			case BIN_INT:
			case DEC_INT:
			case HEX_INT:
				{
				alt33=1;
				}
				break;
			case IDENTIFIER:
				{
				int LA33_2 = input.LA(2);
				if ( ((LA33_2 >= AMPERSAND && LA33_2 <= ASTERISK)||(LA33_2 >= BOOL_AND && LA33_2 <= COMMA)||LA33_2==EQUAL||(LA33_2 >= FDIV && LA33_2 <= GREATEQUAL)||LA33_2==KEY_GOTO||(LA33_2 >= LEFT && LA33_2 <= LESSEQUAL)||(LA33_2 >= MINUS && LA33_2 <= NOTEQUAL)||(LA33_2 >= PERCENT && LA33_2 <= PLUS)||LA33_2==RBRACKET||(LA33_2 >= RIGHT && LA33_2 <= SLESSEQUAL)||(LA33_2 >= SREM && LA33_2 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_2==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 2, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ALIGNMENT:
				{
				int LA33_3 = input.LA(2);
				if ( ((LA33_3 >= AMPERSAND && LA33_3 <= ASTERISK)||(LA33_3 >= BOOL_AND && LA33_3 <= COMMA)||LA33_3==EQUAL||(LA33_3 >= FDIV && LA33_3 <= GREATEQUAL)||LA33_3==KEY_GOTO||(LA33_3 >= LEFT && LA33_3 <= LESSEQUAL)||(LA33_3 >= MINUS && LA33_3 <= NOTEQUAL)||(LA33_3 >= PERCENT && LA33_3 <= PLUS)||LA33_3==RBRACKET||(LA33_3 >= RIGHT && LA33_3 <= SLESSEQUAL)||(LA33_3 >= SREM && LA33_3 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_3==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 3, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ATTACH:
				{
				int LA33_4 = input.LA(2);
				if ( ((LA33_4 >= AMPERSAND && LA33_4 <= ASTERISK)||(LA33_4 >= BOOL_AND && LA33_4 <= COMMA)||LA33_4==EQUAL||(LA33_4 >= FDIV && LA33_4 <= GREATEQUAL)||LA33_4==KEY_GOTO||(LA33_4 >= LEFT && LA33_4 <= LESSEQUAL)||(LA33_4 >= MINUS && LA33_4 <= NOTEQUAL)||(LA33_4 >= PERCENT && LA33_4 <= PLUS)||LA33_4==RBRACKET||(LA33_4 >= RIGHT && LA33_4 <= SLESSEQUAL)||(LA33_4 >= SREM && LA33_4 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_4==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 4, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BIG:
				{
				int LA33_5 = input.LA(2);
				if ( ((LA33_5 >= AMPERSAND && LA33_5 <= ASTERISK)||(LA33_5 >= BOOL_AND && LA33_5 <= COMMA)||LA33_5==EQUAL||(LA33_5 >= FDIV && LA33_5 <= GREATEQUAL)||LA33_5==KEY_GOTO||(LA33_5 >= LEFT && LA33_5 <= LESSEQUAL)||(LA33_5 >= MINUS && LA33_5 <= NOTEQUAL)||(LA33_5 >= PERCENT && LA33_5 <= PLUS)||LA33_5==RBRACKET||(LA33_5 >= RIGHT && LA33_5 <= SLESSEQUAL)||(LA33_5 >= SREM && LA33_5 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_5==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 5, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BITRANGE:
				{
				int LA33_6 = input.LA(2);
				if ( ((LA33_6 >= AMPERSAND && LA33_6 <= ASTERISK)||(LA33_6 >= BOOL_AND && LA33_6 <= COMMA)||LA33_6==EQUAL||(LA33_6 >= FDIV && LA33_6 <= GREATEQUAL)||LA33_6==KEY_GOTO||(LA33_6 >= LEFT && LA33_6 <= LESSEQUAL)||(LA33_6 >= MINUS && LA33_6 <= NOTEQUAL)||(LA33_6 >= PERCENT && LA33_6 <= PLUS)||LA33_6==RBRACKET||(LA33_6 >= RIGHT && LA33_6 <= SLESSEQUAL)||(LA33_6 >= SREM && LA33_6 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_6==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 6, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BUILD:
				{
				int LA33_7 = input.LA(2);
				if ( ((LA33_7 >= AMPERSAND && LA33_7 <= ASTERISK)||(LA33_7 >= BOOL_AND && LA33_7 <= COMMA)||LA33_7==EQUAL||(LA33_7 >= FDIV && LA33_7 <= GREATEQUAL)||LA33_7==KEY_GOTO||(LA33_7 >= LEFT && LA33_7 <= LESSEQUAL)||(LA33_7 >= MINUS && LA33_7 <= NOTEQUAL)||(LA33_7 >= PERCENT && LA33_7 <= PLUS)||LA33_7==RBRACKET||(LA33_7 >= RIGHT && LA33_7 <= SLESSEQUAL)||(LA33_7 >= SREM && LA33_7 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_7==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 7, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CALL:
				{
				int LA33_8 = input.LA(2);
				if ( ((LA33_8 >= AMPERSAND && LA33_8 <= ASTERISK)||(LA33_8 >= BOOL_AND && LA33_8 <= COMMA)||LA33_8==EQUAL||(LA33_8 >= FDIV && LA33_8 <= GREATEQUAL)||LA33_8==KEY_GOTO||(LA33_8 >= LEFT && LA33_8 <= LESSEQUAL)||(LA33_8 >= MINUS && LA33_8 <= NOTEQUAL)||(LA33_8 >= PERCENT && LA33_8 <= PLUS)||LA33_8==RBRACKET||(LA33_8 >= RIGHT && LA33_8 <= SLESSEQUAL)||(LA33_8 >= SREM && LA33_8 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_8==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 8, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CONTEXT:
				{
				int LA33_9 = input.LA(2);
				if ( ((LA33_9 >= AMPERSAND && LA33_9 <= ASTERISK)||(LA33_9 >= BOOL_AND && LA33_9 <= COMMA)||LA33_9==EQUAL||(LA33_9 >= FDIV && LA33_9 <= GREATEQUAL)||LA33_9==KEY_GOTO||(LA33_9 >= LEFT && LA33_9 <= LESSEQUAL)||(LA33_9 >= MINUS && LA33_9 <= NOTEQUAL)||(LA33_9 >= PERCENT && LA33_9 <= PLUS)||LA33_9==RBRACKET||(LA33_9 >= RIGHT && LA33_9 <= SLESSEQUAL)||(LA33_9 >= SREM && LA33_9 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_9==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 9, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CROSSBUILD:
				{
				int LA33_10 = input.LA(2);
				if ( ((LA33_10 >= AMPERSAND && LA33_10 <= ASTERISK)||(LA33_10 >= BOOL_AND && LA33_10 <= COMMA)||LA33_10==EQUAL||(LA33_10 >= FDIV && LA33_10 <= GREATEQUAL)||LA33_10==KEY_GOTO||(LA33_10 >= LEFT && LA33_10 <= LESSEQUAL)||(LA33_10 >= MINUS && LA33_10 <= NOTEQUAL)||(LA33_10 >= PERCENT && LA33_10 <= PLUS)||LA33_10==RBRACKET||(LA33_10 >= RIGHT && LA33_10 <= SLESSEQUAL)||(LA33_10 >= SREM && LA33_10 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_10==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 10, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEC:
				{
				int LA33_11 = input.LA(2);
				if ( ((LA33_11 >= AMPERSAND && LA33_11 <= ASTERISK)||(LA33_11 >= BOOL_AND && LA33_11 <= COMMA)||LA33_11==EQUAL||(LA33_11 >= FDIV && LA33_11 <= GREATEQUAL)||LA33_11==KEY_GOTO||(LA33_11 >= LEFT && LA33_11 <= LESSEQUAL)||(LA33_11 >= MINUS && LA33_11 <= NOTEQUAL)||(LA33_11 >= PERCENT && LA33_11 <= PLUS)||LA33_11==RBRACKET||(LA33_11 >= RIGHT && LA33_11 <= SLESSEQUAL)||(LA33_11 >= SREM && LA33_11 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_11==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 11, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEFAULT:
				{
				int LA33_12 = input.LA(2);
				if ( ((LA33_12 >= AMPERSAND && LA33_12 <= ASTERISK)||(LA33_12 >= BOOL_AND && LA33_12 <= COMMA)||LA33_12==EQUAL||(LA33_12 >= FDIV && LA33_12 <= GREATEQUAL)||LA33_12==KEY_GOTO||(LA33_12 >= LEFT && LA33_12 <= LESSEQUAL)||(LA33_12 >= MINUS && LA33_12 <= NOTEQUAL)||(LA33_12 >= PERCENT && LA33_12 <= PLUS)||LA33_12==RBRACKET||(LA33_12 >= RIGHT && LA33_12 <= SLESSEQUAL)||(LA33_12 >= SREM && LA33_12 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_12==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 12, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEFINE:
				{
				int LA33_13 = input.LA(2);
				if ( ((LA33_13 >= AMPERSAND && LA33_13 <= ASTERISK)||(LA33_13 >= BOOL_AND && LA33_13 <= COMMA)||LA33_13==EQUAL||(LA33_13 >= FDIV && LA33_13 <= GREATEQUAL)||LA33_13==KEY_GOTO||(LA33_13 >= LEFT && LA33_13 <= LESSEQUAL)||(LA33_13 >= MINUS && LA33_13 <= NOTEQUAL)||(LA33_13 >= PERCENT && LA33_13 <= PLUS)||LA33_13==RBRACKET||(LA33_13 >= RIGHT && LA33_13 <= SLESSEQUAL)||(LA33_13 >= SREM && LA33_13 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_13==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 13, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ENDIAN:
				{
				int LA33_14 = input.LA(2);
				if ( ((LA33_14 >= AMPERSAND && LA33_14 <= ASTERISK)||(LA33_14 >= BOOL_AND && LA33_14 <= COMMA)||LA33_14==EQUAL||(LA33_14 >= FDIV && LA33_14 <= GREATEQUAL)||LA33_14==KEY_GOTO||(LA33_14 >= LEFT && LA33_14 <= LESSEQUAL)||(LA33_14 >= MINUS && LA33_14 <= NOTEQUAL)||(LA33_14 >= PERCENT && LA33_14 <= PLUS)||LA33_14==RBRACKET||(LA33_14 >= RIGHT && LA33_14 <= SLESSEQUAL)||(LA33_14 >= SREM && LA33_14 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_14==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 14, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_EXPORT:
				{
				int LA33_15 = input.LA(2);
				if ( ((LA33_15 >= AMPERSAND && LA33_15 <= ASTERISK)||(LA33_15 >= BOOL_AND && LA33_15 <= COMMA)||LA33_15==EQUAL||(LA33_15 >= FDIV && LA33_15 <= GREATEQUAL)||LA33_15==KEY_GOTO||(LA33_15 >= LEFT && LA33_15 <= LESSEQUAL)||(LA33_15 >= MINUS && LA33_15 <= NOTEQUAL)||(LA33_15 >= PERCENT && LA33_15 <= PLUS)||LA33_15==RBRACKET||(LA33_15 >= RIGHT && LA33_15 <= SLESSEQUAL)||(LA33_15 >= SREM && LA33_15 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_15==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 15, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_GOTO:
				{
				int LA33_16 = input.LA(2);
				if ( ((LA33_16 >= AMPERSAND && LA33_16 <= ASTERISK)||(LA33_16 >= BOOL_AND && LA33_16 <= COMMA)||LA33_16==EQUAL||(LA33_16 >= FDIV && LA33_16 <= GREATEQUAL)||LA33_16==KEY_GOTO||(LA33_16 >= LEFT && LA33_16 <= LESSEQUAL)||(LA33_16 >= MINUS && LA33_16 <= NOTEQUAL)||(LA33_16 >= PERCENT && LA33_16 <= PLUS)||LA33_16==RBRACKET||(LA33_16 >= RIGHT && LA33_16 <= SLESSEQUAL)||(LA33_16 >= SREM && LA33_16 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_16==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 16, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_HEX:
				{
				int LA33_17 = input.LA(2);
				if ( ((LA33_17 >= AMPERSAND && LA33_17 <= ASTERISK)||(LA33_17 >= BOOL_AND && LA33_17 <= COMMA)||LA33_17==EQUAL||(LA33_17 >= FDIV && LA33_17 <= GREATEQUAL)||LA33_17==KEY_GOTO||(LA33_17 >= LEFT && LA33_17 <= LESSEQUAL)||(LA33_17 >= MINUS && LA33_17 <= NOTEQUAL)||(LA33_17 >= PERCENT && LA33_17 <= PLUS)||LA33_17==RBRACKET||(LA33_17 >= RIGHT && LA33_17 <= SLESSEQUAL)||(LA33_17 >= SREM && LA33_17 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_17==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 17, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_LITTLE:
				{
				int LA33_18 = input.LA(2);
				if ( ((LA33_18 >= AMPERSAND && LA33_18 <= ASTERISK)||(LA33_18 >= BOOL_AND && LA33_18 <= COMMA)||LA33_18==EQUAL||(LA33_18 >= FDIV && LA33_18 <= GREATEQUAL)||LA33_18==KEY_GOTO||(LA33_18 >= LEFT && LA33_18 <= LESSEQUAL)||(LA33_18 >= MINUS && LA33_18 <= NOTEQUAL)||(LA33_18 >= PERCENT && LA33_18 <= PLUS)||LA33_18==RBRACKET||(LA33_18 >= RIGHT && LA33_18 <= SLESSEQUAL)||(LA33_18 >= SREM && LA33_18 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_18==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 18, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_LOCAL:
				{
				int LA33_19 = input.LA(2);
				if ( ((LA33_19 >= AMPERSAND && LA33_19 <= ASTERISK)||(LA33_19 >= BOOL_AND && LA33_19 <= COMMA)||LA33_19==EQUAL||(LA33_19 >= FDIV && LA33_19 <= GREATEQUAL)||LA33_19==KEY_GOTO||(LA33_19 >= LEFT && LA33_19 <= LESSEQUAL)||(LA33_19 >= MINUS && LA33_19 <= NOTEQUAL)||(LA33_19 >= PERCENT && LA33_19 <= PLUS)||LA33_19==RBRACKET||(LA33_19 >= RIGHT && LA33_19 <= SLESSEQUAL)||(LA33_19 >= SREM && LA33_19 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_19==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 19, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_MACRO:
				{
				int LA33_20 = input.LA(2);
				if ( ((LA33_20 >= AMPERSAND && LA33_20 <= ASTERISK)||(LA33_20 >= BOOL_AND && LA33_20 <= COMMA)||LA33_20==EQUAL||(LA33_20 >= FDIV && LA33_20 <= GREATEQUAL)||LA33_20==KEY_GOTO||(LA33_20 >= LEFT && LA33_20 <= LESSEQUAL)||(LA33_20 >= MINUS && LA33_20 <= NOTEQUAL)||(LA33_20 >= PERCENT && LA33_20 <= PLUS)||LA33_20==RBRACKET||(LA33_20 >= RIGHT && LA33_20 <= SLESSEQUAL)||(LA33_20 >= SREM && LA33_20 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_20==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 20, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_NAMES:
				{
				int LA33_21 = input.LA(2);
				if ( ((LA33_21 >= AMPERSAND && LA33_21 <= ASTERISK)||(LA33_21 >= BOOL_AND && LA33_21 <= COMMA)||LA33_21==EQUAL||(LA33_21 >= FDIV && LA33_21 <= GREATEQUAL)||LA33_21==KEY_GOTO||(LA33_21 >= LEFT && LA33_21 <= LESSEQUAL)||(LA33_21 >= MINUS && LA33_21 <= NOTEQUAL)||(LA33_21 >= PERCENT && LA33_21 <= PLUS)||LA33_21==RBRACKET||(LA33_21 >= RIGHT && LA33_21 <= SLESSEQUAL)||(LA33_21 >= SREM && LA33_21 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_21==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 21, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_NOFLOW:
				{
				int LA33_22 = input.LA(2);
				if ( ((LA33_22 >= AMPERSAND && LA33_22 <= ASTERISK)||(LA33_22 >= BOOL_AND && LA33_22 <= COMMA)||LA33_22==EQUAL||(LA33_22 >= FDIV && LA33_22 <= GREATEQUAL)||LA33_22==KEY_GOTO||(LA33_22 >= LEFT && LA33_22 <= LESSEQUAL)||(LA33_22 >= MINUS && LA33_22 <= NOTEQUAL)||(LA33_22 >= PERCENT && LA33_22 <= PLUS)||LA33_22==RBRACKET||(LA33_22 >= RIGHT && LA33_22 <= SLESSEQUAL)||(LA33_22 >= SREM && LA33_22 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_22==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 22, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_OFFSET:
				{
				int LA33_23 = input.LA(2);
				if ( ((LA33_23 >= AMPERSAND && LA33_23 <= ASTERISK)||(LA33_23 >= BOOL_AND && LA33_23 <= COMMA)||LA33_23==EQUAL||(LA33_23 >= FDIV && LA33_23 <= GREATEQUAL)||LA33_23==KEY_GOTO||(LA33_23 >= LEFT && LA33_23 <= LESSEQUAL)||(LA33_23 >= MINUS && LA33_23 <= NOTEQUAL)||(LA33_23 >= PERCENT && LA33_23 <= PLUS)||LA33_23==RBRACKET||(LA33_23 >= RIGHT && LA33_23 <= SLESSEQUAL)||(LA33_23 >= SREM && LA33_23 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_23==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 23, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_PCODEOP:
				{
				int LA33_24 = input.LA(2);
				if ( ((LA33_24 >= AMPERSAND && LA33_24 <= ASTERISK)||(LA33_24 >= BOOL_AND && LA33_24 <= COMMA)||LA33_24==EQUAL||(LA33_24 >= FDIV && LA33_24 <= GREATEQUAL)||LA33_24==KEY_GOTO||(LA33_24 >= LEFT && LA33_24 <= LESSEQUAL)||(LA33_24 >= MINUS && LA33_24 <= NOTEQUAL)||(LA33_24 >= PERCENT && LA33_24 <= PLUS)||LA33_24==RBRACKET||(LA33_24 >= RIGHT && LA33_24 <= SLESSEQUAL)||(LA33_24 >= SREM && LA33_24 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_24==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 24, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_RETURN:
				{
				int LA33_25 = input.LA(2);
				if ( ((LA33_25 >= AMPERSAND && LA33_25 <= ASTERISK)||(LA33_25 >= BOOL_AND && LA33_25 <= COMMA)||LA33_25==EQUAL||(LA33_25 >= FDIV && LA33_25 <= GREATEQUAL)||LA33_25==KEY_GOTO||(LA33_25 >= LEFT && LA33_25 <= LESSEQUAL)||(LA33_25 >= MINUS && LA33_25 <= NOTEQUAL)||(LA33_25 >= PERCENT && LA33_25 <= PLUS)||LA33_25==RBRACKET||(LA33_25 >= RIGHT && LA33_25 <= SLESSEQUAL)||(LA33_25 >= SREM && LA33_25 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_25==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 25, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SIGNED:
				{
				int LA33_26 = input.LA(2);
				if ( ((LA33_26 >= AMPERSAND && LA33_26 <= ASTERISK)||(LA33_26 >= BOOL_AND && LA33_26 <= COMMA)||LA33_26==EQUAL||(LA33_26 >= FDIV && LA33_26 <= GREATEQUAL)||LA33_26==KEY_GOTO||(LA33_26 >= LEFT && LA33_26 <= LESSEQUAL)||(LA33_26 >= MINUS && LA33_26 <= NOTEQUAL)||(LA33_26 >= PERCENT && LA33_26 <= PLUS)||LA33_26==RBRACKET||(LA33_26 >= RIGHT && LA33_26 <= SLESSEQUAL)||(LA33_26 >= SREM && LA33_26 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_26==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 26, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SIZE:
				{
				int LA33_27 = input.LA(2);
				if ( ((LA33_27 >= AMPERSAND && LA33_27 <= ASTERISK)||(LA33_27 >= BOOL_AND && LA33_27 <= COMMA)||LA33_27==EQUAL||(LA33_27 >= FDIV && LA33_27 <= GREATEQUAL)||LA33_27==KEY_GOTO||(LA33_27 >= LEFT && LA33_27 <= LESSEQUAL)||(LA33_27 >= MINUS && LA33_27 <= NOTEQUAL)||(LA33_27 >= PERCENT && LA33_27 <= PLUS)||LA33_27==RBRACKET||(LA33_27 >= RIGHT && LA33_27 <= SLESSEQUAL)||(LA33_27 >= SREM && LA33_27 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_27==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 27, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SPACE:
				{
				int LA33_28 = input.LA(2);
				if ( ((LA33_28 >= AMPERSAND && LA33_28 <= ASTERISK)||(LA33_28 >= BOOL_AND && LA33_28 <= COMMA)||LA33_28==EQUAL||(LA33_28 >= FDIV && LA33_28 <= GREATEQUAL)||LA33_28==KEY_GOTO||(LA33_28 >= LEFT && LA33_28 <= LESSEQUAL)||(LA33_28 >= MINUS && LA33_28 <= NOTEQUAL)||(LA33_28 >= PERCENT && LA33_28 <= PLUS)||LA33_28==RBRACKET||(LA33_28 >= RIGHT && LA33_28 <= SLESSEQUAL)||(LA33_28 >= SREM && LA33_28 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_28==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 28, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_TOKEN:
				{
				int LA33_29 = input.LA(2);
				if ( ((LA33_29 >= AMPERSAND && LA33_29 <= ASTERISK)||(LA33_29 >= BOOL_AND && LA33_29 <= COMMA)||LA33_29==EQUAL||(LA33_29 >= FDIV && LA33_29 <= GREATEQUAL)||LA33_29==KEY_GOTO||(LA33_29 >= LEFT && LA33_29 <= LESSEQUAL)||(LA33_29 >= MINUS && LA33_29 <= NOTEQUAL)||(LA33_29 >= PERCENT && LA33_29 <= PLUS)||LA33_29==RBRACKET||(LA33_29 >= RIGHT && LA33_29 <= SLESSEQUAL)||(LA33_29 >= SREM && LA33_29 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_29==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 29, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_TYPE:
				{
				int LA33_30 = input.LA(2);
				if ( ((LA33_30 >= AMPERSAND && LA33_30 <= ASTERISK)||(LA33_30 >= BOOL_AND && LA33_30 <= COMMA)||LA33_30==EQUAL||(LA33_30 >= FDIV && LA33_30 <= GREATEQUAL)||LA33_30==KEY_GOTO||(LA33_30 >= LEFT && LA33_30 <= LESSEQUAL)||(LA33_30 >= MINUS && LA33_30 <= NOTEQUAL)||(LA33_30 >= PERCENT && LA33_30 <= PLUS)||LA33_30==RBRACKET||(LA33_30 >= RIGHT && LA33_30 <= SLESSEQUAL)||(LA33_30 >= SREM && LA33_30 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_30==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 30, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_UNIMPL:
				{
				int LA33_31 = input.LA(2);
				if ( ((LA33_31 >= AMPERSAND && LA33_31 <= ASTERISK)||(LA33_31 >= BOOL_AND && LA33_31 <= COMMA)||LA33_31==EQUAL||(LA33_31 >= FDIV && LA33_31 <= GREATEQUAL)||LA33_31==KEY_GOTO||(LA33_31 >= LEFT && LA33_31 <= LESSEQUAL)||(LA33_31 >= MINUS && LA33_31 <= NOTEQUAL)||(LA33_31 >= PERCENT && LA33_31 <= PLUS)||LA33_31==RBRACKET||(LA33_31 >= RIGHT && LA33_31 <= SLESSEQUAL)||(LA33_31 >= SREM && LA33_31 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_31==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 31, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_VALUES:
				{
				int LA33_32 = input.LA(2);
				if ( ((LA33_32 >= AMPERSAND && LA33_32 <= ASTERISK)||(LA33_32 >= BOOL_AND && LA33_32 <= COMMA)||LA33_32==EQUAL||(LA33_32 >= FDIV && LA33_32 <= GREATEQUAL)||LA33_32==KEY_GOTO||(LA33_32 >= LEFT && LA33_32 <= LESSEQUAL)||(LA33_32 >= MINUS && LA33_32 <= NOTEQUAL)||(LA33_32 >= PERCENT && LA33_32 <= PLUS)||LA33_32==RBRACKET||(LA33_32 >= RIGHT && LA33_32 <= SLESSEQUAL)||(LA33_32 >= SREM && LA33_32 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_32==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 32, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_VARIABLES:
				{
				int LA33_33 = input.LA(2);
				if ( ((LA33_33 >= AMPERSAND && LA33_33 <= ASTERISK)||(LA33_33 >= BOOL_AND && LA33_33 <= COMMA)||LA33_33==EQUAL||(LA33_33 >= FDIV && LA33_33 <= GREATEQUAL)||LA33_33==KEY_GOTO||(LA33_33 >= LEFT && LA33_33 <= LESSEQUAL)||(LA33_33 >= MINUS && LA33_33 <= NOTEQUAL)||(LA33_33 >= PERCENT && LA33_33 <= PLUS)||LA33_33==RBRACKET||(LA33_33 >= RIGHT && LA33_33 <= SLESSEQUAL)||(LA33_33 >= SREM && LA33_33 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_33==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 33, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_WORDSIZE:
				{
				int LA33_34 = input.LA(2);
				if ( ((LA33_34 >= AMPERSAND && LA33_34 <= ASTERISK)||(LA33_34 >= BOOL_AND && LA33_34 <= COMMA)||LA33_34==EQUAL||(LA33_34 >= FDIV && LA33_34 <= GREATEQUAL)||LA33_34==KEY_GOTO||(LA33_34 >= LEFT && LA33_34 <= LESSEQUAL)||(LA33_34 >= MINUS && LA33_34 <= NOTEQUAL)||(LA33_34 >= PERCENT && LA33_34 <= PLUS)||LA33_34==RBRACKET||(LA33_34 >= RIGHT && LA33_34 <= SLESSEQUAL)||(LA33_34 >= SREM && LA33_34 <= SRIGHT)) ) {
					alt33=1;
				}
				else if ( (LA33_34==LBRACKET) ) {
					alt33=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 33, 34, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case LPAREN:
				{
				alt33=3;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 33, 0, input);
				throw nvae;
			}
			switch (alt33) {
				case 1 :
					// SemanticParser.g:321:4: varnode
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_varnode_in_expr_term2157);
					varnode119=varnode();
					state._fsp--;

					adaptor.addChild(root_0, varnode119.getTree());

					}
					break;
				case 2 :
					// SemanticParser.g:322:4: sembitrange
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_sembitrange_in_expr_term2162);
					sembitrange120=sembitrange();
					state._fsp--;

					adaptor.addChild(root_0, sembitrange120.getTree());

					}
					break;
				case 3 :
					// SemanticParser.g:323:4: lc= LPAREN expr RPAREN
					{
					lc=(Token)match(input,LPAREN,FOLLOW_LPAREN_in_expr_term2169);  
					stream_LPAREN.add(lc);

					pushFollow(FOLLOW_expr_in_expr_term2171);
					expr121=expr();
					state._fsp--;

					stream_expr.add(expr121.getTree());
					RPAREN122=(Token)match(input,RPAREN,FOLLOW_RPAREN_in_expr_term2173);  
					stream_RPAREN.add(RPAREN122);

					// AST REWRITE
					// elements: expr
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 323:26: -> ^( OP_PARENTHESIZED[$lc, \"(...)\"] expr )
					{
						// SemanticParser.g:323:29: ^( OP_PARENTHESIZED[$lc, \"(...)\"] expr )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_PARENTHESIZED, lc, "(...)"), root_1);
						adaptor.addChild(root_1, stream_expr.nextTree());
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
	// $ANTLR end "expr_term"


	public static class varnode_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "varnode"
	// SemanticParser.g:326:1: varnode : ( integer | identifier | integer lc= COLON constant -> ^( OP_TRUNCATION_SIZE[$lc] integer constant ) | identifier lc= COLON constant -> ^( OP_BITRANGE2[$lc] identifier constant ) |lc= AMPERSAND fp= COLON constant varnode -> ^( OP_ADDRESS_OF[$lc] ^( OP_SIZING_SIZE[$fp] constant ) varnode ) |lc= AMPERSAND varnode -> ^( OP_ADDRESS_OF[$lc] varnode ) );
	public final SleighParser_SemanticParser.varnode_return varnode() throws RecognitionException {
		SleighParser_SemanticParser.varnode_return retval = new SleighParser_SemanticParser.varnode_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		Token lc=null;
		Token fp=null;
		ParserRuleReturnScope integer123 =null;
		ParserRuleReturnScope identifier124 =null;
		ParserRuleReturnScope integer125 =null;
		ParserRuleReturnScope constant126 =null;
		ParserRuleReturnScope identifier127 =null;
		ParserRuleReturnScope constant128 =null;
		ParserRuleReturnScope constant129 =null;
		ParserRuleReturnScope varnode130 =null;
		ParserRuleReturnScope varnode131 =null;

		CommonTree lc_tree=null;
		CommonTree fp_tree=null;
		RewriteRuleTokenStream stream_AMPERSAND=new RewriteRuleTokenStream(adaptor,"token AMPERSAND");
		RewriteRuleTokenStream stream_COLON=new RewriteRuleTokenStream(adaptor,"token COLON");
		RewriteRuleSubtreeStream stream_identifier=new RewriteRuleSubtreeStream(adaptor,"rule identifier");
		RewriteRuleSubtreeStream stream_constant=new RewriteRuleSubtreeStream(adaptor,"rule constant");
		RewriteRuleSubtreeStream stream_varnode=new RewriteRuleSubtreeStream(adaptor,"rule varnode");
		RewriteRuleSubtreeStream stream_integer=new RewriteRuleSubtreeStream(adaptor,"rule integer");

		try {
			// SemanticParser.g:327:2: ( integer | identifier | integer lc= COLON constant -> ^( OP_TRUNCATION_SIZE[$lc] integer constant ) | identifier lc= COLON constant -> ^( OP_BITRANGE2[$lc] identifier constant ) |lc= AMPERSAND fp= COLON constant varnode -> ^( OP_ADDRESS_OF[$lc] ^( OP_SIZING_SIZE[$fp] constant ) varnode ) |lc= AMPERSAND varnode -> ^( OP_ADDRESS_OF[$lc] varnode ) )
			int alt34=6;
			switch ( input.LA(1) ) {
			case HEX_INT:
				{
				int LA34_1 = input.LA(2);
				if ( ((LA34_1 >= AMPERSAND && LA34_1 <= ASTERISK)||(LA34_1 >= BOOL_AND && LA34_1 <= CARET)||LA34_1==COMMA||LA34_1==EQUAL||(LA34_1 >= FDIV && LA34_1 <= GREATEQUAL)||LA34_1==KEY_GOTO||(LA34_1 >= LEFT && LA34_1 <= LESSEQUAL)||(LA34_1 >= MINUS && LA34_1 <= NOTEQUAL)||(LA34_1 >= PERCENT && LA34_1 <= PLUS)||LA34_1==RBRACKET||(LA34_1 >= RIGHT && LA34_1 <= SLESSEQUAL)||(LA34_1 >= SREM && LA34_1 <= SRIGHT)) ) {
					alt34=1;
				}
				else if ( (LA34_1==COLON) ) {
					alt34=3;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case DEC_INT:
				{
				int LA34_2 = input.LA(2);
				if ( ((LA34_2 >= AMPERSAND && LA34_2 <= ASTERISK)||(LA34_2 >= BOOL_AND && LA34_2 <= CARET)||LA34_2==COMMA||LA34_2==EQUAL||(LA34_2 >= FDIV && LA34_2 <= GREATEQUAL)||LA34_2==KEY_GOTO||(LA34_2 >= LEFT && LA34_2 <= LESSEQUAL)||(LA34_2 >= MINUS && LA34_2 <= NOTEQUAL)||(LA34_2 >= PERCENT && LA34_2 <= PLUS)||LA34_2==RBRACKET||(LA34_2 >= RIGHT && LA34_2 <= SLESSEQUAL)||(LA34_2 >= SREM && LA34_2 <= SRIGHT)) ) {
					alt34=1;
				}
				else if ( (LA34_2==COLON) ) {
					alt34=3;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 2, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case BIN_INT:
				{
				int LA34_3 = input.LA(2);
				if ( ((LA34_3 >= AMPERSAND && LA34_3 <= ASTERISK)||(LA34_3 >= BOOL_AND && LA34_3 <= CARET)||LA34_3==COMMA||LA34_3==EQUAL||(LA34_3 >= FDIV && LA34_3 <= GREATEQUAL)||LA34_3==KEY_GOTO||(LA34_3 >= LEFT && LA34_3 <= LESSEQUAL)||(LA34_3 >= MINUS && LA34_3 <= NOTEQUAL)||(LA34_3 >= PERCENT && LA34_3 <= PLUS)||LA34_3==RBRACKET||(LA34_3 >= RIGHT && LA34_3 <= SLESSEQUAL)||(LA34_3 >= SREM && LA34_3 <= SRIGHT)) ) {
					alt34=1;
				}
				else if ( (LA34_3==COLON) ) {
					alt34=3;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 3, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case IDENTIFIER:
				{
				int LA34_4 = input.LA(2);
				if ( ((LA34_4 >= AMPERSAND && LA34_4 <= ASTERISK)||(LA34_4 >= BOOL_AND && LA34_4 <= CARET)||LA34_4==COMMA||LA34_4==EQUAL||(LA34_4 >= FDIV && LA34_4 <= GREATEQUAL)||LA34_4==KEY_GOTO||(LA34_4 >= LEFT && LA34_4 <= LESSEQUAL)||(LA34_4 >= MINUS && LA34_4 <= NOTEQUAL)||(LA34_4 >= PERCENT && LA34_4 <= PLUS)||LA34_4==RBRACKET||(LA34_4 >= RIGHT && LA34_4 <= SLESSEQUAL)||(LA34_4 >= SREM && LA34_4 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_4==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 4, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ALIGNMENT:
				{
				int LA34_5 = input.LA(2);
				if ( ((LA34_5 >= AMPERSAND && LA34_5 <= ASTERISK)||(LA34_5 >= BOOL_AND && LA34_5 <= CARET)||LA34_5==COMMA||LA34_5==EQUAL||(LA34_5 >= FDIV && LA34_5 <= GREATEQUAL)||LA34_5==KEY_GOTO||(LA34_5 >= LEFT && LA34_5 <= LESSEQUAL)||(LA34_5 >= MINUS && LA34_5 <= NOTEQUAL)||(LA34_5 >= PERCENT && LA34_5 <= PLUS)||LA34_5==RBRACKET||(LA34_5 >= RIGHT && LA34_5 <= SLESSEQUAL)||(LA34_5 >= SREM && LA34_5 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_5==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 5, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ATTACH:
				{
				int LA34_6 = input.LA(2);
				if ( ((LA34_6 >= AMPERSAND && LA34_6 <= ASTERISK)||(LA34_6 >= BOOL_AND && LA34_6 <= CARET)||LA34_6==COMMA||LA34_6==EQUAL||(LA34_6 >= FDIV && LA34_6 <= GREATEQUAL)||LA34_6==KEY_GOTO||(LA34_6 >= LEFT && LA34_6 <= LESSEQUAL)||(LA34_6 >= MINUS && LA34_6 <= NOTEQUAL)||(LA34_6 >= PERCENT && LA34_6 <= PLUS)||LA34_6==RBRACKET||(LA34_6 >= RIGHT && LA34_6 <= SLESSEQUAL)||(LA34_6 >= SREM && LA34_6 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_6==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 6, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BIG:
				{
				int LA34_7 = input.LA(2);
				if ( ((LA34_7 >= AMPERSAND && LA34_7 <= ASTERISK)||(LA34_7 >= BOOL_AND && LA34_7 <= CARET)||LA34_7==COMMA||LA34_7==EQUAL||(LA34_7 >= FDIV && LA34_7 <= GREATEQUAL)||LA34_7==KEY_GOTO||(LA34_7 >= LEFT && LA34_7 <= LESSEQUAL)||(LA34_7 >= MINUS && LA34_7 <= NOTEQUAL)||(LA34_7 >= PERCENT && LA34_7 <= PLUS)||LA34_7==RBRACKET||(LA34_7 >= RIGHT && LA34_7 <= SLESSEQUAL)||(LA34_7 >= SREM && LA34_7 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_7==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 7, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BITRANGE:
				{
				int LA34_8 = input.LA(2);
				if ( ((LA34_8 >= AMPERSAND && LA34_8 <= ASTERISK)||(LA34_8 >= BOOL_AND && LA34_8 <= CARET)||LA34_8==COMMA||LA34_8==EQUAL||(LA34_8 >= FDIV && LA34_8 <= GREATEQUAL)||LA34_8==KEY_GOTO||(LA34_8 >= LEFT && LA34_8 <= LESSEQUAL)||(LA34_8 >= MINUS && LA34_8 <= NOTEQUAL)||(LA34_8 >= PERCENT && LA34_8 <= PLUS)||LA34_8==RBRACKET||(LA34_8 >= RIGHT && LA34_8 <= SLESSEQUAL)||(LA34_8 >= SREM && LA34_8 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_8==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 8, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_BUILD:
				{
				int LA34_9 = input.LA(2);
				if ( ((LA34_9 >= AMPERSAND && LA34_9 <= ASTERISK)||(LA34_9 >= BOOL_AND && LA34_9 <= CARET)||LA34_9==COMMA||LA34_9==EQUAL||(LA34_9 >= FDIV && LA34_9 <= GREATEQUAL)||LA34_9==KEY_GOTO||(LA34_9 >= LEFT && LA34_9 <= LESSEQUAL)||(LA34_9 >= MINUS && LA34_9 <= NOTEQUAL)||(LA34_9 >= PERCENT && LA34_9 <= PLUS)||LA34_9==RBRACKET||(LA34_9 >= RIGHT && LA34_9 <= SLESSEQUAL)||(LA34_9 >= SREM && LA34_9 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_9==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 9, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CALL:
				{
				int LA34_10 = input.LA(2);
				if ( ((LA34_10 >= AMPERSAND && LA34_10 <= ASTERISK)||(LA34_10 >= BOOL_AND && LA34_10 <= CARET)||LA34_10==COMMA||LA34_10==EQUAL||(LA34_10 >= FDIV && LA34_10 <= GREATEQUAL)||LA34_10==KEY_GOTO||(LA34_10 >= LEFT && LA34_10 <= LESSEQUAL)||(LA34_10 >= MINUS && LA34_10 <= NOTEQUAL)||(LA34_10 >= PERCENT && LA34_10 <= PLUS)||LA34_10==RBRACKET||(LA34_10 >= RIGHT && LA34_10 <= SLESSEQUAL)||(LA34_10 >= SREM && LA34_10 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_10==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 10, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CONTEXT:
				{
				int LA34_11 = input.LA(2);
				if ( ((LA34_11 >= AMPERSAND && LA34_11 <= ASTERISK)||(LA34_11 >= BOOL_AND && LA34_11 <= CARET)||LA34_11==COMMA||LA34_11==EQUAL||(LA34_11 >= FDIV && LA34_11 <= GREATEQUAL)||LA34_11==KEY_GOTO||(LA34_11 >= LEFT && LA34_11 <= LESSEQUAL)||(LA34_11 >= MINUS && LA34_11 <= NOTEQUAL)||(LA34_11 >= PERCENT && LA34_11 <= PLUS)||LA34_11==RBRACKET||(LA34_11 >= RIGHT && LA34_11 <= SLESSEQUAL)||(LA34_11 >= SREM && LA34_11 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_11==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 11, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_CROSSBUILD:
				{
				int LA34_12 = input.LA(2);
				if ( ((LA34_12 >= AMPERSAND && LA34_12 <= ASTERISK)||(LA34_12 >= BOOL_AND && LA34_12 <= CARET)||LA34_12==COMMA||LA34_12==EQUAL||(LA34_12 >= FDIV && LA34_12 <= GREATEQUAL)||LA34_12==KEY_GOTO||(LA34_12 >= LEFT && LA34_12 <= LESSEQUAL)||(LA34_12 >= MINUS && LA34_12 <= NOTEQUAL)||(LA34_12 >= PERCENT && LA34_12 <= PLUS)||LA34_12==RBRACKET||(LA34_12 >= RIGHT && LA34_12 <= SLESSEQUAL)||(LA34_12 >= SREM && LA34_12 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_12==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 12, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEC:
				{
				int LA34_13 = input.LA(2);
				if ( ((LA34_13 >= AMPERSAND && LA34_13 <= ASTERISK)||(LA34_13 >= BOOL_AND && LA34_13 <= CARET)||LA34_13==COMMA||LA34_13==EQUAL||(LA34_13 >= FDIV && LA34_13 <= GREATEQUAL)||LA34_13==KEY_GOTO||(LA34_13 >= LEFT && LA34_13 <= LESSEQUAL)||(LA34_13 >= MINUS && LA34_13 <= NOTEQUAL)||(LA34_13 >= PERCENT && LA34_13 <= PLUS)||LA34_13==RBRACKET||(LA34_13 >= RIGHT && LA34_13 <= SLESSEQUAL)||(LA34_13 >= SREM && LA34_13 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_13==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 13, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEFAULT:
				{
				int LA34_14 = input.LA(2);
				if ( ((LA34_14 >= AMPERSAND && LA34_14 <= ASTERISK)||(LA34_14 >= BOOL_AND && LA34_14 <= CARET)||LA34_14==COMMA||LA34_14==EQUAL||(LA34_14 >= FDIV && LA34_14 <= GREATEQUAL)||LA34_14==KEY_GOTO||(LA34_14 >= LEFT && LA34_14 <= LESSEQUAL)||(LA34_14 >= MINUS && LA34_14 <= NOTEQUAL)||(LA34_14 >= PERCENT && LA34_14 <= PLUS)||LA34_14==RBRACKET||(LA34_14 >= RIGHT && LA34_14 <= SLESSEQUAL)||(LA34_14 >= SREM && LA34_14 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_14==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 14, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_DEFINE:
				{
				int LA34_15 = input.LA(2);
				if ( ((LA34_15 >= AMPERSAND && LA34_15 <= ASTERISK)||(LA34_15 >= BOOL_AND && LA34_15 <= CARET)||LA34_15==COMMA||LA34_15==EQUAL||(LA34_15 >= FDIV && LA34_15 <= GREATEQUAL)||LA34_15==KEY_GOTO||(LA34_15 >= LEFT && LA34_15 <= LESSEQUAL)||(LA34_15 >= MINUS && LA34_15 <= NOTEQUAL)||(LA34_15 >= PERCENT && LA34_15 <= PLUS)||LA34_15==RBRACKET||(LA34_15 >= RIGHT && LA34_15 <= SLESSEQUAL)||(LA34_15 >= SREM && LA34_15 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_15==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 15, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_ENDIAN:
				{
				int LA34_16 = input.LA(2);
				if ( ((LA34_16 >= AMPERSAND && LA34_16 <= ASTERISK)||(LA34_16 >= BOOL_AND && LA34_16 <= CARET)||LA34_16==COMMA||LA34_16==EQUAL||(LA34_16 >= FDIV && LA34_16 <= GREATEQUAL)||LA34_16==KEY_GOTO||(LA34_16 >= LEFT && LA34_16 <= LESSEQUAL)||(LA34_16 >= MINUS && LA34_16 <= NOTEQUAL)||(LA34_16 >= PERCENT && LA34_16 <= PLUS)||LA34_16==RBRACKET||(LA34_16 >= RIGHT && LA34_16 <= SLESSEQUAL)||(LA34_16 >= SREM && LA34_16 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_16==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 16, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_EXPORT:
				{
				int LA34_17 = input.LA(2);
				if ( ((LA34_17 >= AMPERSAND && LA34_17 <= ASTERISK)||(LA34_17 >= BOOL_AND && LA34_17 <= CARET)||LA34_17==COMMA||LA34_17==EQUAL||(LA34_17 >= FDIV && LA34_17 <= GREATEQUAL)||LA34_17==KEY_GOTO||(LA34_17 >= LEFT && LA34_17 <= LESSEQUAL)||(LA34_17 >= MINUS && LA34_17 <= NOTEQUAL)||(LA34_17 >= PERCENT && LA34_17 <= PLUS)||LA34_17==RBRACKET||(LA34_17 >= RIGHT && LA34_17 <= SLESSEQUAL)||(LA34_17 >= SREM && LA34_17 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_17==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 17, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_GOTO:
				{
				int LA34_18 = input.LA(2);
				if ( ((LA34_18 >= AMPERSAND && LA34_18 <= ASTERISK)||(LA34_18 >= BOOL_AND && LA34_18 <= CARET)||LA34_18==COMMA||LA34_18==EQUAL||(LA34_18 >= FDIV && LA34_18 <= GREATEQUAL)||LA34_18==KEY_GOTO||(LA34_18 >= LEFT && LA34_18 <= LESSEQUAL)||(LA34_18 >= MINUS && LA34_18 <= NOTEQUAL)||(LA34_18 >= PERCENT && LA34_18 <= PLUS)||LA34_18==RBRACKET||(LA34_18 >= RIGHT && LA34_18 <= SLESSEQUAL)||(LA34_18 >= SREM && LA34_18 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_18==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 18, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_HEX:
				{
				int LA34_19 = input.LA(2);
				if ( ((LA34_19 >= AMPERSAND && LA34_19 <= ASTERISK)||(LA34_19 >= BOOL_AND && LA34_19 <= CARET)||LA34_19==COMMA||LA34_19==EQUAL||(LA34_19 >= FDIV && LA34_19 <= GREATEQUAL)||LA34_19==KEY_GOTO||(LA34_19 >= LEFT && LA34_19 <= LESSEQUAL)||(LA34_19 >= MINUS && LA34_19 <= NOTEQUAL)||(LA34_19 >= PERCENT && LA34_19 <= PLUS)||LA34_19==RBRACKET||(LA34_19 >= RIGHT && LA34_19 <= SLESSEQUAL)||(LA34_19 >= SREM && LA34_19 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_19==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 19, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_LITTLE:
				{
				int LA34_20 = input.LA(2);
				if ( ((LA34_20 >= AMPERSAND && LA34_20 <= ASTERISK)||(LA34_20 >= BOOL_AND && LA34_20 <= CARET)||LA34_20==COMMA||LA34_20==EQUAL||(LA34_20 >= FDIV && LA34_20 <= GREATEQUAL)||LA34_20==KEY_GOTO||(LA34_20 >= LEFT && LA34_20 <= LESSEQUAL)||(LA34_20 >= MINUS && LA34_20 <= NOTEQUAL)||(LA34_20 >= PERCENT && LA34_20 <= PLUS)||LA34_20==RBRACKET||(LA34_20 >= RIGHT && LA34_20 <= SLESSEQUAL)||(LA34_20 >= SREM && LA34_20 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_20==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 20, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_LOCAL:
				{
				int LA34_21 = input.LA(2);
				if ( ((LA34_21 >= AMPERSAND && LA34_21 <= ASTERISK)||(LA34_21 >= BOOL_AND && LA34_21 <= CARET)||LA34_21==COMMA||LA34_21==EQUAL||(LA34_21 >= FDIV && LA34_21 <= GREATEQUAL)||LA34_21==KEY_GOTO||(LA34_21 >= LEFT && LA34_21 <= LESSEQUAL)||(LA34_21 >= MINUS && LA34_21 <= NOTEQUAL)||(LA34_21 >= PERCENT && LA34_21 <= PLUS)||LA34_21==RBRACKET||(LA34_21 >= RIGHT && LA34_21 <= SLESSEQUAL)||(LA34_21 >= SREM && LA34_21 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_21==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 21, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_MACRO:
				{
				int LA34_22 = input.LA(2);
				if ( ((LA34_22 >= AMPERSAND && LA34_22 <= ASTERISK)||(LA34_22 >= BOOL_AND && LA34_22 <= CARET)||LA34_22==COMMA||LA34_22==EQUAL||(LA34_22 >= FDIV && LA34_22 <= GREATEQUAL)||LA34_22==KEY_GOTO||(LA34_22 >= LEFT && LA34_22 <= LESSEQUAL)||(LA34_22 >= MINUS && LA34_22 <= NOTEQUAL)||(LA34_22 >= PERCENT && LA34_22 <= PLUS)||LA34_22==RBRACKET||(LA34_22 >= RIGHT && LA34_22 <= SLESSEQUAL)||(LA34_22 >= SREM && LA34_22 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_22==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 22, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_NAMES:
				{
				int LA34_23 = input.LA(2);
				if ( ((LA34_23 >= AMPERSAND && LA34_23 <= ASTERISK)||(LA34_23 >= BOOL_AND && LA34_23 <= CARET)||LA34_23==COMMA||LA34_23==EQUAL||(LA34_23 >= FDIV && LA34_23 <= GREATEQUAL)||LA34_23==KEY_GOTO||(LA34_23 >= LEFT && LA34_23 <= LESSEQUAL)||(LA34_23 >= MINUS && LA34_23 <= NOTEQUAL)||(LA34_23 >= PERCENT && LA34_23 <= PLUS)||LA34_23==RBRACKET||(LA34_23 >= RIGHT && LA34_23 <= SLESSEQUAL)||(LA34_23 >= SREM && LA34_23 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_23==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 23, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_NOFLOW:
				{
				int LA34_24 = input.LA(2);
				if ( ((LA34_24 >= AMPERSAND && LA34_24 <= ASTERISK)||(LA34_24 >= BOOL_AND && LA34_24 <= CARET)||LA34_24==COMMA||LA34_24==EQUAL||(LA34_24 >= FDIV && LA34_24 <= GREATEQUAL)||LA34_24==KEY_GOTO||(LA34_24 >= LEFT && LA34_24 <= LESSEQUAL)||(LA34_24 >= MINUS && LA34_24 <= NOTEQUAL)||(LA34_24 >= PERCENT && LA34_24 <= PLUS)||LA34_24==RBRACKET||(LA34_24 >= RIGHT && LA34_24 <= SLESSEQUAL)||(LA34_24 >= SREM && LA34_24 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_24==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 24, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_OFFSET:
				{
				int LA34_25 = input.LA(2);
				if ( ((LA34_25 >= AMPERSAND && LA34_25 <= ASTERISK)||(LA34_25 >= BOOL_AND && LA34_25 <= CARET)||LA34_25==COMMA||LA34_25==EQUAL||(LA34_25 >= FDIV && LA34_25 <= GREATEQUAL)||LA34_25==KEY_GOTO||(LA34_25 >= LEFT && LA34_25 <= LESSEQUAL)||(LA34_25 >= MINUS && LA34_25 <= NOTEQUAL)||(LA34_25 >= PERCENT && LA34_25 <= PLUS)||LA34_25==RBRACKET||(LA34_25 >= RIGHT && LA34_25 <= SLESSEQUAL)||(LA34_25 >= SREM && LA34_25 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_25==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 25, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_PCODEOP:
				{
				int LA34_26 = input.LA(2);
				if ( ((LA34_26 >= AMPERSAND && LA34_26 <= ASTERISK)||(LA34_26 >= BOOL_AND && LA34_26 <= CARET)||LA34_26==COMMA||LA34_26==EQUAL||(LA34_26 >= FDIV && LA34_26 <= GREATEQUAL)||LA34_26==KEY_GOTO||(LA34_26 >= LEFT && LA34_26 <= LESSEQUAL)||(LA34_26 >= MINUS && LA34_26 <= NOTEQUAL)||(LA34_26 >= PERCENT && LA34_26 <= PLUS)||LA34_26==RBRACKET||(LA34_26 >= RIGHT && LA34_26 <= SLESSEQUAL)||(LA34_26 >= SREM && LA34_26 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_26==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 26, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_RETURN:
				{
				int LA34_27 = input.LA(2);
				if ( ((LA34_27 >= AMPERSAND && LA34_27 <= ASTERISK)||(LA34_27 >= BOOL_AND && LA34_27 <= CARET)||LA34_27==COMMA||LA34_27==EQUAL||(LA34_27 >= FDIV && LA34_27 <= GREATEQUAL)||LA34_27==KEY_GOTO||(LA34_27 >= LEFT && LA34_27 <= LESSEQUAL)||(LA34_27 >= MINUS && LA34_27 <= NOTEQUAL)||(LA34_27 >= PERCENT && LA34_27 <= PLUS)||LA34_27==RBRACKET||(LA34_27 >= RIGHT && LA34_27 <= SLESSEQUAL)||(LA34_27 >= SREM && LA34_27 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_27==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 27, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SIGNED:
				{
				int LA34_28 = input.LA(2);
				if ( ((LA34_28 >= AMPERSAND && LA34_28 <= ASTERISK)||(LA34_28 >= BOOL_AND && LA34_28 <= CARET)||LA34_28==COMMA||LA34_28==EQUAL||(LA34_28 >= FDIV && LA34_28 <= GREATEQUAL)||LA34_28==KEY_GOTO||(LA34_28 >= LEFT && LA34_28 <= LESSEQUAL)||(LA34_28 >= MINUS && LA34_28 <= NOTEQUAL)||(LA34_28 >= PERCENT && LA34_28 <= PLUS)||LA34_28==RBRACKET||(LA34_28 >= RIGHT && LA34_28 <= SLESSEQUAL)||(LA34_28 >= SREM && LA34_28 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_28==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 28, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SIZE:
				{
				int LA34_29 = input.LA(2);
				if ( ((LA34_29 >= AMPERSAND && LA34_29 <= ASTERISK)||(LA34_29 >= BOOL_AND && LA34_29 <= CARET)||LA34_29==COMMA||LA34_29==EQUAL||(LA34_29 >= FDIV && LA34_29 <= GREATEQUAL)||LA34_29==KEY_GOTO||(LA34_29 >= LEFT && LA34_29 <= LESSEQUAL)||(LA34_29 >= MINUS && LA34_29 <= NOTEQUAL)||(LA34_29 >= PERCENT && LA34_29 <= PLUS)||LA34_29==RBRACKET||(LA34_29 >= RIGHT && LA34_29 <= SLESSEQUAL)||(LA34_29 >= SREM && LA34_29 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_29==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 29, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_SPACE:
				{
				int LA34_30 = input.LA(2);
				if ( ((LA34_30 >= AMPERSAND && LA34_30 <= ASTERISK)||(LA34_30 >= BOOL_AND && LA34_30 <= CARET)||LA34_30==COMMA||LA34_30==EQUAL||(LA34_30 >= FDIV && LA34_30 <= GREATEQUAL)||LA34_30==KEY_GOTO||(LA34_30 >= LEFT && LA34_30 <= LESSEQUAL)||(LA34_30 >= MINUS && LA34_30 <= NOTEQUAL)||(LA34_30 >= PERCENT && LA34_30 <= PLUS)||LA34_30==RBRACKET||(LA34_30 >= RIGHT && LA34_30 <= SLESSEQUAL)||(LA34_30 >= SREM && LA34_30 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_30==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 30, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_TOKEN:
				{
				int LA34_31 = input.LA(2);
				if ( ((LA34_31 >= AMPERSAND && LA34_31 <= ASTERISK)||(LA34_31 >= BOOL_AND && LA34_31 <= CARET)||LA34_31==COMMA||LA34_31==EQUAL||(LA34_31 >= FDIV && LA34_31 <= GREATEQUAL)||LA34_31==KEY_GOTO||(LA34_31 >= LEFT && LA34_31 <= LESSEQUAL)||(LA34_31 >= MINUS && LA34_31 <= NOTEQUAL)||(LA34_31 >= PERCENT && LA34_31 <= PLUS)||LA34_31==RBRACKET||(LA34_31 >= RIGHT && LA34_31 <= SLESSEQUAL)||(LA34_31 >= SREM && LA34_31 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_31==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 31, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_TYPE:
				{
				int LA34_32 = input.LA(2);
				if ( ((LA34_32 >= AMPERSAND && LA34_32 <= ASTERISK)||(LA34_32 >= BOOL_AND && LA34_32 <= CARET)||LA34_32==COMMA||LA34_32==EQUAL||(LA34_32 >= FDIV && LA34_32 <= GREATEQUAL)||LA34_32==KEY_GOTO||(LA34_32 >= LEFT && LA34_32 <= LESSEQUAL)||(LA34_32 >= MINUS && LA34_32 <= NOTEQUAL)||(LA34_32 >= PERCENT && LA34_32 <= PLUS)||LA34_32==RBRACKET||(LA34_32 >= RIGHT && LA34_32 <= SLESSEQUAL)||(LA34_32 >= SREM && LA34_32 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_32==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 32, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_UNIMPL:
				{
				int LA34_33 = input.LA(2);
				if ( ((LA34_33 >= AMPERSAND && LA34_33 <= ASTERISK)||(LA34_33 >= BOOL_AND && LA34_33 <= CARET)||LA34_33==COMMA||LA34_33==EQUAL||(LA34_33 >= FDIV && LA34_33 <= GREATEQUAL)||LA34_33==KEY_GOTO||(LA34_33 >= LEFT && LA34_33 <= LESSEQUAL)||(LA34_33 >= MINUS && LA34_33 <= NOTEQUAL)||(LA34_33 >= PERCENT && LA34_33 <= PLUS)||LA34_33==RBRACKET||(LA34_33 >= RIGHT && LA34_33 <= SLESSEQUAL)||(LA34_33 >= SREM && LA34_33 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_33==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 33, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_VALUES:
				{
				int LA34_34 = input.LA(2);
				if ( ((LA34_34 >= AMPERSAND && LA34_34 <= ASTERISK)||(LA34_34 >= BOOL_AND && LA34_34 <= CARET)||LA34_34==COMMA||LA34_34==EQUAL||(LA34_34 >= FDIV && LA34_34 <= GREATEQUAL)||LA34_34==KEY_GOTO||(LA34_34 >= LEFT && LA34_34 <= LESSEQUAL)||(LA34_34 >= MINUS && LA34_34 <= NOTEQUAL)||(LA34_34 >= PERCENT && LA34_34 <= PLUS)||LA34_34==RBRACKET||(LA34_34 >= RIGHT && LA34_34 <= SLESSEQUAL)||(LA34_34 >= SREM && LA34_34 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_34==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 34, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_VARIABLES:
				{
				int LA34_35 = input.LA(2);
				if ( ((LA34_35 >= AMPERSAND && LA34_35 <= ASTERISK)||(LA34_35 >= BOOL_AND && LA34_35 <= CARET)||LA34_35==COMMA||LA34_35==EQUAL||(LA34_35 >= FDIV && LA34_35 <= GREATEQUAL)||LA34_35==KEY_GOTO||(LA34_35 >= LEFT && LA34_35 <= LESSEQUAL)||(LA34_35 >= MINUS && LA34_35 <= NOTEQUAL)||(LA34_35 >= PERCENT && LA34_35 <= PLUS)||LA34_35==RBRACKET||(LA34_35 >= RIGHT && LA34_35 <= SLESSEQUAL)||(LA34_35 >= SREM && LA34_35 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_35==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 35, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case KEY_WORDSIZE:
				{
				int LA34_36 = input.LA(2);
				if ( ((LA34_36 >= AMPERSAND && LA34_36 <= ASTERISK)||(LA34_36 >= BOOL_AND && LA34_36 <= CARET)||LA34_36==COMMA||LA34_36==EQUAL||(LA34_36 >= FDIV && LA34_36 <= GREATEQUAL)||LA34_36==KEY_GOTO||(LA34_36 >= LEFT && LA34_36 <= LESSEQUAL)||(LA34_36 >= MINUS && LA34_36 <= NOTEQUAL)||(LA34_36 >= PERCENT && LA34_36 <= PLUS)||LA34_36==RBRACKET||(LA34_36 >= RIGHT && LA34_36 <= SLESSEQUAL)||(LA34_36 >= SREM && LA34_36 <= SRIGHT)) ) {
					alt34=2;
				}
				else if ( (LA34_36==COLON) ) {
					alt34=4;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 36, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case AMPERSAND:
				{
				int LA34_37 = input.LA(2);
				if ( (LA34_37==COLON) ) {
					alt34=5;
				}
				else if ( (LA34_37==AMPERSAND||LA34_37==BIN_INT||LA34_37==DEC_INT||(LA34_37 >= HEX_INT && LA34_37 <= KEY_WORDSIZE)) ) {
					alt34=6;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 34, 37, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 34, 0, input);
				throw nvae;
			}
			switch (alt34) {
				case 1 :
					// SemanticParser.g:327:4: integer
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_integer_in_varnode2193);
					integer123=gSleighParser.integer();
					state._fsp--;

					adaptor.addChild(root_0, integer123.getTree());

					}
					break;
				case 2 :
					// SemanticParser.g:328:4: identifier
					{
					root_0 = (CommonTree)adaptor.nil();


					pushFollow(FOLLOW_identifier_in_varnode2198);
					identifier124=gSleighParser.identifier();
					state._fsp--;

					adaptor.addChild(root_0, identifier124.getTree());

					}
					break;
				case 3 :
					// SemanticParser.g:329:4: integer lc= COLON constant
					{
					pushFollow(FOLLOW_integer_in_varnode2203);
					integer125=gSleighParser.integer();
					state._fsp--;

					stream_integer.add(integer125.getTree());
					lc=(Token)match(input,COLON,FOLLOW_COLON_in_varnode2207);  
					stream_COLON.add(lc);

					pushFollow(FOLLOW_constant_in_varnode2209);
					constant126=constant();
					state._fsp--;

					stream_constant.add(constant126.getTree());
					// AST REWRITE
					// elements: constant, integer
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 329:30: -> ^( OP_TRUNCATION_SIZE[$lc] integer constant )
					{
						// SemanticParser.g:329:33: ^( OP_TRUNCATION_SIZE[$lc] integer constant )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_TRUNCATION_SIZE, lc), root_1);
						adaptor.addChild(root_1, stream_integer.nextTree());
						adaptor.addChild(root_1, stream_constant.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 4 :
					// SemanticParser.g:330:4: identifier lc= COLON constant
					{
					pushFollow(FOLLOW_identifier_in_varnode2225);
					identifier127=gSleighParser.identifier();
					state._fsp--;

					stream_identifier.add(identifier127.getTree());
					lc=(Token)match(input,COLON,FOLLOW_COLON_in_varnode2229);  
					stream_COLON.add(lc);

					pushFollow(FOLLOW_constant_in_varnode2231);
					constant128=constant();
					state._fsp--;

					stream_constant.add(constant128.getTree());
					// AST REWRITE
					// elements: identifier, constant
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 330:33: -> ^( OP_BITRANGE2[$lc] identifier constant )
					{
						// SemanticParser.g:330:36: ^( OP_BITRANGE2[$lc] identifier constant )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_BITRANGE2, lc), root_1);
						adaptor.addChild(root_1, stream_identifier.nextTree());
						adaptor.addChild(root_1, stream_constant.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 5 :
					// SemanticParser.g:331:4: lc= AMPERSAND fp= COLON constant varnode
					{
					lc=(Token)match(input,AMPERSAND,FOLLOW_AMPERSAND_in_varnode2249);  
					stream_AMPERSAND.add(lc);

					fp=(Token)match(input,COLON,FOLLOW_COLON_in_varnode2253);  
					stream_COLON.add(fp);

					pushFollow(FOLLOW_constant_in_varnode2255);
					constant129=constant();
					state._fsp--;

					stream_constant.add(constant129.getTree());
					pushFollow(FOLLOW_varnode_in_varnode2257);
					varnode130=varnode();
					state._fsp--;

					stream_varnode.add(varnode130.getTree());
					// AST REWRITE
					// elements: constant, varnode
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 331:43: -> ^( OP_ADDRESS_OF[$lc] ^( OP_SIZING_SIZE[$fp] constant ) varnode )
					{
						// SemanticParser.g:331:46: ^( OP_ADDRESS_OF[$lc] ^( OP_SIZING_SIZE[$fp] constant ) varnode )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_ADDRESS_OF, lc), root_1);
						// SemanticParser.g:331:67: ^( OP_SIZING_SIZE[$fp] constant )
						{
						CommonTree root_2 = (CommonTree)adaptor.nil();
						root_2 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_SIZING_SIZE, fp), root_2);
						adaptor.addChild(root_2, stream_constant.nextTree());
						adaptor.addChild(root_1, root_2);
						}

						adaptor.addChild(root_1, stream_varnode.nextTree());
						adaptor.addChild(root_0, root_1);
						}

					}


					retval.tree = root_0;

					}
					break;
				case 6 :
					// SemanticParser.g:332:4: lc= AMPERSAND varnode
					{
					lc=(Token)match(input,AMPERSAND,FOLLOW_AMPERSAND_in_varnode2280);  
					stream_AMPERSAND.add(lc);

					pushFollow(FOLLOW_varnode_in_varnode2282);
					varnode131=varnode();
					state._fsp--;

					stream_varnode.add(varnode131.getTree());
					// AST REWRITE
					// elements: varnode
					// token labels: 
					// rule labels: retval
					// token list labels: 
					// rule list labels: 
					// wildcard labels: 
					retval.tree = root_0;
					RewriteRuleSubtreeStream stream_retval=new RewriteRuleSubtreeStream(adaptor,"rule retval",retval!=null?retval.getTree():null);

					root_0 = (CommonTree)adaptor.nil();
					// 332:25: -> ^( OP_ADDRESS_OF[$lc] varnode )
					{
						// SemanticParser.g:332:28: ^( OP_ADDRESS_OF[$lc] varnode )
						{
						CommonTree root_1 = (CommonTree)adaptor.nil();
						root_1 = (CommonTree)adaptor.becomeRoot((CommonTree)adaptor.create(OP_ADDRESS_OF, lc), root_1);
						adaptor.addChild(root_1, stream_varnode.nextTree());
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
	// $ANTLR end "varnode"


	public static class constant_return extends ParserRuleReturnScope {
		CommonTree tree;
		@Override
		public CommonTree getTree() { return tree; }
	};


	// $ANTLR start "constant"
	// SemanticParser.g:335:1: constant : integer ;
	public final SleighParser_SemanticParser.constant_return constant() throws RecognitionException {
		SleighParser_SemanticParser.constant_return retval = new SleighParser_SemanticParser.constant_return();
		retval.start = input.LT(1);

		CommonTree root_0 = null;

		ParserRuleReturnScope integer132 =null;


		try {
			// SemanticParser.g:336:2: ( integer )
			// SemanticParser.g:336:4: integer
			{
			root_0 = (CommonTree)adaptor.nil();


			pushFollow(FOLLOW_integer_in_constant2302);
			integer132=gSleighParser.integer();
			state._fsp--;

			adaptor.addChild(root_0, integer132.getTree());

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
	// $ANTLR end "constant"

	// Delegated rules


	protected DFA3 dfa3 = new DFA3(this);
	static final String DFA3_eotS =
		"\136\uffff";
	static final String DFA3_eofS =
		"\136\uffff";
	static final String DFA3_minS =
		"\1\10\11\7\1\6\4\7\1\6\22\7\3\uffff\41\7\2\uffff\1\6\3\uffff\1\6\1\uffff"+
		"\1\6\1\12\1\uffff\6\6\1\uffff\3\6\3\7";
	static final String DFA3_maxS =
		"\1\u00dd\41\117\3\uffff\41\u00dd\2\uffff\1\u00e8\3\uffff\1\u00e8\1\uffff"+
		"\1\u00e8\1\47\1\uffff\6\u00e7\1\uffff\3\u00e7\3\u00dd";
	static final String DFA3_acceptS =
		"\42\uffff\1\1\1\7\1\13\41\uffff\1\3\1\4\1\uffff\1\10\1\5\1\11\1\uffff"+
		"\1\6\2\uffff\1\2\6\uffff\1\12\6\uffff";
	static final String DFA3_specialS =
		"\136\uffff}>";
	static final String[] DFA3_transitionS = {
			"\1\42\37\uffff\1\2\1\3\1\4\1\5\1\6\1\7\1\10\1\11\1\12\1\13\1\14\1\15"+
			"\1\16\1\17\1\20\1\21\1\22\1\1\1\23\1\24\1\25\1\26\1\27\1\30\1\31\1\32"+
			"\1\33\1\34\1\35\1\36\1\37\1\40\1\41\u008e\uffff\1\43\5\uffff\1\44",
			"\2\42\6\uffff\1\42\30\uffff\1\45\1\46\1\47\1\50\1\51\1\52\1\53\1\54"+
			"\1\55\1\56\1\57\1\60\1\61\1\62\1\63\1\64\1\65\1\66\1\67\1\70\1\71\1\72"+
			"\1\73\1\74\1\75\1\76\1\77\1\100\1\101\1\102\1\103\1\104\1\105\1\uffff"+
			"\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\30\uffff\41\107\1\uffff\1\42\4\uffff\1\106",
			"\1\42\2\uffff\1\111\4\uffff\1\42\2\uffff\1\111\24\uffff\42\111\1\uffff"+
			"\1\110\1\uffff\1\111\2\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\112\1\42\2\uffff\1\112\4\uffff\1\42\2\uffff\1\112\24\uffff\42\112"+
			"\1\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\113\1\42\1\113\1\uffff\1\113\4\uffff\1\42\2\uffff\1\113\24\uffff"+
			"\42\113\1\uffff\1\42\4\uffff\1\106",
			"\1\42\2\uffff\1\115\4\uffff\1\42\2\uffff\1\115\24\uffff\42\115\1\uffff"+
			"\1\114\1\uffff\1\115\2\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\116\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"\1\42\7\uffff\1\42\72\uffff\1\42\4\uffff\1\106",
			"",
			"",
			"",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"\1\42\7\uffff\1\117\72\uffff\1\42\u0092\uffff\1\120",
			"",
			"",
			"\1\111\1\uffff\1\111\1\uffff\1\123\7\uffff\1\122\6\uffff\1\111\6\uffff"+
			"\1\111\6\uffff\1\121\41\111\6\uffff\2\111\u0097\uffff\1\111",
			"",
			"",
			"",
			"\1\115\1\uffff\1\115\1\uffff\1\126\7\uffff\1\125\6\uffff\1\115\6\uffff"+
			"\1\115\6\uffff\1\124\41\115\6\uffff\2\115\u0097\uffff\1\115",
			"",
			"\1\127\1\uffff\1\127\1\uffff\1\132\7\uffff\1\131\6\uffff\1\127\6\uffff"+
			"\1\127\6\uffff\1\130\41\127\6\uffff\2\127\u0097\uffff\1\127",
			"\1\135\7\uffff\1\134\24\uffff\1\133",
			"",
			"\1\111\1\uffff\1\111\2\uffff\5\111\1\42\6\uffff\1\111\2\uffff\14\111"+
			"\45\uffff\3\111\2\uffff\2\111\175\uffff\3\111\4\uffff\1\111\3\uffff\1"+
			"\111\1\uffff\1\111\1\uffff\5\111\3\uffff\2\111",
			"\1\111\1\uffff\1\111\2\uffff\5\111\1\42\6\uffff\1\111\2\uffff\14\111"+
			"\45\uffff\3\111\2\uffff\2\111\175\uffff\3\111\4\uffff\1\111\3\uffff\1"+
			"\111\1\uffff\1\111\1\uffff\5\111\3\uffff\2\111",
			"\1\111\1\uffff\1\111\2\uffff\5\111\1\42\6\uffff\1\111\2\uffff\14\111"+
			"\45\uffff\3\111\2\uffff\2\111\175\uffff\3\111\4\uffff\1\111\3\uffff\1"+
			"\111\1\uffff\1\111\1\uffff\5\111\3\uffff\2\111",
			"\1\115\1\uffff\1\115\2\uffff\5\115\1\42\6\uffff\1\115\2\uffff\14\115"+
			"\45\uffff\3\115\2\uffff\2\115\175\uffff\3\115\4\uffff\1\115\3\uffff\1"+
			"\115\1\uffff\1\115\1\uffff\5\115\3\uffff\2\115",
			"\1\115\1\uffff\1\115\2\uffff\5\115\1\42\6\uffff\1\115\2\uffff\14\115"+
			"\45\uffff\3\115\2\uffff\2\115\175\uffff\3\115\4\uffff\1\115\3\uffff\1"+
			"\115\1\uffff\1\115\1\uffff\5\115\3\uffff\2\115",
			"\1\115\1\uffff\1\115\2\uffff\5\115\1\42\6\uffff\1\115\2\uffff\14\115"+
			"\45\uffff\3\115\2\uffff\2\115\175\uffff\3\115\4\uffff\1\115\3\uffff\1"+
			"\115\1\uffff\1\115\1\uffff\5\115\3\uffff\2\115",
			"",
			"\1\127\1\uffff\1\127\2\uffff\5\127\1\42\6\uffff\1\127\2\uffff\14\127"+
			"\45\uffff\3\127\2\uffff\2\127\175\uffff\3\127\4\uffff\1\127\3\uffff\1"+
			"\127\1\uffff\1\127\1\uffff\5\127\3\uffff\2\127",
			"\1\127\1\uffff\1\127\2\uffff\5\127\1\42\6\uffff\1\127\2\uffff\14\127"+
			"\45\uffff\3\127\2\uffff\2\127\175\uffff\3\127\4\uffff\1\127\3\uffff\1"+
			"\127\1\uffff\1\127\1\uffff\5\127\3\uffff\2\127",
			"\1\127\1\uffff\1\127\2\uffff\5\127\1\42\6\uffff\1\127\2\uffff\14\127"+
			"\45\uffff\3\127\2\uffff\2\127\175\uffff\3\127\4\uffff\1\127\3\uffff\1"+
			"\127\1\uffff\1\127\1\uffff\5\127\3\uffff\2\127",
			"\1\42\u00d5\uffff\1\120",
			"\1\42\u00d5\uffff\1\120",
			"\1\42\u00d5\uffff\1\120"
	};

	static final short[] DFA3_eot = DFA.unpackEncodedString(DFA3_eotS);
	static final short[] DFA3_eof = DFA.unpackEncodedString(DFA3_eofS);
	static final char[] DFA3_min = DFA.unpackEncodedStringToUnsignedChars(DFA3_minS);
	static final char[] DFA3_max = DFA.unpackEncodedStringToUnsignedChars(DFA3_maxS);
	static final short[] DFA3_accept = DFA.unpackEncodedString(DFA3_acceptS);
	static final short[] DFA3_special = DFA.unpackEncodedString(DFA3_specialS);
	static final short[][] DFA3_transition;

	static {
		int numStates = DFA3_transitionS.length;
		DFA3_transition = new short[numStates][];
		for (int i=0; i<numStates; i++) {
			DFA3_transition[i] = DFA.unpackEncodedString(DFA3_transitionS[i]);
		}
	}

	protected class DFA3 extends DFA {

		public DFA3(BaseRecognizer recognizer) {
			this.recognizer = recognizer;
			this.decisionNumber = 3;
			this.eot = DFA3_eot;
			this.eof = DFA3_eof;
			this.min = DFA3_min;
			this.max = DFA3_max;
			this.accept = DFA3_accept;
			this.special = DFA3_special;
			this.transition = DFA3_transition;
		}
		@Override
		public String getDescription() {
			return "45:4: ( assignment | declaration | funcall | build_stmt | crossbuild_stmt | goto_stmt | cond_stmt | call_stmt | export | return_stmt |)";
		}
	}

	public static final BitSet FOLLOW_LBRACE_in_semanticbody30 = new BitSet(new long[]{0xFFFFFF2FFC81F9C0L,0x000000000003B9FFL,0x0000000000000000L,0x000001C7F8C38000L});
	public static final BitSet FOLLOW_semantic_in_semanticbody34 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000200000L});
	public static final BitSet FOLLOW_RBRACE_in_semanticbody36 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_code_block_in_semantic53 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_statements_in_code_block72 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_statement_in_statements95 = new BitSet(new long[]{0xFFFFFF2FFC81F9C2L,0x000000000003B9FFL,0x0000000000000000L,0x000001C7F8C38000L});
	public static final BitSet FOLLOW_LESS_in_label109 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_label111 = new BitSet(new long[]{0x0000001000000000L});
	public static final BitSet FOLLOW_GREAT_in_label113 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LEFT_in_section_def135 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_section_def137 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000004000000L});
	public static final BitSet FOLLOW_RIGHT_in_section_def139 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_assignment_in_statement167 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_declaration_in_statement173 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_funcall_in_statement179 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_build_stmt_in_statement185 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_crossbuild_stmt_in_statement191 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_goto_stmt_in_statement197 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_cond_stmt_in_statement203 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_call_stmt_in_statement209 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_export_in_statement215 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_return_stmt_in_statement221 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000020000000L});
	public static final BitSet FOLLOW_SEMI_in_statement235 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_label_in_statement243 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_section_def_in_statement248 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_outererror_in_statement253 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_EQUAL_in_outererror267 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_NOTEQUAL_in_outererror274 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FEQUAL_in_outererror281 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FNOTEQUAL_in_outererror288 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LESSEQUAL_in_outererror295 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_GREATEQUAL_in_outererror302 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SLESS_in_outererror309 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SGREAT_in_outererror316 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SLESSEQUAL_in_outererror323 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SGREATEQUAL_in_outererror330 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FLESS_in_outererror337 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FGREAT_in_outererror344 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FLESSEQUAL_in_outererror351 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FGREATEQUAL_in_outererror358 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_ASSIGN_in_outererror365 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_COLON_in_outererror372 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_COMMA_in_outererror379 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_RBRACKET_in_outererror386 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_BOOL_OR_in_outererror393 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_BOOL_XOR_in_outererror400 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_BOOL_AND_in_outererror407 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_PIPE_in_outererror414 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_CARET_in_outererror421 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_AMPERSAND_in_outererror428 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SRIGHT_in_outererror435 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_PLUS_in_outererror442 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_MINUS_in_outererror449 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FPLUS_in_outererror456 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FMINUS_in_outererror463 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SLASH_in_outererror470 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_PERCENT_in_outererror477 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SDIV_in_outererror484 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SREM_in_outererror491 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FMULT_in_outererror498 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FDIV_in_outererror505 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_TILDE_in_outererror512 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LPAREN_in_outererror519 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_RPAREN_in_outererror526 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_LOCAL_in_assignment542 = new BitSet(new long[]{0xFFFFFF0000000100L,0x00000000000001FFL});
	public static final BitSet FOLLOW_lvalue_in_assignment544 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_assignment548 = new BitSet(new long[]{0xFFFFFF8102040540L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_expr_in_assignment550 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_lvalue_in_assignment569 = new BitSet(new long[]{0x0000000000000080L});
	public static final BitSet FOLLOW_ASSIGN_in_assignment573 = new BitSet(new long[]{0xFFFFFF8102040540L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_expr_in_assignment575 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_LOCAL_in_declaration599 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_declaration601 = new BitSet(new long[]{0x0000000000008000L});
	public static final BitSet FOLLOW_COLON_in_declaration605 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_constant_in_declaration607 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_LOCAL_in_declaration625 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_declaration627 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_sembitrange_in_lvalue647 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_lvalue652 = new BitSet(new long[]{0x0000000000008000L});
	public static final BitSet FOLLOW_COLON_in_lvalue656 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_constant_in_lvalue658 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_lvalue674 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_sizedstar_in_lvalue679 = new BitSet(new long[]{0xFFFFFF8102040540L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_expr_in_lvalue682 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_sembitrange693 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_LBRACKET_in_sembitrange697 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_constant_in_sembitrange701 = new BitSet(new long[]{0x0000000000010000L});
	public static final BitSet FOLLOW_COMMA_in_sembitrange703 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_constant_in_sembitrange707 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000400000L});
	public static final BitSet FOLLOW_RBRACKET_in_sembitrange709 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_ASTERISK_in_sizedstar737 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_LBRACKET_in_sizedstar739 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_sizedstar741 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000400000L});
	public static final BitSet FOLLOW_RBRACKET_in_sizedstar743 = new BitSet(new long[]{0x0000000000008000L});
	public static final BitSet FOLLOW_COLON_in_sizedstar745 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_constant_in_sizedstar747 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_ASTERISK_in_sizedstar765 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_LBRACKET_in_sizedstar767 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_sizedstar769 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000400000L});
	public static final BitSet FOLLOW_RBRACKET_in_sizedstar771 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_ASTERISK_in_sizedstar802 = new BitSet(new long[]{0x0000000000008000L});
	public static final BitSet FOLLOW_COLON_in_sizedstar833 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_constant_in_sizedstar835 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_ASTERISK_in_sizedstar851 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_apply_in_funcall913 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_BUILD_in_build_stmt926 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_build_stmt928 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_CROSSBUILD_in_crossbuild_stmt950 = new BitSet(new long[]{0xFFFFFF8000040440L,0x00000000000001FFL});
	public static final BitSet FOLLOW_varnode_in_crossbuild_stmt952 = new BitSet(new long[]{0x0000000000010000L});
	public static final BitSet FOLLOW_COMMA_in_crossbuild_stmt954 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_crossbuild_stmt956 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_GOTO_in_goto_stmt979 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000015FFL});
	public static final BitSet FOLLOW_jumpdest_in_goto_stmt981 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_jumpdest1001 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LBRACKET_in_jumpdest1014 = new BitSet(new long[]{0xFFFFFF8102040540L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_expr_in_jumpdest1016 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000400000L});
	public static final BitSet FOLLOW_RBRACKET_in_jumpdest1018 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_integer_in_jumpdest1031 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_constant_in_jumpdest1044 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_LBRACKET_in_jumpdest1046 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_jumpdest1048 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000400000L});
	public static final BitSet FOLLOW_RBRACKET_in_jumpdest1050 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_label_in_jumpdest1065 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_RES_IF_in_cond_stmt1086 = new BitSet(new long[]{0xFFFFFF8102040540L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_expr_in_cond_stmt1088 = new BitSet(new long[]{0x0040000000000000L});
	public static final BitSet FOLLOW_goto_stmt_in_cond_stmt1090 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_CALL_in_call_stmt1114 = new BitSet(new long[]{0xFFFFFF8000040400L,0x00000000000015FFL});
	public static final BitSet FOLLOW_jumpdest_in_call_stmt1116 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_RETURN_in_return_stmt1138 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_LBRACKET_in_return_stmt1140 = new BitSet(new long[]{0xFFFFFF8102040540L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_expr_in_return_stmt1142 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000000400000L});
	public static final BitSet FOLLOW_RBRACKET_in_return_stmt1144 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_sizedstar_in_sizedexport1164 = new BitSet(new long[]{0xFFFFFF0000000000L,0x00000000000001FFL});
	public static final BitSet FOLLOW_identifier_in_sizedexport1167 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_EXPORT_in_export1180 = new BitSet(new long[]{0x0000000000000100L});
	public static final BitSet FOLLOW_sizedexport_in_export1182 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_EXPORT_in_export1198 = new BitSet(new long[]{0xFFFFFF8000040440L,0x00000000000001FFL});
	public static final BitSet FOLLOW_varnode_in_export1200 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_boolor_in_expr1220 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_booland_in_expr_boolor1231 = new BitSet(new long[]{0x0000000000001002L});
	public static final BitSet FOLLOW_expr_boolor_op_in_expr_boolor1235 = new BitSet(new long[]{0xFFFFFF8102040540L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_expr_booland_in_expr_boolor1238 = new BitSet(new long[]{0x0000000000001002L});
	public static final BitSet FOLLOW_BOOL_OR_in_expr_boolor_op1254 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_or_in_expr_booland1272 = new BitSet(new long[]{0x0000000000002802L});
	public static final BitSet FOLLOW_booland_op_in_expr_booland1276 = new BitSet(new long[]{0xFFFFFF8102040540L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_expr_or_in_expr_booland1279 = new BitSet(new long[]{0x0000000000002802L});
	public static final BitSet FOLLOW_BOOL_AND_in_booland_op1295 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_BOOL_XOR_in_booland_op1309 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_xor_in_expr_or1327 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000000000010000L});
	public static final BitSet FOLLOW_expr_or_op_in_expr_or1331 = new BitSet(new long[]{0xFFFFFF8102040540L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_expr_xor_in_expr_or1334 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000000L,0x0000000000000000L,0x0000000000010000L});
	public static final BitSet FOLLOW_PIPE_in_expr_or_op1350 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_and_in_expr_xor1368 = new BitSet(new long[]{0x0000000000004002L});
	public static final BitSet FOLLOW_expr_xor_op_in_expr_xor1372 = new BitSet(new long[]{0xFFFFFF8102040540L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_expr_and_in_expr_xor1375 = new BitSet(new long[]{0x0000000000004002L});
	public static final BitSet FOLLOW_CARET_in_expr_xor_op1391 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_eq_in_expr_and1409 = new BitSet(new long[]{0x0000000000000042L});
	public static final BitSet FOLLOW_expr_and_op_in_expr_and1413 = new BitSet(new long[]{0xFFFFFF8102040540L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_expr_eq_in_expr_and1416 = new BitSet(new long[]{0x0000000000000042L});
	public static final BitSet FOLLOW_AMPERSAND_in_expr_and_op1432 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_comp_in_expr_eq1450 = new BitSet(new long[]{0x0000000408800002L,0x0000000000020000L});
	public static final BitSet FOLLOW_eq_op_in_expr_eq1454 = new BitSet(new long[]{0xFFFFFF8102040540L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_expr_comp_in_expr_eq1457 = new BitSet(new long[]{0x0000000408800002L,0x0000000000020000L});
	public static final BitSet FOLLOW_EQUAL_in_eq_op1473 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_NOTEQUAL_in_eq_op1487 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FEQUAL_in_eq_op1501 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FNOTEQUAL_in_eq_op1515 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_shift_in_expr_comp1533 = new BitSet(new long[]{0x00000030F0000002L,0x0000000000003000L,0x0000000000000000L,0x00000006C0000000L});
	public static final BitSet FOLLOW_compare_op_in_expr_comp1537 = new BitSet(new long[]{0xFFFFFF8102040540L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_expr_shift_in_expr_comp1540 = new BitSet(new long[]{0x00000030F0000002L,0x0000000000003000L,0x0000000000000000L,0x00000006C0000000L});
	public static final BitSet FOLLOW_LESS_in_compare_op1556 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_GREATEQUAL_in_compare_op1570 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LESSEQUAL_in_compare_op1584 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_GREAT_in_compare_op1598 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SLESS_in_compare_op1612 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SGREATEQUAL_in_compare_op1626 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SLESSEQUAL_in_compare_op1640 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SGREAT_in_compare_op1654 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FLESS_in_compare_op1668 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FGREATEQUAL_in_compare_op1682 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FLESSEQUAL_in_compare_op1696 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FGREAT_in_compare_op1710 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_add_in_expr_shift1728 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000800L,0x0000000000000000L,0x0000008004000000L});
	public static final BitSet FOLLOW_shift_op_in_expr_shift1732 = new BitSet(new long[]{0xFFFFFF8102040540L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_expr_add_in_expr_shift1735 = new BitSet(new long[]{0x0000000000000002L,0x0000000000000800L,0x0000000000000000L,0x0000008004000000L});
	public static final BitSet FOLLOW_LEFT_in_shift_op1751 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_RIGHT_in_shift_op1765 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SRIGHT_in_shift_op1779 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_mult_in_expr_add1797 = new BitSet(new long[]{0x0000000900000002L,0x0000000000010000L,0x0000000000000000L,0x0000000000020000L});
	public static final BitSet FOLLOW_add_op_in_expr_add1801 = new BitSet(new long[]{0xFFFFFF8102040540L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_expr_mult_in_expr_add1804 = new BitSet(new long[]{0x0000000900000002L,0x0000000000010000L,0x0000000000000000L,0x0000000000020000L});
	public static final BitSet FOLLOW_PLUS_in_add_op1820 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_MINUS_in_add_op1834 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FPLUS_in_add_op1848 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FMINUS_in_add_op1862 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_unary_in_expr_mult1880 = new BitSet(new long[]{0x0000000204000102L,0x0000000000000000L,0x0000000000000000L,0x0000004110008000L});
	public static final BitSet FOLLOW_mult_op_in_expr_mult1884 = new BitSet(new long[]{0xFFFFFF8102040540L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_expr_unary_in_expr_mult1887 = new BitSet(new long[]{0x0000000204000102L,0x0000000000000000L,0x0000000000000000L,0x0000004110008000L});
	public static final BitSet FOLLOW_ASTERISK_in_mult_op1903 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SLASH_in_mult_op1917 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_PERCENT_in_mult_op1931 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SDIV_in_mult_op1945 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_SREM_in_mult_op1959 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FMULT_in_mult_op1973 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FDIV_in_mult_op1987 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_unary_op_in_expr_unary2005 = new BitSet(new long[]{0xFFFFFF8000040440L,0x00000000000081FFL});
	public static final BitSet FOLLOW_expr_func_in_expr_unary2010 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_EXCLAIM_in_unary_op2023 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_TILDE_in_unary_op2037 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_MINUS_in_unary_op2051 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_FMINUS_in_unary_op2065 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_sizedstar_in_unary_op2077 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_apply_in_expr_func2088 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_term_in_expr_func2093 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_expr_apply2104 = new BitSet(new long[]{0x0000000000000000L,0x0000000000008000L});
	public static final BitSet FOLLOW_expr_operands_in_expr_apply2106 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LPAREN_in_expr_operands2128 = new BitSet(new long[]{0xFFFFFF8102040540L,0x00000000000181FFL,0x0000000000000000L,0x0000010008000000L});
	public static final BitSet FOLLOW_expr_in_expr_operands2132 = new BitSet(new long[]{0x0000000000010000L,0x0000000000000000L,0x0000000000000000L,0x0000000008000000L});
	public static final BitSet FOLLOW_COMMA_in_expr_operands2135 = new BitSet(new long[]{0xFFFFFF8102040540L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_expr_in_expr_operands2138 = new BitSet(new long[]{0x0000000000010000L,0x0000000000000000L,0x0000000000000000L,0x0000000008000000L});
	public static final BitSet FOLLOW_RPAREN_in_expr_operands2145 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_varnode_in_expr_term2157 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_sembitrange_in_expr_term2162 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_LPAREN_in_expr_term2169 = new BitSet(new long[]{0xFFFFFF8102040540L,0x00000000000181FFL,0x0000000000000000L,0x0000010000000000L});
	public static final BitSet FOLLOW_expr_in_expr_term2171 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,0x0000000008000000L});
	public static final BitSet FOLLOW_RPAREN_in_expr_term2173 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_integer_in_varnode2193 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_varnode2198 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_integer_in_varnode2203 = new BitSet(new long[]{0x0000000000008000L});
	public static final BitSet FOLLOW_COLON_in_varnode2207 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_constant_in_varnode2209 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_identifier_in_varnode2225 = new BitSet(new long[]{0x0000000000008000L});
	public static final BitSet FOLLOW_COLON_in_varnode2229 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_constant_in_varnode2231 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_AMPERSAND_in_varnode2249 = new BitSet(new long[]{0x0000000000008000L});
	public static final BitSet FOLLOW_COLON_in_varnode2253 = new BitSet(new long[]{0x0000008000040400L});
	public static final BitSet FOLLOW_constant_in_varnode2255 = new BitSet(new long[]{0xFFFFFF8000040440L,0x00000000000001FFL});
	public static final BitSet FOLLOW_varnode_in_varnode2257 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_AMPERSAND_in_varnode2280 = new BitSet(new long[]{0xFFFFFF8000040440L,0x00000000000001FFL});
	public static final BitSet FOLLOW_varnode_in_varnode2282 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_integer_in_constant2302 = new BitSet(new long[]{0x0000000000000002L});
}
