package ghidra.sleigh.grammar;
// $ANTLR 3.5.2 ghidra/sleigh/grammar/SleighCompiler.g 2019-02-28 12:48:46

	import generic.stl.Pair;
	import generic.stl.VectorSTL;
	import ghidra.pcodeCPort.opcodes.OpCode;
	import ghidra.pcodeCPort.semantics.*;
	import ghidra.pcodeCPort.slgh_compile.*;
	import ghidra.pcodeCPort.slghpatexpress.*;
	import ghidra.pcodeCPort.slghsymbol.*;
	import ghidra.pcodeCPort.space.AddrSpace;

	import java.math.BigInteger;
	import java.util.Stack;

	import org.antlr.runtime.*;
	import org.antlr.runtime.Token;
	import org.antlr.runtime.tree.*;


import org.antlr.runtime.*;
import org.antlr.runtime.tree.*;
import java.util.Stack;
import java.util.List;
import java.util.ArrayList;

@SuppressWarnings("all")
public class SleighCompiler extends TreeParser {
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
		"WS"
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
	public TreeParser[] getDelegates() {
		return new TreeParser[] {};
	}

	// delegators

	protected static class Return_scope {
		boolean noReturn;
	}
	protected Stack<Return_scope> Return_stack = new Stack<Return_scope>();

	protected static class Block_scope {
		ConstructTpl ct;
	}
	protected Stack<Block_scope> Block_stack = new Stack<Block_scope>();

	protected static class Jump_scope {
		boolean indirect;
	}
	protected Stack<Jump_scope> Jump_stack = new Stack<Jump_scope>();


	public SleighCompiler(TreeNodeStream input) {
		this(input, new RecognizerSharedState());
	}
	public SleighCompiler(TreeNodeStream input, RecognizerSharedState state) {
		super(input, state);
	}

	@Override public String[] getTokenNames() { return SleighCompiler.tokenNames; }
	@Override public String getGrammarFileName() { return "ghidra/sleigh/grammar/SleighCompiler.g"; }


		private ParsingEnvironment env = null;
		private SleighCompile sc = null;
		private PcodeCompile pcode = null;

		private void reportError(Location loc, String msg) {
			if (pcode != null) {
		    	pcode.reportError(loc, msg);
		    }
		    else {
		    	sc.reportError(loc, msg);
		    }
		}

		private void reportWarning(Location loc, String msg) {
			if (pcode != null) {
		    	pcode.reportWarning(loc, msg);
		    }
		    else {
		    	sc.reportWarning(loc, msg);
		    }
		}

		private void check(RadixBigInteger rbi) {
			if (rbi.bitLength() > 64) {
				reportError(rbi.location, "Integer representation exceeds Java long (" + rbi + ")");
			}
		}

		private void redefinedError(SleighSymbol sym, Tree t, String what) {
		    String msg = "symbol " + sym.getName() + " (from " + sym.getLocation() + ") redefined as " + what;
		    reportError(find(t), msg);
		}

		private void wildcardError(Tree t, String what) {
		    String msg = "wildcard (_) not allowed in " + what;
		    reportError(find(t), msg);
		}

		private void wrongSymbolTypeError(SleighSymbol sym, Location where, String type, String purpose) {
		    String msg = sym.getType() + " " + sym + " (defined at " + sym.getLocation() + ") is wrong type (should be " + type + ") in " + purpose;
		    reportError(where, msg);
		}

		private void undeclaredSymbolError(SleighSymbol sym, Location where, String purpose) {
		    String msg = sym + " (used in " + purpose + ") is not declared in the pattern list";
		    reportError(where, msg);
		}

		private void unknownSymbolError(String text, Location loc, String type, String purpose) {
		    String msg = "unknown " + type + " " + text + " in " + purpose;
		    reportError(loc, msg);
		}

		private void invalidDynamicTargetError(Location loc, String purpose) {
		    String msg = "invalid dynamic target used in " + purpose;
		    reportError(loc, msg);
		}

		private Location find(Tree t) {
		    return env.getLocator().getLocation(t.getLine());
		}
		
		private SubtableSymbol findOrNewTable(Location loc, String name) {
			SleighSymbol sym = sc.findSymbol(name);
			if (sym == null) {
				SubtableSymbol ss = sc.newTable(loc, name);
				return ss;
			} else if(sym.getType() != symbol_type.subtable_symbol) {
				wrongSymbolTypeError(sym, loc, "subtable", "subconstructor");
				return null;
			} else {
				return (SubtableSymbol) sym;
			}
		}

		public String getErrorMessage(RecognitionException e, String[] tokenNames) {
		    return env.getParserErrorMessage(e, tokenNames);
		}

		public String getTokenErrorDisplay(Token t) {
		    return env.getTokenErrorDisplay(t);
		}

		public String getErrorHeader(RecognitionException e) {
		    return env.getErrorHeader(e);
		}

		void bail(String msg) {
		    throw new BailoutException(msg);
		}



	// $ANTLR start "root"
	// ghidra/sleigh/grammar/SleighCompiler.g:131:1: root[ParsingEnvironment pe, SleighCompile sc] returns [int errors] : endiandef ( definition | constructorlike )* ;
	public final int root(ParsingEnvironment pe, SleighCompile sc) throws RecognitionException {
		int errors = 0;



				this.env = pe;
				this.sc = sc;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:139:2: ( endiandef ( definition | constructorlike )* )
			// ghidra/sleigh/grammar/SleighCompiler.g:139:4: endiandef ( definition | constructorlike )*
			{
			pushFollow(FOLLOW_endiandef_in_root80);
			endiandef();
			state._fsp--;

			// ghidra/sleigh/grammar/SleighCompiler.g:140:3: ( definition | constructorlike )*
			loop1:
			while (true) {
				int alt1=3;
				int LA1_0 = input.LA(1);
				if ( (LA1_0==OP_ALIGNMENT||LA1_0==OP_BITRANGES||LA1_0==OP_CONTEXT||LA1_0==OP_NAMES||LA1_0==OP_PCODEOP||LA1_0==OP_SPACE||LA1_0==OP_TOKEN||(LA1_0 >= OP_VALUES && LA1_0 <= OP_VARNODE)) ) {
					alt1=1;
				}
				else if ( (LA1_0==OP_CONSTRUCTOR||LA1_0==OP_MACRO||LA1_0==OP_WITH) ) {
					alt1=2;
				}

				switch (alt1) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:140:5: definition
					{
					pushFollow(FOLLOW_definition_in_root86);
					definition();
					state._fsp--;

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:141:5: constructorlike
					{
					pushFollow(FOLLOW_constructorlike_in_root92);
					constructorlike();
					state._fsp--;

					}
					break;

				default :
					break loop1;
				}
			}

			}


					errors = env.getLexingErrors() + env.getParsingErrors();
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return errors;
	}
	// $ANTLR end "root"



	// $ANTLR start "endiandef"
	// ghidra/sleigh/grammar/SleighCompiler.g:145:1: endiandef : ^( OP_ENDIAN s= endian ) ;
	public final void endiandef() throws RecognitionException {
		int s =0;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:146:2: ( ^( OP_ENDIAN s= endian ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:146:4: ^( OP_ENDIAN s= endian )
			{
			match(input,OP_ENDIAN,FOLLOW_OP_ENDIAN_in_endiandef109); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_endian_in_endiandef113);
			s=endian();
			state._fsp--;

			match(input, Token.UP, null); 

			 sc.setEndian(s); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "endiandef"



	// $ANTLR start "endian"
	// ghidra/sleigh/grammar/SleighCompiler.g:149:1: endian returns [int value] : ( OP_BIG | OP_LITTLE );
	public final int endian() throws RecognitionException {
		int value = 0;


		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:150:2: ( OP_BIG | OP_LITTLE )
			int alt2=2;
			int LA2_0 = input.LA(1);
			if ( (LA2_0==OP_BIG) ) {
				alt2=1;
			}
			else if ( (LA2_0==OP_LITTLE) ) {
				alt2=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 2, 0, input);
				throw nvae;
			}

			switch (alt2) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:150:4: OP_BIG
					{
					match(input,OP_BIG,FOLLOW_OP_BIG_in_endian131); 
					 value = 1; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:151:4: OP_LITTLE
					{
					match(input,OP_LITTLE,FOLLOW_OP_LITTLE_in_endian141); 
					 value = 0; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "endian"



	// $ANTLR start "definition"
	// ghidra/sleigh/grammar/SleighCompiler.g:154:1: definition : ( aligndef | tokendef | contextdef | spacedef | varnodedef | bitrangedef | pcodeopdef | valueattach | nameattach | varattach ) ;
	public final void definition() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:155:2: ( ( aligndef | tokendef | contextdef | spacedef | varnodedef | bitrangedef | pcodeopdef | valueattach | nameattach | varattach ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:155:4: ( aligndef | tokendef | contextdef | spacedef | varnodedef | bitrangedef | pcodeopdef | valueattach | nameattach | varattach )
			{
			// ghidra/sleigh/grammar/SleighCompiler.g:155:4: ( aligndef | tokendef | contextdef | spacedef | varnodedef | bitrangedef | pcodeopdef | valueattach | nameattach | varattach )
			int alt3=10;
			switch ( input.LA(1) ) {
			case OP_ALIGNMENT:
				{
				alt3=1;
				}
				break;
			case OP_TOKEN:
				{
				alt3=2;
				}
				break;
			case OP_CONTEXT:
				{
				alt3=3;
				}
				break;
			case OP_SPACE:
				{
				alt3=4;
				}
				break;
			case OP_VARNODE:
				{
				alt3=5;
				}
				break;
			case OP_BITRANGES:
				{
				alt3=6;
				}
				break;
			case OP_PCODEOP:
				{
				alt3=7;
				}
				break;
			case OP_VALUES:
				{
				alt3=8;
				}
				break;
			case OP_NAMES:
				{
				alt3=9;
				}
				break;
			case OP_VARIABLES:
				{
				alt3=10;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 3, 0, input);
				throw nvae;
			}
			switch (alt3) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:155:5: aligndef
					{
					pushFollow(FOLLOW_aligndef_in_definition155);
					aligndef();
					state._fsp--;

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:156:4: tokendef
					{
					pushFollow(FOLLOW_tokendef_in_definition160);
					tokendef();
					state._fsp--;

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:157:4: contextdef
					{
					pushFollow(FOLLOW_contextdef_in_definition165);
					contextdef();
					state._fsp--;

					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:158:4: spacedef
					{
					pushFollow(FOLLOW_spacedef_in_definition170);
					spacedef();
					state._fsp--;

					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighCompiler.g:159:4: varnodedef
					{
					pushFollow(FOLLOW_varnodedef_in_definition175);
					varnodedef();
					state._fsp--;

					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighCompiler.g:160:4: bitrangedef
					{
					pushFollow(FOLLOW_bitrangedef_in_definition180);
					bitrangedef();
					state._fsp--;

					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighCompiler.g:161:4: pcodeopdef
					{
					pushFollow(FOLLOW_pcodeopdef_in_definition185);
					pcodeopdef();
					state._fsp--;

					}
					break;
				case 8 :
					// ghidra/sleigh/grammar/SleighCompiler.g:162:4: valueattach
					{
					pushFollow(FOLLOW_valueattach_in_definition190);
					valueattach();
					state._fsp--;

					}
					break;
				case 9 :
					// ghidra/sleigh/grammar/SleighCompiler.g:163:4: nameattach
					{
					pushFollow(FOLLOW_nameattach_in_definition195);
					nameattach();
					state._fsp--;

					}
					break;
				case 10 :
					// ghidra/sleigh/grammar/SleighCompiler.g:164:4: varattach
					{
					pushFollow(FOLLOW_varattach_in_definition200);
					varattach();
					state._fsp--;

					}
					break;

			}

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "definition"



	// $ANTLR start "aligndef"
	// ghidra/sleigh/grammar/SleighCompiler.g:168:1: aligndef : ^( OP_ALIGNMENT i= integer ) ;
	public final void aligndef() throws RecognitionException {
		RadixBigInteger i =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:169:2: ( ^( OP_ALIGNMENT i= integer ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:169:4: ^( OP_ALIGNMENT i= integer )
			{
			match(input,OP_ALIGNMENT,FOLLOW_OP_ALIGNMENT_in_aligndef215); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_integer_in_aligndef219);
			i=integer();
			state._fsp--;

			match(input, Token.UP, null); 

			 sc.setAlignment(i.intValue()); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "aligndef"


	protected static class tokendef_scope {
		TokenSymbol tokenSymbol;
	}
	protected Stack<tokendef_scope> tokendef_stack = new Stack<tokendef_scope>();


	// $ANTLR start "tokendef"
	// ghidra/sleigh/grammar/SleighCompiler.g:172:1: tokendef : ^( OP_TOKEN n= specific_identifier[\"token definition\"] i= integer fielddefs ) ;
	public final void tokendef() throws RecognitionException {
		tokendef_stack.push(new tokendef_scope());
		Tree n =null;
		RadixBigInteger i =null;


				tokendef_stack.peek().tokenSymbol = null;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:179:2: ( ^( OP_TOKEN n= specific_identifier[\"token definition\"] i= integer fielddefs ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:179:4: ^( OP_TOKEN n= specific_identifier[\"token definition\"] i= integer fielddefs )
			{
			match(input,OP_TOKEN,FOLLOW_OP_TOKEN_in_tokendef245); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_specific_identifier_in_tokendef249);
			n=specific_identifier("token definition");
			state._fsp--;

			pushFollow(FOLLOW_integer_in_tokendef254);
			i=integer();
			state._fsp--;


						if (n != null) {
							SleighSymbol sym = sc.findSymbol(n.getText());
							if (sym != null) {
								redefinedError(sym, n, "token");
							} else {
								tokendef_stack.peek().tokenSymbol = sc.defineToken(find(n), n.getText(), i.intValue());
							}
						}
					
			pushFollow(FOLLOW_fielddefs_in_tokendef258);
			fielddefs();
			state._fsp--;

			match(input, Token.UP, null); 

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
			tokendef_stack.pop();
		}
	}
	// $ANTLR end "tokendef"



	// $ANTLR start "fielddefs"
	// ghidra/sleigh/grammar/SleighCompiler.g:191:1: fielddefs : ^( OP_FIELDDEFS ( fielddef )* ) ;
	public final void fielddefs() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:192:2: ( ^( OP_FIELDDEFS ( fielddef )* ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:192:4: ^( OP_FIELDDEFS ( fielddef )* )
			{
			match(input,OP_FIELDDEFS,FOLLOW_OP_FIELDDEFS_in_fielddefs271); 
			if ( input.LA(1)==Token.DOWN ) {
				match(input, Token.DOWN, null); 
				// ghidra/sleigh/grammar/SleighCompiler.g:192:19: ( fielddef )*
				loop4:
				while (true) {
					int alt4=2;
					int LA4_0 = input.LA(1);
					if ( (LA4_0==OP_FIELDDEF) ) {
						alt4=1;
					}

					switch (alt4) {
					case 1 :
						// ghidra/sleigh/grammar/SleighCompiler.g:192:19: fielddef
						{
						pushFollow(FOLLOW_fielddef_in_fielddefs273);
						fielddef();
						state._fsp--;

						}
						break;

					default :
						break loop4;
					}
				}

				match(input, Token.UP, null); 
			}

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "fielddefs"


	protected static class fielddef_scope {
		FieldQuality fieldQuality;
	}
	protected Stack<fielddef_scope> fielddef_stack = new Stack<fielddef_scope>();


	// $ANTLR start "fielddef"
	// ghidra/sleigh/grammar/SleighCompiler.g:195:1: fielddef : ^(t= OP_FIELDDEF n= unbound_identifier[\"field\"] s= integer e= integer fieldmods ) ;
	public final void fielddef() throws RecognitionException {
		fielddef_stack.push(new fielddef_scope());
		CommonTree t=null;
		Tree n =null;
		RadixBigInteger s =null;
		RadixBigInteger e =null;


				fielddef_stack.peek().fieldQuality = null;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:202:2: ( ^(t= OP_FIELDDEF n= unbound_identifier[\"field\"] s= integer e= integer fieldmods ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:202:4: ^(t= OP_FIELDDEF n= unbound_identifier[\"field\"] s= integer e= integer fieldmods )
			{
			t=(CommonTree)match(input,OP_FIELDDEF,FOLLOW_OP_FIELDDEF_in_fielddef299); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_unbound_identifier_in_fielddef303);
			n=unbound_identifier("field");
			state._fsp--;

			pushFollow(FOLLOW_integer_in_fielddef308);
			s=integer();
			state._fsp--;

			pushFollow(FOLLOW_integer_in_fielddef312);
			e=integer();
			state._fsp--;


						if (n != null) {
			                long start = s.longValue();
			                long finish = e.longValue();
			                if (finish < start) {
			                    reportError(find(t), "field " + n.getText() + " starts at " + start + " and ends at " + finish);
			                }
			                fielddef_stack.peek().fieldQuality = new FieldQuality(n.getText(), find(t), s.longValue(), e.longValue());
						}
					
			pushFollow(FOLLOW_fieldmods_in_fielddef316);
			fieldmods();
			state._fsp--;

			match(input, Token.UP, null); 


						if (fielddef_stack.size() > 0 && fielddef_stack.peek().fieldQuality != null) {
							if (tokendef_stack.size() > 0 && tokendef_stack.peek().tokenSymbol != null) {
								sc.addTokenField(find(n), tokendef_stack.peek().tokenSymbol, fielddef_stack.peek().fieldQuality);
							} else if (contextdef_stack.size() > 0 && contextdef_stack.peek().varnode != null) {
								if (!sc.addContextField(contextdef_stack.peek().varnode, fielddef_stack.peek().fieldQuality)) {
									reportError(find(t), "all context definitions must come before constructors");
								}
							}
						}
					
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
			fielddef_stack.pop();
		}
	}
	// $ANTLR end "fielddef"



	// $ANTLR start "fieldmods"
	// ghidra/sleigh/grammar/SleighCompiler.g:224:1: fieldmods : ( ^( OP_FIELD_MODS ( fieldmod )+ ) | OP_NO_FIELD_MOD );
	public final void fieldmods() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:225:2: ( ^( OP_FIELD_MODS ( fieldmod )+ ) | OP_NO_FIELD_MOD )
			int alt6=2;
			int LA6_0 = input.LA(1);
			if ( (LA6_0==OP_FIELD_MODS) ) {
				alt6=1;
			}
			else if ( (LA6_0==OP_NO_FIELD_MOD) ) {
				alt6=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 6, 0, input);
				throw nvae;
			}

			switch (alt6) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:225:4: ^( OP_FIELD_MODS ( fieldmod )+ )
					{
					match(input,OP_FIELD_MODS,FOLLOW_OP_FIELD_MODS_in_fieldmods331); 
					match(input, Token.DOWN, null); 
					// ghidra/sleigh/grammar/SleighCompiler.g:225:20: ( fieldmod )+
					int cnt5=0;
					loop5:
					while (true) {
						int alt5=2;
						int LA5_0 = input.LA(1);
						if ( (LA5_0==OP_DEC||LA5_0==OP_HEX||LA5_0==OP_NOFLOW||LA5_0==OP_SIGNED) ) {
							alt5=1;
						}

						switch (alt5) {
						case 1 :
							// ghidra/sleigh/grammar/SleighCompiler.g:225:20: fieldmod
							{
							pushFollow(FOLLOW_fieldmod_in_fieldmods333);
							fieldmod();
							state._fsp--;

							}
							break;

						default :
							if ( cnt5 >= 1 ) break loop5;
							EarlyExitException eee = new EarlyExitException(5, input);
							throw eee;
						}
						cnt5++;
					}

					match(input, Token.UP, null); 

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:226:4: OP_NO_FIELD_MOD
					{
					match(input,OP_NO_FIELD_MOD,FOLLOW_OP_NO_FIELD_MOD_in_fieldmods340); 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "fieldmods"



	// $ANTLR start "fieldmod"
	// ghidra/sleigh/grammar/SleighCompiler.g:229:1: fieldmod : ( OP_SIGNED | OP_NOFLOW | OP_HEX | OP_DEC );
	public final void fieldmod() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:230:5: ( OP_SIGNED | OP_NOFLOW | OP_HEX | OP_DEC )
			int alt7=4;
			switch ( input.LA(1) ) {
			case OP_SIGNED:
				{
				alt7=1;
				}
				break;
			case OP_NOFLOW:
				{
				alt7=2;
				}
				break;
			case OP_HEX:
				{
				alt7=3;
				}
				break;
			case OP_DEC:
				{
				alt7=4;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 7, 0, input);
				throw nvae;
			}
			switch (alt7) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:230:9: OP_SIGNED
					{
					match(input,OP_SIGNED,FOLLOW_OP_SIGNED_in_fieldmod356); 
					 if (fielddef_stack.peek().fieldQuality != null) fielddef_stack.peek().fieldQuality.signext = true; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:231:9: OP_NOFLOW
					{
					match(input,OP_NOFLOW,FOLLOW_OP_NOFLOW_in_fieldmod368); 
					 if (fielddef_stack.peek().fieldQuality != null) fielddef_stack.peek().fieldQuality.flow = false; 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:232:9: OP_HEX
					{
					match(input,OP_HEX,FOLLOW_OP_HEX_in_fieldmod380); 
					 if (fielddef_stack.peek().fieldQuality != null) fielddef_stack.peek().fieldQuality.hex = true; 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:233:9: OP_DEC
					{
					match(input,OP_DEC,FOLLOW_OP_DEC_in_fieldmod392); 
					 if (fielddef_stack.peek().fieldQuality != null) fielddef_stack.peek().fieldQuality.hex = false; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "fieldmod"



	// $ANTLR start "specific_identifier"
	// ghidra/sleigh/grammar/SleighCompiler.g:236:1: specific_identifier[String purpose] returns [Tree value] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final Tree specific_identifier(String purpose) throws RecognitionException {
		Tree value = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:237:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt8=2;
			int LA8_0 = input.LA(1);
			if ( (LA8_0==OP_IDENTIFIER) ) {
				alt8=1;
			}
			else if ( (LA8_0==OP_WILDCARD) ) {
				alt8=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 8, 0, input);
				throw nvae;
			}

			switch (alt8) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:237:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_specific_identifier414); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					 value = s; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:238:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_specific_identifier428); 

								wildcardError(t, purpose);
								value = null;
							
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "specific_identifier"



	// $ANTLR start "unbound_identifier"
	// ghidra/sleigh/grammar/SleighCompiler.g:244:1: unbound_identifier[String purpose] returns [Tree value] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final Tree unbound_identifier(String purpose) throws RecognitionException {
		Tree value = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:245:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt9=2;
			int LA9_0 = input.LA(1);
			if ( (LA9_0==OP_IDENTIFIER) ) {
				alt9=1;
			}
			else if ( (LA9_0==OP_WILDCARD) ) {
				alt9=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 9, 0, input);
				throw nvae;
			}

			switch (alt9) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:245:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_unbound_identifier447); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


						        // use PcodeCompile for symbol table while parsing pcode
					        	SleighSymbol sym = pcode != null ? pcode.findSymbol(s.getText()) : sc.findSymbol(s.getText());
								if (sym != null) {
									redefinedError(sym, s, purpose);
									value = null;
								} else {
									value = s;
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:255:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_unbound_identifier461); 

								wildcardError(t, purpose);
								value = null;
							
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "unbound_identifier"



	// $ANTLR start "varnode_symbol"
	// ghidra/sleigh/grammar/SleighCompiler.g:261:1: varnode_symbol[String purpose, boolean noWildcards] returns [VarnodeSymbol symbol] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final VarnodeSymbol varnode_symbol(String purpose, boolean noWildcards) throws RecognitionException {
		VarnodeSymbol symbol = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:262:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt10=2;
			int LA10_0 = input.LA(1);
			if ( (LA10_0==OP_IDENTIFIER) ) {
				alt10=1;
			}
			else if ( (LA10_0==OP_WILDCARD) ) {
				alt10=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 10, 0, input);
				throw nvae;
			}

			switch (alt10) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:262:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_varnode_symbol480); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								SleighSymbol sym = sc.findSymbol(s.getText());
								if (sym == null) {
									unknownSymbolError(s.getText(), find(s), "varnode", purpose);
								} else if(sym.getType() != symbol_type.varnode_symbol) {
									wrongSymbolTypeError(sym, find(s), "varnode", purpose);
								} else {
									symbol = (VarnodeSymbol) sym;
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:272:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_varnode_symbol494); 

								if (noWildcards) {
									wildcardError(t, purpose);
								}
								symbol = null;
							
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return symbol;
	}
	// $ANTLR end "varnode_symbol"



	// $ANTLR start "value_symbol"
	// ghidra/sleigh/grammar/SleighCompiler.g:280:1: value_symbol[String purpose] returns [Pair<ValueSymbol,Location> symbol] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final Pair<ValueSymbol,Location> value_symbol(String purpose) throws RecognitionException {
		Pair<ValueSymbol,Location> symbol = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:281:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt11=2;
			int LA11_0 = input.LA(1);
			if ( (LA11_0==OP_IDENTIFIER) ) {
				alt11=1;
			}
			else if ( (LA11_0==OP_WILDCARD) ) {
				alt11=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 11, 0, input);
				throw nvae;
			}

			switch (alt11) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:281:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_value_symbol513); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								SleighSymbol sym = sc.findSymbol(s.getText());
								if (sym == null) {
									unknownSymbolError(s.getText(), find(s), "value or context", purpose);
								} else if(sym.getType() == symbol_type.value_symbol
										|| sym.getType() == symbol_type.context_symbol) {
									symbol = new Pair<ValueSymbol,Location>((ValueSymbol) sym, find(s));
								} else {
									wrongSymbolTypeError(sym, find(s), "value or context", purpose);
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:292:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_value_symbol527); 

								wildcardError(t, purpose);
								symbol = null;
							
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return symbol;
	}
	// $ANTLR end "value_symbol"



	// $ANTLR start "operand_symbol"
	// ghidra/sleigh/grammar/SleighCompiler.g:298:1: operand_symbol[String purpose] returns [OperandSymbol symbol] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final OperandSymbol operand_symbol(String purpose) throws RecognitionException {
		OperandSymbol symbol = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:299:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt12=2;
			int LA12_0 = input.LA(1);
			if ( (LA12_0==OP_IDENTIFIER) ) {
				alt12=1;
			}
			else if ( (LA12_0==OP_WILDCARD) ) {
				alt12=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 12, 0, input);
				throw nvae;
			}

			switch (alt12) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:299:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_operand_symbol546); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								SleighSymbol sym = pcode.findSymbol(s.getText());
								if (sym == null) {
									unknownSymbolError(s.getText(), find(s), "operand", purpose);
								} else if(sym.getType() != symbol_type.operand_symbol) {
									wrongSymbolTypeError(sym, find(s), "operand", purpose);
								} else {
									symbol = (OperandSymbol) sym;
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:309:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_operand_symbol560); 

								wildcardError(t, purpose);
								symbol = null;
							
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return symbol;
	}
	// $ANTLR end "operand_symbol"



	// $ANTLR start "space_symbol"
	// ghidra/sleigh/grammar/SleighCompiler.g:315:1: space_symbol[String purpose] returns [SpaceSymbol symbol] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final SpaceSymbol space_symbol(String purpose) throws RecognitionException {
		SpaceSymbol symbol = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:316:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt13=2;
			int LA13_0 = input.LA(1);
			if ( (LA13_0==OP_IDENTIFIER) ) {
				alt13=1;
			}
			else if ( (LA13_0==OP_WILDCARD) ) {
				alt13=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 13, 0, input);
				throw nvae;
			}

			switch (alt13) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:316:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_space_symbol579); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								// use PcodeCompile for symbol table while parsing pcode
					        	SleighSymbol sym = pcode != null ? pcode.findSymbol(s.getText()) : sc.findSymbol(s.getText());
								if (sym == null) {
									unknownSymbolError(s.getText(), find(s), "space", purpose);
								} else if(sym.getType() != symbol_type.space_symbol) {
									wrongSymbolTypeError(sym, find(s), "space", purpose);
								} else {
									symbol = (SpaceSymbol) sym;
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:327:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_space_symbol593); 

								wildcardError(t, purpose);
								symbol = null;
							
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return symbol;
	}
	// $ANTLR end "space_symbol"



	// $ANTLR start "specific_symbol"
	// ghidra/sleigh/grammar/SleighCompiler.g:333:1: specific_symbol[String purpose] returns [SpecificSymbol symbol] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final SpecificSymbol specific_symbol(String purpose) throws RecognitionException {
		SpecificSymbol symbol = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:334:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt14=2;
			int LA14_0 = input.LA(1);
			if ( (LA14_0==OP_IDENTIFIER) ) {
				alt14=1;
			}
			else if ( (LA14_0==OP_WILDCARD) ) {
				alt14=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 14, 0, input);
				throw nvae;
			}

			switch (alt14) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:334:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_specific_symbol612); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								SleighSymbol sym = pcode.findSymbol(s.getText());
								if (sym == null) {
									unknownSymbolError(s.getText(), find(s), "start, end, operand, epsilon, or varnode", purpose);
								} else if(sym.getType() != symbol_type.start_symbol
										&& sym.getType() != symbol_type.end_symbol
										&& sym.getType() != symbol_type.operand_symbol
										&& sym.getType() != symbol_type.epsilon_symbol
										&& sym.getType() != symbol_type.varnode_symbol) {
									undeclaredSymbolError(sym, find(s), purpose);
								} else {
									symbol = (SpecificSymbol) sym;
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:348:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_specific_symbol626); 

								wildcardError(t, purpose);
								symbol = null;
							
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return symbol;
	}
	// $ANTLR end "specific_symbol"



	// $ANTLR start "family_symbol"
	// ghidra/sleigh/grammar/SleighCompiler.g:354:1: family_symbol[String purpose] returns [FamilySymbol symbol] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final FamilySymbol family_symbol(String purpose) throws RecognitionException {
		FamilySymbol symbol = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:355:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt15=2;
			int LA15_0 = input.LA(1);
			if ( (LA15_0==OP_IDENTIFIER) ) {
				alt15=1;
			}
			else if ( (LA15_0==OP_WILDCARD) ) {
				alt15=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 15, 0, input);
				throw nvae;
			}

			switch (alt15) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:355:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_family_symbol645); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								SleighSymbol sym = sc.findSymbol(s.getText());
								if (sym == null) {
									unknownSymbolError(s.getText(), find(s), "family", purpose);
								} else if(sym.getType() != symbol_type.value_symbol
										&& sym.getType() != symbol_type.valuemap_symbol
										&& sym.getType() != symbol_type.context_symbol
										&& sym.getType() != symbol_type.name_symbol
										&& sym.getType() != symbol_type.varnodelist_symbol) {
									wrongSymbolTypeError(sym, find(s), "family", purpose);
								} else {
									symbol = (FamilySymbol) sym;
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:369:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_family_symbol659); 

								wildcardError(t, purpose);
								symbol = null;
							
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return symbol;
	}
	// $ANTLR end "family_symbol"


	protected static class contextdef_scope {
		VarnodeSymbol varnode;
	}
	protected Stack<contextdef_scope> contextdef_stack = new Stack<contextdef_scope>();


	// $ANTLR start "contextdef"
	// ghidra/sleigh/grammar/SleighCompiler.g:375:1: contextdef : ^( OP_CONTEXT s= varnode_symbol[\"context definition\", true] fielddefs ) ;
	public final void contextdef() throws RecognitionException {
		contextdef_stack.push(new contextdef_scope());
		VarnodeSymbol s =null;


				contextdef_stack.peek().varnode = null;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:382:2: ( ^( OP_CONTEXT s= varnode_symbol[\"context definition\", true] fielddefs ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:382:4: ^( OP_CONTEXT s= varnode_symbol[\"context definition\", true] fielddefs )
			{
			match(input,OP_CONTEXT,FOLLOW_OP_CONTEXT_in_contextdef684); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_varnode_symbol_in_contextdef688);
			s=varnode_symbol("context definition", true);
			state._fsp--;


						if (s != null) {
							contextdef_stack.peek().varnode = s;
						}
					
			pushFollow(FOLLOW_fielddefs_in_contextdef693);
			fielddefs();
			state._fsp--;

			match(input, Token.UP, null); 

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
			contextdef_stack.pop();
		}
	}
	// $ANTLR end "contextdef"


	protected static class spacedef_scope {
		SpaceQuality quality;
	}
	protected Stack<spacedef_scope> spacedef_stack = new Stack<spacedef_scope>();


	// $ANTLR start "spacedef"
	// ghidra/sleigh/grammar/SleighCompiler.g:389:1: spacedef : ^( OP_SPACE n= unbound_identifier[\"space\"] s= spacemods ) ;
	public final void spacedef() throws RecognitionException {
		spacedef_stack.push(new spacedef_scope());
		Tree n =null;


				spacedef_stack.peek().quality = null;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:396:2: ( ^( OP_SPACE n= unbound_identifier[\"space\"] s= spacemods ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:396:4: ^( OP_SPACE n= unbound_identifier[\"space\"] s= spacemods )
			{
			match(input,OP_SPACE,FOLLOW_OP_SPACE_in_spacedef717); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_unbound_identifier_in_spacedef721);
			n=unbound_identifier("space");
			state._fsp--;


						String name = "<parse error>";
						if (n != null) {
							name = n.getText();
						}
						spacedef_stack.peek().quality = new SpaceQuality(name);
					
			pushFollow(FOLLOW_spacemods_in_spacedef728);
			spacemods();
			state._fsp--;

			match(input, Token.UP, null); 


						if (n != null) {
							sc.newSpace(find(n), spacedef_stack.peek().quality);
						}
					
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
			spacedef_stack.pop();
		}
	}
	// $ANTLR end "spacedef"



	// $ANTLR start "spacemods"
	// ghidra/sleigh/grammar/SleighCompiler.g:409:1: spacemods : ^( OP_SPACEMODS ( spacemod )* ) ;
	public final void spacemods() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:410:2: ( ^( OP_SPACEMODS ( spacemod )* ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:410:4: ^( OP_SPACEMODS ( spacemod )* )
			{
			match(input,OP_SPACEMODS,FOLLOW_OP_SPACEMODS_in_spacemods743); 
			if ( input.LA(1)==Token.DOWN ) {
				match(input, Token.DOWN, null); 
				// ghidra/sleigh/grammar/SleighCompiler.g:410:19: ( spacemod )*
				loop16:
				while (true) {
					int alt16=2;
					int LA16_0 = input.LA(1);
					if ( (LA16_0==OP_DEFAULT||LA16_0==OP_SIZE||LA16_0==OP_TYPE||LA16_0==OP_WORDSIZE) ) {
						alt16=1;
					}

					switch (alt16) {
					case 1 :
						// ghidra/sleigh/grammar/SleighCompiler.g:410:19: spacemod
						{
						pushFollow(FOLLOW_spacemod_in_spacemods745);
						spacemod();
						state._fsp--;

						}
						break;

					default :
						break loop16;
					}
				}

				match(input, Token.UP, null); 
			}

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "spacemods"



	// $ANTLR start "spacemod"
	// ghidra/sleigh/grammar/SleighCompiler.g:413:1: spacemod : ( typemod | sizemod | wordsizemod | OP_DEFAULT );
	public final void spacemod() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:414:2: ( typemod | sizemod | wordsizemod | OP_DEFAULT )
			int alt17=4;
			switch ( input.LA(1) ) {
			case OP_TYPE:
				{
				alt17=1;
				}
				break;
			case OP_SIZE:
				{
				alt17=2;
				}
				break;
			case OP_WORDSIZE:
				{
				alt17=3;
				}
				break;
			case OP_DEFAULT:
				{
				alt17=4;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 17, 0, input);
				throw nvae;
			}
			switch (alt17) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:414:4: typemod
					{
					pushFollow(FOLLOW_typemod_in_spacemod758);
					typemod();
					state._fsp--;

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:415:4: sizemod
					{
					pushFollow(FOLLOW_sizemod_in_spacemod763);
					sizemod();
					state._fsp--;

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:416:4: wordsizemod
					{
					pushFollow(FOLLOW_wordsizemod_in_spacemod768);
					wordsizemod();
					state._fsp--;

					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:417:4: OP_DEFAULT
					{
					match(input,OP_DEFAULT,FOLLOW_OP_DEFAULT_in_spacemod773); 
					 spacedef_stack.peek().quality.isdefault = true; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "spacemod"



	// $ANTLR start "typemod"
	// ghidra/sleigh/grammar/SleighCompiler.g:420:1: typemod : ^( OP_TYPE n= specific_identifier[\"space type qualifier\"] ) ;
	public final void typemod() throws RecognitionException {
		Tree n =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:421:2: ( ^( OP_TYPE n= specific_identifier[\"space type qualifier\"] ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:421:4: ^( OP_TYPE n= specific_identifier[\"space type qualifier\"] )
			{
			match(input,OP_TYPE,FOLLOW_OP_TYPE_in_typemod787); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_specific_identifier_in_typemod791);
			n=specific_identifier("space type qualifier");
			state._fsp--;

			match(input, Token.UP, null); 


						if (n != null) {
							String typeName = n.getText();
							try {
								space_class type = space_class.valueOf(typeName);
								spacedef_stack.peek().quality.type = type;
							} catch(IllegalArgumentException e) {
								reportError(find(n), "invalid space type " + typeName);
							}
						}
					
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "typemod"



	// $ANTLR start "sizemod"
	// ghidra/sleigh/grammar/SleighCompiler.g:434:1: sizemod : ^( OP_SIZE i= integer ) ;
	public final void sizemod() throws RecognitionException {
		RadixBigInteger i =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:435:2: ( ^( OP_SIZE i= integer ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:435:4: ^( OP_SIZE i= integer )
			{
			match(input,OP_SIZE,FOLLOW_OP_SIZE_in_sizemod807); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_integer_in_sizemod811);
			i=integer();
			state._fsp--;

			match(input, Token.UP, null); 


						spacedef_stack.peek().quality.size = i.intValue();
					
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "sizemod"



	// $ANTLR start "wordsizemod"
	// ghidra/sleigh/grammar/SleighCompiler.g:440:1: wordsizemod : ^( OP_WORDSIZE i= integer ) ;
	public final void wordsizemod() throws RecognitionException {
		RadixBigInteger i =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:441:2: ( ^( OP_WORDSIZE i= integer ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:441:4: ^( OP_WORDSIZE i= integer )
			{
			match(input,OP_WORDSIZE,FOLLOW_OP_WORDSIZE_in_wordsizemod826); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_integer_in_wordsizemod830);
			i=integer();
			state._fsp--;

			match(input, Token.UP, null); 


						spacedef_stack.peek().quality.wordsize = i.intValue();
					
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "wordsizemod"



	// $ANTLR start "varnodedef"
	// ghidra/sleigh/grammar/SleighCompiler.g:446:1: varnodedef : ^( OP_VARNODE s= space_symbol[\"varnode definition\"] offset= integer size= integer l= identifierlist ) ;
	public final void varnodedef() throws RecognitionException {
		SpaceSymbol s =null;
		RadixBigInteger offset =null;
		RadixBigInteger size =null;
		Pair<VectorSTL<String>,VectorSTL<Location>> l =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:447:2: ( ^( OP_VARNODE s= space_symbol[\"varnode definition\"] offset= integer size= integer l= identifierlist ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:447:4: ^( OP_VARNODE s= space_symbol[\"varnode definition\"] offset= integer size= integer l= identifierlist )
			{
			match(input,OP_VARNODE,FOLLOW_OP_VARNODE_in_varnodedef845); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_space_symbol_in_varnodedef849);
			s=space_symbol("varnode definition");
			state._fsp--;

			pushFollow(FOLLOW_integer_in_varnodedef854);
			offset=integer();
			state._fsp--;

			pushFollow(FOLLOW_integer_in_varnodedef858);
			size=integer();
			state._fsp--;

			pushFollow(FOLLOW_identifierlist_in_varnodedef862);
			l=identifierlist();
			state._fsp--;

			match(input, Token.UP, null); 


						sc.defineVarnodes(s, offset.longValue(), size.longValue(), l.first, l.second);
					
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "varnodedef"



	// $ANTLR start "identifierlist"
	// ghidra/sleigh/grammar/SleighCompiler.g:452:1: identifierlist returns [Pair<VectorSTL<String>,VectorSTL<Location>> value] : ^( OP_IDENTIFIER_LIST ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )+ ) ;
	public final Pair<VectorSTL<String>,VectorSTL<Location>> identifierlist() throws RecognitionException {
		Pair<VectorSTL<String>,VectorSTL<Location>> value = null;


		CommonTree t=null;
		CommonTree s=null;


				VectorSTL<String> names = new VectorSTL<String>();
				VectorSTL<Location> locations = new VectorSTL<Location>();
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:460:2: ( ^( OP_IDENTIFIER_LIST ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )+ ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:460:4: ^( OP_IDENTIFIER_LIST ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )+ )
			{
			match(input,OP_IDENTIFIER_LIST,FOLLOW_OP_IDENTIFIER_LIST_in_identifierlist893); 
			match(input, Token.DOWN, null); 
			// ghidra/sleigh/grammar/SleighCompiler.g:460:25: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )+
			int cnt18=0;
			loop18:
			while (true) {
				int alt18=3;
				int LA18_0 = input.LA(1);
				if ( (LA18_0==OP_IDENTIFIER) ) {
					alt18=1;
				}
				else if ( (LA18_0==OP_WILDCARD) ) {
					alt18=2;
				}

				switch (alt18) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:461:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_identifierlist901); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					 names.push_back(s.getText()); locations.push_back(find(s)); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:462:6: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_identifierlist917); 
					 names.push_back(t.getText()); locations.push_back(find(t)); 
					}
					break;

				default :
					if ( cnt18 >= 1 ) break loop18;
					EarlyExitException eee = new EarlyExitException(18, input);
					throw eee;
				}
				cnt18++;
			}

			match(input, Token.UP, null); 

			}


					value = new Pair<VectorSTL<String>,VectorSTL<Location>>(names, locations);
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "identifierlist"



	// $ANTLR start "stringoridentlist"
	// ghidra/sleigh/grammar/SleighCompiler.g:465:1: stringoridentlist returns [VectorSTL<String> value] : ^( OP_STRING_OR_IDENT_LIST (n= stringorident )* ) ;
	public final VectorSTL<String> stringoridentlist() throws RecognitionException {
		VectorSTL<String> value = null;


		String n =null;


				value = new VectorSTL<String>();
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:469:2: ( ^( OP_STRING_OR_IDENT_LIST (n= stringorident )* ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:469:4: ^( OP_STRING_OR_IDENT_LIST (n= stringorident )* )
			{
			match(input,OP_STRING_OR_IDENT_LIST,FOLLOW_OP_STRING_OR_IDENT_LIST_in_stringoridentlist945); 
			if ( input.LA(1)==Token.DOWN ) {
				match(input, Token.DOWN, null); 
				// ghidra/sleigh/grammar/SleighCompiler.g:469:30: (n= stringorident )*
				loop19:
				while (true) {
					int alt19=2;
					int LA19_0 = input.LA(1);
					if ( (LA19_0==OP_IDENTIFIER||LA19_0==OP_QSTRING||LA19_0==OP_WILDCARD) ) {
						alt19=1;
					}

					switch (alt19) {
					case 1 :
						// ghidra/sleigh/grammar/SleighCompiler.g:469:31: n= stringorident
						{
						pushFollow(FOLLOW_stringorident_in_stringoridentlist950);
						n=stringorident();
						state._fsp--;

						 value.push_back(n); 
						}
						break;

					default :
						break loop19;
					}
				}

				match(input, Token.UP, null); 
			}

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "stringoridentlist"



	// $ANTLR start "stringorident"
	// ghidra/sleigh/grammar/SleighCompiler.g:472:1: stringorident returns [String value] : (n= identifier |s= qstring );
	public final String stringorident() throws RecognitionException {
		String value = null;


		TreeRuleReturnScope n =null;
		String s =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:473:2: (n= identifier |s= qstring )
			int alt20=2;
			int LA20_0 = input.LA(1);
			if ( (LA20_0==OP_IDENTIFIER||LA20_0==OP_WILDCARD) ) {
				alt20=1;
			}
			else if ( (LA20_0==OP_QSTRING) ) {
				alt20=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 20, 0, input);
				throw nvae;
			}

			switch (alt20) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:473:4: n= identifier
					{
					pushFollow(FOLLOW_identifier_in_stringorident973);
					n=identifier();
					state._fsp--;

					 value = (n!=null?((SleighCompiler.identifier_return)n).value:null); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:474:4: s= qstring
					{
					pushFollow(FOLLOW_qstring_in_stringorident982);
					s=qstring();
					state._fsp--;

					 value = s; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "stringorident"



	// $ANTLR start "bitrangedef"
	// ghidra/sleigh/grammar/SleighCompiler.g:477:1: bitrangedef : ^( OP_BITRANGES ( sbitrange )+ ) ;
	public final void bitrangedef() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:478:2: ( ^( OP_BITRANGES ( sbitrange )+ ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:478:4: ^( OP_BITRANGES ( sbitrange )+ )
			{
			match(input,OP_BITRANGES,FOLLOW_OP_BITRANGES_in_bitrangedef996); 
			match(input, Token.DOWN, null); 
			// ghidra/sleigh/grammar/SleighCompiler.g:478:19: ( sbitrange )+
			int cnt21=0;
			loop21:
			while (true) {
				int alt21=2;
				int LA21_0 = input.LA(1);
				if ( (LA21_0==OP_BITRANGE) ) {
					alt21=1;
				}

				switch (alt21) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:478:19: sbitrange
					{
					pushFollow(FOLLOW_sbitrange_in_bitrangedef998);
					sbitrange();
					state._fsp--;

					}
					break;

				default :
					if ( cnt21 >= 1 ) break loop21;
					EarlyExitException eee = new EarlyExitException(21, input);
					throw eee;
				}
				cnt21++;
			}

			match(input, Token.UP, null); 

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "bitrangedef"



	// $ANTLR start "sbitrange"
	// ghidra/sleigh/grammar/SleighCompiler.g:481:1: sbitrange : ^( OP_BITRANGE ^( OP_IDENTIFIER s= . ) b= varnode_symbol[\"bitrange definition\", true] i= integer j= integer ) ;
	public final void sbitrange() throws RecognitionException {
		CommonTree s=null;
		VarnodeSymbol b =null;
		RadixBigInteger i =null;
		RadixBigInteger j =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:482:2: ( ^( OP_BITRANGE ^( OP_IDENTIFIER s= . ) b= varnode_symbol[\"bitrange definition\", true] i= integer j= integer ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:482:4: ^( OP_BITRANGE ^( OP_IDENTIFIER s= . ) b= varnode_symbol[\"bitrange definition\", true] i= integer j= integer )
			{
			match(input,OP_BITRANGE,FOLLOW_OP_BITRANGE_in_sbitrange1012); 
			match(input, Token.DOWN, null); 
			match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_sbitrange1015); 
			match(input, Token.DOWN, null); 
			s=(CommonTree)input.LT(1);
			matchAny(input); 
			match(input, Token.UP, null); 

			pushFollow(FOLLOW_varnode_symbol_in_sbitrange1024);
			b=varnode_symbol("bitrange definition", true);
			state._fsp--;

			pushFollow(FOLLOW_integer_in_sbitrange1029);
			i=integer();
			state._fsp--;

			pushFollow(FOLLOW_integer_in_sbitrange1033);
			j=integer();
			state._fsp--;

			match(input, Token.UP, null); 


						sc.defineBitrange(find(s), s.getText(), b, i.intValue(), j.intValue());
					
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "sbitrange"



	// $ANTLR start "pcodeopdef"
	// ghidra/sleigh/grammar/SleighCompiler.g:487:1: pcodeopdef : ^( OP_PCODEOP l= identifierlist ) ;
	public final void pcodeopdef() throws RecognitionException {
		Pair<VectorSTL<String>,VectorSTL<Location>> l =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:488:2: ( ^( OP_PCODEOP l= identifierlist ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:488:4: ^( OP_PCODEOP l= identifierlist )
			{
			match(input,OP_PCODEOP,FOLLOW_OP_PCODEOP_in_pcodeopdef1048); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_identifierlist_in_pcodeopdef1052);
			l=identifierlist();
			state._fsp--;

			match(input, Token.UP, null); 

			 sc.addUserOp(l.first, l.second); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "pcodeopdef"



	// $ANTLR start "valueattach"
	// ghidra/sleigh/grammar/SleighCompiler.g:491:1: valueattach : ^( OP_VALUES a= valuelist[\"attach values\"] b= intblist ) ;
	public final void valueattach() throws RecognitionException {
		Pair<VectorSTL<SleighSymbol>,VectorSTL<Location>> a =null;
		VectorSTL<Long> b =null;


				sc.calcContextLayout();
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:495:2: ( ^( OP_VALUES a= valuelist[\"attach values\"] b= intblist ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:495:4: ^( OP_VALUES a= valuelist[\"attach values\"] b= intblist )
			{
			match(input,OP_VALUES,FOLLOW_OP_VALUES_in_valueattach1073); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_valuelist_in_valueattach1077);
			a=valuelist("attach values");
			state._fsp--;

			pushFollow(FOLLOW_intblist_in_valueattach1082);
			b=intblist();
			state._fsp--;

			match(input, Token.UP, null); 

			 sc.attachValues(a.first, a.second, b); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "valueattach"



	// $ANTLR start "intblist"
	// ghidra/sleigh/grammar/SleighCompiler.g:498:1: intblist returns [VectorSTL<Long> value] : ^( OP_INTBLIST (n= intbpart )* ) ;
	public final VectorSTL<Long> intblist() throws RecognitionException {
		VectorSTL<Long> value = null;


		BigInteger n =null;


				value = new VectorSTL<Long>();
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:502:2: ( ^( OP_INTBLIST (n= intbpart )* ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:502:4: ^( OP_INTBLIST (n= intbpart )* )
			{
			match(input,OP_INTBLIST,FOLLOW_OP_INTBLIST_in_intblist1107); 
			if ( input.LA(1)==Token.DOWN ) {
				match(input, Token.DOWN, null); 
				// ghidra/sleigh/grammar/SleighCompiler.g:502:18: (n= intbpart )*
				loop22:
				while (true) {
					int alt22=2;
					int LA22_0 = input.LA(1);
					if ( (LA22_0==OP_BIN_CONSTANT||LA22_0==OP_DEC_CONSTANT||LA22_0==OP_HEX_CONSTANT||LA22_0==OP_NEGATE||LA22_0==OP_WILDCARD) ) {
						alt22=1;
					}

					switch (alt22) {
					case 1 :
						// ghidra/sleigh/grammar/SleighCompiler.g:502:19: n= intbpart
						{
						pushFollow(FOLLOW_intbpart_in_intblist1112);
						n=intbpart();
						state._fsp--;

						 value.push_back(n.longValue()); 
						}
						break;

					default :
						break loop22;
					}
				}

				match(input, Token.UP, null); 
			}

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "intblist"



	// $ANTLR start "intbpart"
	// ghidra/sleigh/grammar/SleighCompiler.g:505:1: intbpart returns [BigInteger value] : (t= OP_WILDCARD | ^( OP_NEGATE i= integer ) |i= integer );
	public final BigInteger intbpart() throws RecognitionException {
		BigInteger value = null;


		CommonTree t=null;
		RadixBigInteger i =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:506:2: (t= OP_WILDCARD | ^( OP_NEGATE i= integer ) |i= integer )
			int alt23=3;
			switch ( input.LA(1) ) {
			case OP_WILDCARD:
				{
				alt23=1;
				}
				break;
			case OP_NEGATE:
				{
				alt23=2;
				}
				break;
			case OP_BIN_CONSTANT:
			case OP_DEC_CONSTANT:
			case OP_HEX_CONSTANT:
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
					// ghidra/sleigh/grammar/SleighCompiler.g:506:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_intbpart1135); 
					 value = new RadixBigInteger(find(t), "BADBEEF", 16); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:507:4: ^( OP_NEGATE i= integer )
					{
					match(input,OP_NEGATE,FOLLOW_OP_NEGATE_in_intbpart1143); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_integer_in_intbpart1147);
					i=integer();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = i.negate(); 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:508:4: i= integer
					{
					pushFollow(FOLLOW_integer_in_intbpart1157);
					i=integer();
					state._fsp--;

					 value = i; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "intbpart"



	// $ANTLR start "nameattach"
	// ghidra/sleigh/grammar/SleighCompiler.g:511:1: nameattach : ^( OP_NAMES a= valuelist[\"attach variables\"] b= stringoridentlist ) ;
	public final void nameattach() throws RecognitionException {
		Pair<VectorSTL<SleighSymbol>,VectorSTL<Location>> a =null;
		VectorSTL<String> b =null;


				sc.calcContextLayout();
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:515:2: ( ^( OP_NAMES a= valuelist[\"attach variables\"] b= stringoridentlist ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:515:4: ^( OP_NAMES a= valuelist[\"attach variables\"] b= stringoridentlist )
			{
			match(input,OP_NAMES,FOLLOW_OP_NAMES_in_nameattach1177); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_valuelist_in_nameattach1181);
			a=valuelist("attach variables");
			state._fsp--;

			pushFollow(FOLLOW_stringoridentlist_in_nameattach1186);
			b=stringoridentlist();
			state._fsp--;

			match(input, Token.UP, null); 

			 sc.attachNames(a.first, a.second, b); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "nameattach"



	// $ANTLR start "varattach"
	// ghidra/sleigh/grammar/SleighCompiler.g:518:1: varattach : ^( OP_VARIABLES a= valuelist[\"attach variables\"] b= varlist[\"attach variables\"] ) ;
	public final void varattach() throws RecognitionException {
		Pair<VectorSTL<SleighSymbol>,VectorSTL<Location>> a =null;
		VectorSTL<SleighSymbol> b =null;


				sc.calcContextLayout();
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:522:2: ( ^( OP_VARIABLES a= valuelist[\"attach variables\"] b= varlist[\"attach variables\"] ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:522:4: ^( OP_VARIABLES a= valuelist[\"attach variables\"] b= varlist[\"attach variables\"] )
			{
			match(input,OP_VARIABLES,FOLLOW_OP_VARIABLES_in_varattach1207); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_valuelist_in_varattach1211);
			a=valuelist("attach variables");
			state._fsp--;

			pushFollow(FOLLOW_varlist_in_varattach1216);
			b=varlist("attach variables");
			state._fsp--;

			match(input, Token.UP, null); 


						sc.attachVarnodes(a.first, a.second, b);
					
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "varattach"



	// $ANTLR start "valuelist"
	// ghidra/sleigh/grammar/SleighCompiler.g:527:1: valuelist[String purpose] returns [Pair<VectorSTL<SleighSymbol>,VectorSTL<Location>> value] : ^( OP_IDENTIFIER_LIST (n= value_symbol[purpose] )+ ) ;
	public final Pair<VectorSTL<SleighSymbol>,VectorSTL<Location>> valuelist(String purpose) throws RecognitionException {
		Pair<VectorSTL<SleighSymbol>,VectorSTL<Location>> value = null;


		Pair<ValueSymbol,Location> n =null;


				VectorSTL<SleighSymbol> symbols = new VectorSTL<SleighSymbol>();
				VectorSTL<Location> locations = new VectorSTL<Location>();
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:535:2: ( ^( OP_IDENTIFIER_LIST (n= value_symbol[purpose] )+ ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:535:4: ^( OP_IDENTIFIER_LIST (n= value_symbol[purpose] )+ )
			{
			match(input,OP_IDENTIFIER_LIST,FOLLOW_OP_IDENTIFIER_LIST_in_valuelist1249); 
			match(input, Token.DOWN, null); 
			// ghidra/sleigh/grammar/SleighCompiler.g:535:25: (n= value_symbol[purpose] )+
			int cnt24=0;
			loop24:
			while (true) {
				int alt24=2;
				int LA24_0 = input.LA(1);
				if ( (LA24_0==OP_IDENTIFIER||LA24_0==OP_WILDCARD) ) {
					alt24=1;
				}

				switch (alt24) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:535:26: n= value_symbol[purpose]
					{
					pushFollow(FOLLOW_value_symbol_in_valuelist1254);
					n=value_symbol(purpose);
					state._fsp--;


								symbols.push_back(n.first);
								locations.push_back(n.second);
							
					}
					break;

				default :
					if ( cnt24 >= 1 ) break loop24;
					EarlyExitException eee = new EarlyExitException(24, input);
					throw eee;
				}
				cnt24++;
			}

			match(input, Token.UP, null); 

			}


					value = new Pair<VectorSTL<SleighSymbol>,VectorSTL<Location>>(symbols, locations);
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "valuelist"



	// $ANTLR start "varlist"
	// ghidra/sleigh/grammar/SleighCompiler.g:542:1: varlist[String purpose] returns [VectorSTL<SleighSymbol> value] : ^( OP_IDENTIFIER_LIST (n= varnode_symbol[purpose, false] )+ ) ;
	public final VectorSTL<SleighSymbol> varlist(String purpose) throws RecognitionException {
		VectorSTL<SleighSymbol> value = null;


		VarnodeSymbol n =null;


				value = new VectorSTL<SleighSymbol>();
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:546:2: ( ^( OP_IDENTIFIER_LIST (n= varnode_symbol[purpose, false] )+ ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:546:4: ^( OP_IDENTIFIER_LIST (n= varnode_symbol[purpose, false] )+ )
			{
			match(input,OP_IDENTIFIER_LIST,FOLLOW_OP_IDENTIFIER_LIST_in_varlist1285); 
			match(input, Token.DOWN, null); 
			// ghidra/sleigh/grammar/SleighCompiler.g:546:25: (n= varnode_symbol[purpose, false] )+
			int cnt25=0;
			loop25:
			while (true) {
				int alt25=2;
				int LA25_0 = input.LA(1);
				if ( (LA25_0==OP_IDENTIFIER||LA25_0==OP_WILDCARD) ) {
					alt25=1;
				}

				switch (alt25) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:546:26: n= varnode_symbol[purpose, false]
					{
					pushFollow(FOLLOW_varnode_symbol_in_varlist1290);
					n=varnode_symbol(purpose, false);
					state._fsp--;


								value.push_back(n);
							
					}
					break;

				default :
					if ( cnt25 >= 1 ) break loop25;
					EarlyExitException eee = new EarlyExitException(25, input);
					throw eee;
				}
				cnt25++;
			}

			match(input, Token.UP, null); 

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "varlist"



	// $ANTLR start "constructorlike"
	// ghidra/sleigh/grammar/SleighCompiler.g:551:1: constructorlike : ( macrodef | withblock | constructor );
	public final void constructorlike() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:552:2: ( macrodef | withblock | constructor )
			int alt26=3;
			switch ( input.LA(1) ) {
			case OP_MACRO:
				{
				alt26=1;
				}
				break;
			case OP_WITH:
				{
				alt26=2;
				}
				break;
			case OP_CONSTRUCTOR:
				{
				alt26=3;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 26, 0, input);
				throw nvae;
			}
			switch (alt26) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:552:4: macrodef
					{
					pushFollow(FOLLOW_macrodef_in_constructorlike1308);
					macrodef();
					state._fsp--;

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:553:4: withblock
					{
					 sc.calcContextLayout(); 
					pushFollow(FOLLOW_withblock_in_constructorlike1315);
					withblock();
					state._fsp--;

					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:554:4: constructor
					{
					 sc.calcContextLayout(); 
					pushFollow(FOLLOW_constructor_in_constructorlike1322);
					constructor();
					state._fsp--;

					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "constructorlike"


	protected static class macrodef_scope {
		ConstructTpl macrobody;
	}
	protected Stack<macrodef_scope> macrodef_stack = new Stack<macrodef_scope>();


	// $ANTLR start "macrodef"
	// ghidra/sleigh/grammar/SleighCompiler.g:557:1: macrodef : ^(t= OP_MACRO n= unbound_identifier[\"macro\"] a= arguments s= semantic[env, sc.pcode, $t, false, true] ) ;
	public final void macrodef() throws RecognitionException {
		macrodef_stack.push(new macrodef_scope());
		CommonTree t=null;
		Tree n =null;
		Pair<VectorSTL<String>,VectorSTL<Location>> a =null;
		SectionVector s =null;


				MacroSymbol symbol = null;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:564:2: ( ^(t= OP_MACRO n= unbound_identifier[\"macro\"] a= arguments s= semantic[env, sc.pcode, $t, false, true] ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:564:4: ^(t= OP_MACRO n= unbound_identifier[\"macro\"] a= arguments s= semantic[env, sc.pcode, $t, false, true] )
			{
			t=(CommonTree)match(input,OP_MACRO,FOLLOW_OP_MACRO_in_macrodef1347); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_unbound_identifier_in_macrodef1351);
			n=unbound_identifier("macro");
			state._fsp--;

			pushFollow(FOLLOW_arguments_in_macrodef1356);
			a=arguments();
			state._fsp--;


						symbol = sc.createMacro(find(n), n.getText(), a.first, a.second);
					
			pushFollow(FOLLOW_semantic_in_macrodef1362);
			s=semantic(env, sc.pcode, t, false, true);
			state._fsp--;

			match(input, Token.UP, null); 


						if (symbol != null) {
							sc.buildMacro(symbol, macrodef_stack.peek().macrobody);
						}
					
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
			macrodef_stack.pop();
		}
	}
	// $ANTLR end "macrodef"



	// $ANTLR start "arguments"
	// ghidra/sleigh/grammar/SleighCompiler.g:573:1: arguments returns [Pair<VectorSTL<String>,VectorSTL<Location>> value] : ( ^( OP_ARGUMENTS ( ^( OP_IDENTIFIER s= . ) )+ ) | OP_EMPTY_LIST );
	public final Pair<VectorSTL<String>,VectorSTL<Location>> arguments() throws RecognitionException {
		Pair<VectorSTL<String>,VectorSTL<Location>> value = null;


		CommonTree s=null;


				VectorSTL<String> names = new VectorSTL<String>();
				VectorSTL<Location> locations = new VectorSTL<Location>();
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:581:2: ( ^( OP_ARGUMENTS ( ^( OP_IDENTIFIER s= . ) )+ ) | OP_EMPTY_LIST )
			int alt28=2;
			int LA28_0 = input.LA(1);
			if ( (LA28_0==OP_ARGUMENTS) ) {
				alt28=1;
			}
			else if ( (LA28_0==OP_EMPTY_LIST) ) {
				alt28=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 28, 0, input);
				throw nvae;
			}

			switch (alt28) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:581:4: ^( OP_ARGUMENTS ( ^( OP_IDENTIFIER s= . ) )+ )
					{
					match(input,OP_ARGUMENTS,FOLLOW_OP_ARGUMENTS_in_arguments1394); 
					match(input, Token.DOWN, null); 
					// ghidra/sleigh/grammar/SleighCompiler.g:581:19: ( ^( OP_IDENTIFIER s= . ) )+
					int cnt27=0;
					loop27:
					while (true) {
						int alt27=2;
						int LA27_0 = input.LA(1);
						if ( (LA27_0==OP_IDENTIFIER) ) {
							alt27=1;
						}

						switch (alt27) {
						case 1 :
							// ghidra/sleigh/grammar/SleighCompiler.g:581:20: ^( OP_IDENTIFIER s= . )
							{
							match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_arguments1398); 
							match(input, Token.DOWN, null); 
							s=(CommonTree)input.LT(1);
							matchAny(input); 
							match(input, Token.UP, null); 

							 names.push_back(s.getText()); locations.push_back(find(s)); 
							}
							break;

						default :
							if ( cnt27 >= 1 ) break loop27;
							EarlyExitException eee = new EarlyExitException(27, input);
							throw eee;
						}
						cnt27++;
					}

					match(input, Token.UP, null); 

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:582:4: OP_EMPTY_LIST
					{
					match(input,OP_EMPTY_LIST,FOLLOW_OP_EMPTY_LIST_in_arguments1413); 
					}
					break;

			}

					value = new Pair<VectorSTL<String>,VectorSTL<Location>>(names, locations);
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "arguments"



	// $ANTLR start "withblock"
	// ghidra/sleigh/grammar/SleighCompiler.g:585:1: withblock : ^( OP_WITH s= id_or_nil e= bitpat_or_nil b= contextblock constructorlikelist ) ;
	public final void withblock() throws RecognitionException {
		TreeRuleReturnScope s =null;
		PatternEquation e =null;
		VectorSTL<ContextChange> b =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:586:2: ( ^( OP_WITH s= id_or_nil e= bitpat_or_nil b= contextblock constructorlikelist ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:586:4: ^( OP_WITH s= id_or_nil e= bitpat_or_nil b= contextblock constructorlikelist )
			{
			match(input,OP_WITH,FOLLOW_OP_WITH_in_withblock1425); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_id_or_nil_in_withblock1429);
			s=id_or_nil();
			state._fsp--;

			pushFollow(FOLLOW_bitpat_or_nil_in_withblock1433);
			e=bitpat_or_nil();
			state._fsp--;

			pushFollow(FOLLOW_contextblock_in_withblock1437);
			b=contextblock();
			state._fsp--;


						SubtableSymbol ss = null;
						if ((s!=null?((SleighCompiler.id_or_nil_return)s).value:null) != null) {
							ss = findOrNewTable(find((s!=null?((SleighCompiler.id_or_nil_return)s).tree:null)), (s!=null?((SleighCompiler.id_or_nil_return)s).value:null));
							if (ss == null) bail("With block with invalid subtable identifier");
						}	
						sc.pushWith(ss, e, b);
					
			pushFollow(FOLLOW_constructorlikelist_in_withblock1443);
			constructorlikelist();
			state._fsp--;


						sc.popWith();
					
			match(input, Token.UP, null); 

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "withblock"


	public static class id_or_nil_return extends TreeRuleReturnScope {
		public String value;
		public Tree tree;
	};


	// $ANTLR start "id_or_nil"
	// ghidra/sleigh/grammar/SleighCompiler.g:600:1: id_or_nil returns [String value, Tree tree] : (v= identifier | OP_NIL );
	public final SleighCompiler.id_or_nil_return id_or_nil() throws RecognitionException {
		SleighCompiler.id_or_nil_return retval = new SleighCompiler.id_or_nil_return();
		retval.start = input.LT(1);

		TreeRuleReturnScope v =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:601:2: (v= identifier | OP_NIL )
			int alt29=2;
			int LA29_0 = input.LA(1);
			if ( (LA29_0==OP_IDENTIFIER||LA29_0==OP_WILDCARD) ) {
				alt29=1;
			}
			else if ( (LA29_0==OP_NIL) ) {
				alt29=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 29, 0, input);
				throw nvae;
			}

			switch (alt29) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:601:4: v= identifier
					{
					pushFollow(FOLLOW_identifier_in_id_or_nil1465);
					v=identifier();
					state._fsp--;

					 retval.value = (v!=null?((SleighCompiler.identifier_return)v).value:null); retval.tree = (v!=null?((SleighCompiler.identifier_return)v).tree:null); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:602:4: OP_NIL
					{
					match(input,OP_NIL,FOLLOW_OP_NIL_in_id_or_nil1472); 
					 retval.value = null; retval.tree = null; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "id_or_nil"



	// $ANTLR start "bitpat_or_nil"
	// ghidra/sleigh/grammar/SleighCompiler.g:605:1: bitpat_or_nil returns [PatternEquation value] : (v= bitpattern | OP_NIL );
	public final PatternEquation bitpat_or_nil() throws RecognitionException {
		PatternEquation value = null;


		PatternEquation v =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:606:2: (v= bitpattern | OP_NIL )
			int alt30=2;
			int LA30_0 = input.LA(1);
			if ( (LA30_0==OP_BIT_PATTERN) ) {
				alt30=1;
			}
			else if ( (LA30_0==OP_NIL) ) {
				alt30=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 30, 0, input);
				throw nvae;
			}

			switch (alt30) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:606:4: v= bitpattern
					{
					pushFollow(FOLLOW_bitpattern_in_bitpat_or_nil1491);
					v=bitpattern();
					state._fsp--;

					 value = v; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:607:4: OP_NIL
					{
					match(input,OP_NIL,FOLLOW_OP_NIL_in_bitpat_or_nil1498); 
					 value = null; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "bitpat_or_nil"



	// $ANTLR start "constructorlikelist"
	// ghidra/sleigh/grammar/SleighCompiler.g:610:1: constructorlikelist : ^( OP_CTLIST ( definition | constructorlike )* ) ;
	public final void constructorlikelist() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:611:2: ( ^( OP_CTLIST ( definition | constructorlike )* ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:611:4: ^( OP_CTLIST ( definition | constructorlike )* )
			{
			match(input,OP_CTLIST,FOLLOW_OP_CTLIST_in_constructorlikelist1512); 
			if ( input.LA(1)==Token.DOWN ) {
				match(input, Token.DOWN, null); 
				// ghidra/sleigh/grammar/SleighCompiler.g:611:16: ( definition | constructorlike )*
				loop31:
				while (true) {
					int alt31=3;
					int LA31_0 = input.LA(1);
					if ( (LA31_0==OP_ALIGNMENT||LA31_0==OP_BITRANGES||LA31_0==OP_CONTEXT||LA31_0==OP_NAMES||LA31_0==OP_PCODEOP||LA31_0==OP_SPACE||LA31_0==OP_TOKEN||(LA31_0 >= OP_VALUES && LA31_0 <= OP_VARNODE)) ) {
						alt31=1;
					}
					else if ( (LA31_0==OP_CONSTRUCTOR||LA31_0==OP_MACRO||LA31_0==OP_WITH) ) {
						alt31=2;
					}

					switch (alt31) {
					case 1 :
						// ghidra/sleigh/grammar/SleighCompiler.g:611:18: definition
						{
						pushFollow(FOLLOW_definition_in_constructorlikelist1516);
						definition();
						state._fsp--;

						}
						break;
					case 2 :
						// ghidra/sleigh/grammar/SleighCompiler.g:611:31: constructorlike
						{
						pushFollow(FOLLOW_constructorlike_in_constructorlikelist1520);
						constructorlike();
						state._fsp--;

						}
						break;

					default :
						break loop31;
					}
				}

				match(input, Token.UP, null); 
			}

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "constructorlikelist"



	// $ANTLR start "constructor"
	// ghidra/sleigh/grammar/SleighCompiler.g:614:1: constructor : ^( OP_CONSTRUCTOR c= ctorstart e= bitpattern b= contextblock r= ctorsemantic ) ;
	public final void constructor() throws RecognitionException {
		Constructor c =null;
		PatternEquation e =null;
		VectorSTL<ContextChange> b =null;
		SectionVector r =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:615:2: ( ^( OP_CONSTRUCTOR c= ctorstart e= bitpattern b= contextblock r= ctorsemantic ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:615:4: ^( OP_CONSTRUCTOR c= ctorstart e= bitpattern b= contextblock r= ctorsemantic )
			{
			match(input,OP_CONSTRUCTOR,FOLLOW_OP_CONSTRUCTOR_in_constructor1537); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_ctorstart_in_constructor1541);
			c=ctorstart();
			state._fsp--;

			pushFollow(FOLLOW_bitpattern_in_constructor1545);
			e=bitpattern();
			state._fsp--;

			pushFollow(FOLLOW_contextblock_in_constructor1549);
			b=contextblock();
			state._fsp--;

			pushFollow(FOLLOW_ctorsemantic_in_constructor1553);
			r=ctorsemantic();
			state._fsp--;

			match(input, Token.UP, null); 


						sc.buildConstructor(c, e, b, r);
					
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "constructor"



	// $ANTLR start "ctorsemantic"
	// ghidra/sleigh/grammar/SleighCompiler.g:620:1: ctorsemantic returns [SectionVector value] : ( ^(t= OP_PCODE p= semantic[env, sc.pcode, $t, true, false] ) | ^( OP_PCODE OP_UNIMPL ) );
	public final SectionVector ctorsemantic() throws RecognitionException {
		SectionVector value = null;


		CommonTree t=null;
		SectionVector p =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:621:2: ( ^(t= OP_PCODE p= semantic[env, sc.pcode, $t, true, false] ) | ^( OP_PCODE OP_UNIMPL ) )
			int alt32=2;
			int LA32_0 = input.LA(1);
			if ( (LA32_0==OP_PCODE) ) {
				int LA32_1 = input.LA(2);
				if ( (LA32_1==DOWN) ) {
					int LA32_2 = input.LA(3);
					if ( (LA32_2==OP_UNIMPL) ) {
						alt32=2;
					}
					else if ( (LA32_2==OP_SEMANTIC) ) {
						alt32=1;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 32, 2, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 32, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 32, 0, input);
				throw nvae;
			}

			switch (alt32) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:621:4: ^(t= OP_PCODE p= semantic[env, sc.pcode, $t, true, false] )
					{
					t=(CommonTree)match(input,OP_PCODE,FOLLOW_OP_PCODE_in_ctorsemantic1574); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_semantic_in_ctorsemantic1578);
					p=semantic(env, sc.pcode, t, true, false);
					state._fsp--;

					match(input, Token.UP, null); 

					       value = p; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:622:4: ^( OP_PCODE OP_UNIMPL )
					{
					match(input,OP_PCODE,FOLLOW_OP_PCODE_in_ctorsemantic1588); 
					match(input, Token.DOWN, null); 
					match(input,OP_UNIMPL,FOLLOW_OP_UNIMPL_in_ctorsemantic1590); 
					match(input, Token.UP, null); 

					 /*unimpl unimplemented ; */ value = null; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "ctorsemantic"



	// $ANTLR start "bitpattern"
	// ghidra/sleigh/grammar/SleighCompiler.g:625:1: bitpattern returns [PatternEquation value] : ^( OP_BIT_PATTERN p= pequation ) ;
	public final PatternEquation bitpattern() throws RecognitionException {
		PatternEquation value = null;


		PatternEquation p =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:626:2: ( ^( OP_BIT_PATTERN p= pequation ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:626:4: ^( OP_BIT_PATTERN p= pequation )
			{
			match(input,OP_BIT_PATTERN,FOLLOW_OP_BIT_PATTERN_in_bitpattern1609); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_pequation_in_bitpattern1613);
			p=pequation();
			state._fsp--;

			match(input, Token.UP, null); 

			 value = p; 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "bitpattern"


	protected static class ctorstart_scope {
		boolean table;
		boolean firstTime;
	}
	protected Stack<ctorstart_scope> ctorstart_stack = new Stack<ctorstart_scope>();


	// $ANTLR start "ctorstart"
	// ghidra/sleigh/grammar/SleighCompiler.g:629:1: ctorstart returns [Constructor value] : ( ^(t= OP_SUBTABLE ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD ) d= display[value] ) | ^(t= OP_TABLE d= display[value] ) );
	public final Constructor ctorstart() throws RecognitionException {
		ctorstart_stack.push(new ctorstart_scope());
		Constructor value = null;


		CommonTree t=null;
		CommonTree s=null;


				ctorstart_stack.peek().table = false;
				ctorstart_stack.peek().firstTime = true;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:638:2: ( ^(t= OP_SUBTABLE ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD ) d= display[value] ) | ^(t= OP_TABLE d= display[value] ) )
			int alt34=2;
			int LA34_0 = input.LA(1);
			if ( (LA34_0==OP_SUBTABLE) ) {
				alt34=1;
			}
			else if ( (LA34_0==OP_TABLE) ) {
				alt34=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 34, 0, input);
				throw nvae;
			}

			switch (alt34) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:638:4: ^(t= OP_SUBTABLE ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD ) d= display[value] )
					{
					t=(CommonTree)match(input,OP_SUBTABLE,FOLLOW_OP_SUBTABLE_in_ctorstart1645); 
					match(input, Token.DOWN, null); 
					// ghidra/sleigh/grammar/SleighCompiler.g:638:20: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
					int alt33=2;
					int LA33_0 = input.LA(1);
					if ( (LA33_0==OP_IDENTIFIER) ) {
						alt33=1;
					}
					else if ( (LA33_0==OP_WILDCARD) ) {
						alt33=2;
					}

					else {
						NoViableAltException nvae =
							new NoViableAltException("", 33, 0, input);
						throw nvae;
					}

					switch (alt33) {
						case 1 :
							// ghidra/sleigh/grammar/SleighCompiler.g:638:21: ^( OP_IDENTIFIER s= . )
							{
							match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_ctorstart1649); 
							match(input, Token.DOWN, null); 
							s=(CommonTree)input.LT(1);
							matchAny(input); 
							match(input, Token.UP, null); 


										SubtableSymbol ss = findOrNewTable(find(s), s.getText());
										if (ss != null) {
											value = sc.createConstructor(find(t), ss);
										}
									
							}
							break;
						case 2 :
							// ghidra/sleigh/grammar/SleighCompiler.g:644:4: t= OP_WILDCARD
							{
							t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_ctorstart1663); 

										wildcardError(t, "subconstructor");
									
							}
							break;

					}

					pushFollow(FOLLOW_display_in_ctorstart1670);
					display(value);
					state._fsp--;

					match(input, Token.UP, null); 

					  
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:647:4: ^(t= OP_TABLE d= display[value] )
					{
					t=(CommonTree)match(input,OP_TABLE,FOLLOW_OP_TABLE_in_ctorstart1682); 

								value = sc.createConstructor(find(t), null);
								ctorstart_stack.peek().table = "instruction".equals(value.getParent().getName());
							
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_display_in_ctorstart1688);
					display(value);
					state._fsp--;

					match(input, Token.UP, null); 

					  
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
			ctorstart_stack.pop();
		}
		return value;
	}
	// $ANTLR end "ctorstart"



	// $ANTLR start "display"
	// ghidra/sleigh/grammar/SleighCompiler.g:653:1: display[Constructor ct] : ^( OP_DISPLAY p= pieces[ct] ) ;
	public final void display(Constructor ct) throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:654:2: ( ^( OP_DISPLAY p= pieces[ct] ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:654:4: ^( OP_DISPLAY p= pieces[ct] )
			{
			match(input,OP_DISPLAY,FOLLOW_OP_DISPLAY_in_display1705); 
			if ( input.LA(1)==Token.DOWN ) {
				match(input, Token.DOWN, null); 
				pushFollow(FOLLOW_pieces_in_display1709);
				pieces(ct);
				state._fsp--;

				match(input, Token.UP, null); 
			}

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "display"



	// $ANTLR start "pieces"
	// ghidra/sleigh/grammar/SleighCompiler.g:657:1: pieces[Constructor ct] : ( printpiece[ct] )* ;
	public final void pieces(Constructor ct) throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:658:2: ( ( printpiece[ct] )* )
			// ghidra/sleigh/grammar/SleighCompiler.g:658:4: ( printpiece[ct] )*
			{
			// ghidra/sleigh/grammar/SleighCompiler.g:658:4: ( printpiece[ct] )*
			loop35:
			while (true) {
				int alt35=2;
				int LA35_0 = input.LA(1);
				if ( (LA35_0==OP_CONCATENATE||LA35_0==OP_IDENTIFIER||LA35_0==OP_QSTRING||LA35_0==OP_STRING||LA35_0==OP_WHITESPACE) ) {
					alt35=1;
				}

				switch (alt35) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:658:4: printpiece[ct]
					{
					pushFollow(FOLLOW_printpiece_in_pieces1723);
					printpiece(ct);
					state._fsp--;

					}
					break;

				default :
					break loop35;
				}
			}

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "pieces"



	// $ANTLR start "printpiece"
	// ghidra/sleigh/grammar/SleighCompiler.g:661:1: printpiece[Constructor ct] : ( ^( OP_IDENTIFIER t= . ) |w= whitespace | OP_CONCATENATE |s= string );
	public final void printpiece(Constructor ct) throws RecognitionException {
		CommonTree t=null;
		String w =null;
		String s =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:665:2: ( ^( OP_IDENTIFIER t= . ) |w= whitespace | OP_CONCATENATE |s= string )
			int alt36=4;
			switch ( input.LA(1) ) {
			case OP_IDENTIFIER:
				{
				alt36=1;
				}
				break;
			case OP_WHITESPACE:
				{
				alt36=2;
				}
				break;
			case OP_CONCATENATE:
				{
				alt36=3;
				}
				break;
			case OP_QSTRING:
			case OP_STRING:
				{
				alt36=4;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 36, 0, input);
				throw nvae;
			}
			switch (alt36) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:665:4: ^( OP_IDENTIFIER t= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_printpiece1744); 
					match(input, Token.DOWN, null); 
					t=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								if (ctorstart_stack.peek().table && ctorstart_stack.peek().firstTime) {
									ct.addSyntax(t.getText());
								} else {
									sc.newOperand(find(t), ct, t.getText());
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:672:4: w= whitespace
					{
					pushFollow(FOLLOW_whitespace_in_printpiece1758);
					w=whitespace();
					state._fsp--;


								if (!ctorstart_stack.peek().firstTime) {
									ct.addSyntax(" ");
								}
							
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:677:4: OP_CONCATENATE
					{
					match(input,OP_CONCATENATE,FOLLOW_OP_CONCATENATE_in_printpiece1765); 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:678:4: s= string
					{
					pushFollow(FOLLOW_string_in_printpiece1772);
					s=string();
					state._fsp--;

					 ct.addSyntax(s); 
					}
					break;

			}

					ctorstart_stack.peek().firstTime = false;
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "printpiece"



	// $ANTLR start "whitespace"
	// ghidra/sleigh/grammar/SleighCompiler.g:681:1: whitespace returns [String value] : ^( OP_WHITESPACE s= . ) ;
	public final String whitespace() throws RecognitionException {
		String value = null;


		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:682:2: ( ^( OP_WHITESPACE s= . ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:682:4: ^( OP_WHITESPACE s= . )
			{
			match(input,OP_WHITESPACE,FOLLOW_OP_WHITESPACE_in_whitespace1790); 
			match(input, Token.DOWN, null); 
			s=(CommonTree)input.LT(1);
			matchAny(input); 
			match(input, Token.UP, null); 

			 value = s.getText(); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "whitespace"



	// $ANTLR start "string"
	// ghidra/sleigh/grammar/SleighCompiler.g:685:1: string returns [String value] : ( ^( OP_STRING s= . ) | ^( OP_QSTRING s= . ) );
	public final String string() throws RecognitionException {
		String value = null;


		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:686:2: ( ^( OP_STRING s= . ) | ^( OP_QSTRING s= . ) )
			int alt37=2;
			int LA37_0 = input.LA(1);
			if ( (LA37_0==OP_STRING) ) {
				alt37=1;
			}
			else if ( (LA37_0==OP_QSTRING) ) {
				alt37=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 37, 0, input);
				throw nvae;
			}

			switch (alt37) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:686:4: ^( OP_STRING s= . )
					{
					match(input,OP_STRING,FOLLOW_OP_STRING_in_string1813); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					 value = s.getText(); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:687:4: ^( OP_QSTRING s= . )
					{
					match(input,OP_QSTRING,FOLLOW_OP_QSTRING_in_string1826); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					 value = s.getText(); 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "string"



	// $ANTLR start "pequation"
	// ghidra/sleigh/grammar/SleighCompiler.g:690:1: pequation returns [PatternEquation value] : ( ^(t= OP_BOOL_OR l= pequation r= pequation ) | ^(t= OP_SEQUENCE l= pequation r= pequation ) | ^(t= OP_BOOL_AND l= pequation r= pequation ) | ^(t= OP_ELLIPSIS l= pequation ) | ^(t= OP_ELLIPSIS_RIGHT l= pequation ) | ^(t= OP_EQUAL s= family_or_operand_symbol[\"pattern equation\"] e= pexpression2 ) | ^(t= OP_NOTEQUAL f= family_symbol[\"pattern equation\"] e= pexpression2 ) | ^(t= OP_LESS f= family_symbol[\"pattern equation\"] e= pexpression2 ) | ^(t= OP_LESSEQUAL f= family_symbol[\"pattern equation\"] e= pexpression2 ) | ^(t= OP_GREAT f= family_symbol[\"pattern equation\"] e= pexpression2 ) | ^(t= OP_GREATEQUAL f= family_symbol[\"pattern equation\"] e= pexpression2 ) |ps= pequation_symbol[\"pattern equation\"] | ^( OP_PARENTHESIZED l= pequation ) );
	public final PatternEquation pequation() throws RecognitionException {
		PatternEquation value = null;


		CommonTree t=null;
		PatternEquation l =null;
		PatternEquation r =null;
		Tree s =null;
		PatternExpression e =null;
		FamilySymbol f =null;
		PatternEquation ps =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:696:2: ( ^(t= OP_BOOL_OR l= pequation r= pequation ) | ^(t= OP_SEQUENCE l= pequation r= pequation ) | ^(t= OP_BOOL_AND l= pequation r= pequation ) | ^(t= OP_ELLIPSIS l= pequation ) | ^(t= OP_ELLIPSIS_RIGHT l= pequation ) | ^(t= OP_EQUAL s= family_or_operand_symbol[\"pattern equation\"] e= pexpression2 ) | ^(t= OP_NOTEQUAL f= family_symbol[\"pattern equation\"] e= pexpression2 ) | ^(t= OP_LESS f= family_symbol[\"pattern equation\"] e= pexpression2 ) | ^(t= OP_LESSEQUAL f= family_symbol[\"pattern equation\"] e= pexpression2 ) | ^(t= OP_GREAT f= family_symbol[\"pattern equation\"] e= pexpression2 ) | ^(t= OP_GREATEQUAL f= family_symbol[\"pattern equation\"] e= pexpression2 ) |ps= pequation_symbol[\"pattern equation\"] | ^( OP_PARENTHESIZED l= pequation ) )
			int alt38=13;
			switch ( input.LA(1) ) {
			case OP_BOOL_OR:
				{
				alt38=1;
				}
				break;
			case OP_SEQUENCE:
				{
				alt38=2;
				}
				break;
			case OP_BOOL_AND:
				{
				alt38=3;
				}
				break;
			case OP_ELLIPSIS:
				{
				alt38=4;
				}
				break;
			case OP_ELLIPSIS_RIGHT:
				{
				alt38=5;
				}
				break;
			case OP_EQUAL:
				{
				alt38=6;
				}
				break;
			case OP_NOTEQUAL:
				{
				alt38=7;
				}
				break;
			case OP_LESS:
				{
				alt38=8;
				}
				break;
			case OP_LESSEQUAL:
				{
				alt38=9;
				}
				break;
			case OP_GREAT:
				{
				alt38=10;
				}
				break;
			case OP_GREATEQUAL:
				{
				alt38=11;
				}
				break;
			case OP_IDENTIFIER:
			case OP_WILDCARD:
				{
				alt38=12;
				}
				break;
			case OP_PARENTHESIZED:
				{
				alt38=13;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 38, 0, input);
				throw nvae;
			}
			switch (alt38) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:696:4: ^(t= OP_BOOL_OR l= pequation r= pequation )
					{
					t=(CommonTree)match(input,OP_BOOL_OR,FOLLOW_OP_BOOL_OR_in_pequation1857); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pequation_in_pequation1861);
					l=pequation();
					state._fsp--;

					pushFollow(FOLLOW_pequation_in_pequation1865);
					r=pequation();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new EquationOr(find(t), l, r); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:697:4: ^(t= OP_SEQUENCE l= pequation r= pequation )
					{
					t=(CommonTree)match(input,OP_SEQUENCE,FOLLOW_OP_SEQUENCE_in_pequation1876); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pequation_in_pequation1880);
					l=pequation();
					state._fsp--;

					pushFollow(FOLLOW_pequation_in_pequation1884);
					r=pequation();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new EquationCat(find(t), l, r); 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:698:4: ^(t= OP_BOOL_AND l= pequation r= pequation )
					{
					t=(CommonTree)match(input,OP_BOOL_AND,FOLLOW_OP_BOOL_AND_in_pequation1895); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pequation_in_pequation1899);
					l=pequation();
					state._fsp--;

					pushFollow(FOLLOW_pequation_in_pequation1903);
					r=pequation();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new EquationAnd(find(t), l, r); 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:700:4: ^(t= OP_ELLIPSIS l= pequation )
					{
					t=(CommonTree)match(input,OP_ELLIPSIS,FOLLOW_OP_ELLIPSIS_in_pequation1915); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pequation_in_pequation1919);
					l=pequation();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new EquationLeftEllipsis(find(t), l); 
					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighCompiler.g:701:4: ^(t= OP_ELLIPSIS_RIGHT l= pequation )
					{
					t=(CommonTree)match(input,OP_ELLIPSIS_RIGHT,FOLLOW_OP_ELLIPSIS_RIGHT_in_pequation1930); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pequation_in_pequation1934);
					l=pequation();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new EquationRightEllipsis(find(t), l); 
					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighCompiler.g:703:4: ^(t= OP_EQUAL s= family_or_operand_symbol[\"pattern equation\"] e= pexpression2 )
					{
					t=(CommonTree)match(input,OP_EQUAL,FOLLOW_OP_EQUAL_in_pequation1946); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_family_or_operand_symbol_in_pequation1950);
					s=family_or_operand_symbol("pattern equation");
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pequation1955);
					e=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 


								SleighSymbol sym = sc.findSymbol(s.getText());
								if (sym instanceof OperandSymbol) {
									value = sc.constrainOperand(find(t), (OperandSymbol) sym, e);
								} else {
									FamilySymbol fs = (FamilySymbol) sym;
									value = new EqualEquation(find(t), fs.getPatternValue(), e);
								}
							
					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighCompiler.g:712:4: ^(t= OP_NOTEQUAL f= family_symbol[\"pattern equation\"] e= pexpression2 )
					{
					t=(CommonTree)match(input,OP_NOTEQUAL,FOLLOW_OP_NOTEQUAL_in_pequation1966); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_family_symbol_in_pequation1970);
					f=family_symbol("pattern equation");
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pequation1975);
					e=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new NotEqualEquation(find(t), f.getPatternValue(), e); 
					}
					break;
				case 8 :
					// ghidra/sleigh/grammar/SleighCompiler.g:713:4: ^(t= OP_LESS f= family_symbol[\"pattern equation\"] e= pexpression2 )
					{
					t=(CommonTree)match(input,OP_LESS,FOLLOW_OP_LESS_in_pequation1986); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_family_symbol_in_pequation1990);
					f=family_symbol("pattern equation");
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pequation1995);
					e=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new LessEquation(find(t), f.getPatternValue(), e); 
					}
					break;
				case 9 :
					// ghidra/sleigh/grammar/SleighCompiler.g:714:4: ^(t= OP_LESSEQUAL f= family_symbol[\"pattern equation\"] e= pexpression2 )
					{
					t=(CommonTree)match(input,OP_LESSEQUAL,FOLLOW_OP_LESSEQUAL_in_pequation2006); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_family_symbol_in_pequation2010);
					f=family_symbol("pattern equation");
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pequation2015);
					e=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new LessEqualEquation(find(t), f.getPatternValue(), e); 
					}
					break;
				case 10 :
					// ghidra/sleigh/grammar/SleighCompiler.g:715:4: ^(t= OP_GREAT f= family_symbol[\"pattern equation\"] e= pexpression2 )
					{
					t=(CommonTree)match(input,OP_GREAT,FOLLOW_OP_GREAT_in_pequation2026); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_family_symbol_in_pequation2030);
					f=family_symbol("pattern equation");
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pequation2035);
					e=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new GreaterEquation(find(t), f.getPatternValue(), e); 
					}
					break;
				case 11 :
					// ghidra/sleigh/grammar/SleighCompiler.g:716:4: ^(t= OP_GREATEQUAL f= family_symbol[\"pattern equation\"] e= pexpression2 )
					{
					t=(CommonTree)match(input,OP_GREATEQUAL,FOLLOW_OP_GREATEQUAL_in_pequation2046); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_family_symbol_in_pequation2050);
					f=family_symbol("pattern equation");
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pequation2055);
					e=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new GreaterEqualEquation(find(t), f.getPatternValue(), e); 
					}
					break;
				case 12 :
					// ghidra/sleigh/grammar/SleighCompiler.g:718:4: ps= pequation_symbol[\"pattern equation\"]
					{
					pushFollow(FOLLOW_pequation_symbol_in_pequation2066);
					ps=pequation_symbol("pattern equation");
					state._fsp--;

					 value = ps; 
					}
					break;
				case 13 :
					// ghidra/sleigh/grammar/SleighCompiler.g:719:4: ^( OP_PARENTHESIZED l= pequation )
					{
					match(input,OP_PARENTHESIZED,FOLLOW_OP_PARENTHESIZED_in_pequation2075); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pequation_in_pequation2079);
					l=pequation();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l; 
					}
					break;

			}

					if (value == null) {
						throw new BailoutException("Pattern equation parsing returned null");
					}
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "pequation"



	// $ANTLR start "family_or_operand_symbol"
	// ghidra/sleigh/grammar/SleighCompiler.g:723:1: family_or_operand_symbol[String purpose] returns [Tree value] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final Tree family_or_operand_symbol(String purpose) throws RecognitionException {
		Tree value = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:724:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt39=2;
			int LA39_0 = input.LA(1);
			if ( (LA39_0==OP_IDENTIFIER) ) {
				alt39=1;
			}
			else if ( (LA39_0==OP_WILDCARD) ) {
				alt39=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 39, 0, input);
				throw nvae;
			}

			switch (alt39) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:724:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_family_or_operand_symbol2100); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								SleighSymbol sym = sc.findSymbol(s.getText());
								if (sym == null) {
									unknownSymbolError(s.getText(), find(s), "family or operand", purpose);
								} else if(sym.getType() != symbol_type.value_symbol
										&& sym.getType() != symbol_type.valuemap_symbol
										&& sym.getType() != symbol_type.context_symbol
										&& sym.getType() != symbol_type.name_symbol
										&& sym.getType() != symbol_type.varnodelist_symbol
										&& sym.getType() != symbol_type.operand_symbol) {
									wrongSymbolTypeError(sym, find(s), "family or operand", purpose);
								} else {
									value = s;
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:739:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_family_or_operand_symbol2114); 

								wildcardError(t, purpose);
							
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "family_or_operand_symbol"



	// $ANTLR start "pequation_symbol"
	// ghidra/sleigh/grammar/SleighCompiler.g:744:1: pequation_symbol[String purpose] returns [PatternEquation value] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final PatternEquation pequation_symbol(String purpose) throws RecognitionException {
		PatternEquation value = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:745:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt40=2;
			int LA40_0 = input.LA(1);
			if ( (LA40_0==OP_IDENTIFIER) ) {
				alt40=1;
			}
			else if ( (LA40_0==OP_WILDCARD) ) {
				alt40=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 40, 0, input);
				throw nvae;
			}

			switch (alt40) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:745:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_pequation_symbol2133); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								Location location = find(s);
								SleighSymbol sym = sc.findSymbol(s.getText());
								if (sym == null) {
									unknownSymbolError(s.getText(), find(s), "family, operand, epsilon, or subtable", purpose);
								} else if(sym.getType() == symbol_type.value_symbol
										|| sym.getType() == symbol_type.valuemap_symbol
										|| sym.getType() == symbol_type.context_symbol
										|| sym.getType() == symbol_type.name_symbol
										|| sym.getType() == symbol_type.varnodelist_symbol) {
									value = sc.defineInvisibleOperand(location, (FamilySymbol) sym);
								} else if(sym.getType() == symbol_type.operand_symbol) {
									OperandSymbol os = (OperandSymbol) sym;
									value = new OperandEquation(location, os.getIndex()); sc.selfDefine(os);
								} else if(sym.getType() == symbol_type.epsilon_symbol) {
									SpecificSymbol ss = (SpecificSymbol) sym;
									value = new UnconstrainedEquation(location, ss.getPatternExpression());
								} else if(sym.getType() == symbol_type.subtable_symbol) {
									SubtableSymbol ss = (SubtableSymbol) sym;
									value = sc.defineInvisibleOperand(location, ss);
								} else {
									value = null;
									wrongSymbolTypeError(sym, find(s), "family, operand, epsilon, or subtable", purpose);
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:770:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_pequation_symbol2147); 

								wildcardError(t, purpose);
							
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "pequation_symbol"



	// $ANTLR start "pexpression"
	// ghidra/sleigh/grammar/SleighCompiler.g:775:1: pexpression returns [PatternExpression value] : ( ^(t= OP_OR l= pexpression r= pexpression ) | ^(t= OP_XOR l= pexpression r= pexpression ) | ^(t= OP_AND l= pexpression r= pexpression ) | ^(t= OP_LEFT l= pexpression r= pexpression ) | ^(t= OP_RIGHT l= pexpression r= pexpression ) | ^(t= OP_ADD l= pexpression r= pexpression ) | ^(t= OP_SUB l= pexpression r= pexpression ) | ^(t= OP_MULT l= pexpression r= pexpression ) | ^(t= OP_DIV l= pexpression r= pexpression ) | ^(t= OP_NEGATE l= pexpression ) | ^(t= OP_INVERT l= pexpression ) |y= pattern_symbol[\"pattern expression\"] |i= integer | ^( OP_PARENTHESIZED l= pexpression ) );
	public final PatternExpression pexpression() throws RecognitionException {
		PatternExpression value = null;


		CommonTree t=null;
		PatternExpression l =null;
		PatternExpression r =null;
		PatternExpression y =null;
		RadixBigInteger i =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:776:2: ( ^(t= OP_OR l= pexpression r= pexpression ) | ^(t= OP_XOR l= pexpression r= pexpression ) | ^(t= OP_AND l= pexpression r= pexpression ) | ^(t= OP_LEFT l= pexpression r= pexpression ) | ^(t= OP_RIGHT l= pexpression r= pexpression ) | ^(t= OP_ADD l= pexpression r= pexpression ) | ^(t= OP_SUB l= pexpression r= pexpression ) | ^(t= OP_MULT l= pexpression r= pexpression ) | ^(t= OP_DIV l= pexpression r= pexpression ) | ^(t= OP_NEGATE l= pexpression ) | ^(t= OP_INVERT l= pexpression ) |y= pattern_symbol[\"pattern expression\"] |i= integer | ^( OP_PARENTHESIZED l= pexpression ) )
			int alt41=14;
			switch ( input.LA(1) ) {
			case OP_OR:
				{
				alt41=1;
				}
				break;
			case OP_XOR:
				{
				alt41=2;
				}
				break;
			case OP_AND:
				{
				alt41=3;
				}
				break;
			case OP_LEFT:
				{
				alt41=4;
				}
				break;
			case OP_RIGHT:
				{
				alt41=5;
				}
				break;
			case OP_ADD:
				{
				alt41=6;
				}
				break;
			case OP_SUB:
				{
				alt41=7;
				}
				break;
			case OP_MULT:
				{
				alt41=8;
				}
				break;
			case OP_DIV:
				{
				alt41=9;
				}
				break;
			case OP_NEGATE:
				{
				alt41=10;
				}
				break;
			case OP_INVERT:
				{
				alt41=11;
				}
				break;
			case OP_IDENTIFIER:
			case OP_WILDCARD:
				{
				alt41=12;
				}
				break;
			case OP_BIN_CONSTANT:
			case OP_DEC_CONSTANT:
			case OP_HEX_CONSTANT:
				{
				alt41=13;
				}
				break;
			case OP_PARENTHESIZED:
				{
				alt41=14;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 41, 0, input);
				throw nvae;
			}
			switch (alt41) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:776:4: ^(t= OP_OR l= pexpression r= pexpression )
					{
					t=(CommonTree)match(input,OP_OR,FOLLOW_OP_OR_in_pexpression2167); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2171);
					l=pexpression();
					state._fsp--;

					pushFollow(FOLLOW_pexpression_in_pexpression2175);
					r=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new OrExpression(find(t), l, r); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:777:4: ^(t= OP_XOR l= pexpression r= pexpression )
					{
					t=(CommonTree)match(input,OP_XOR,FOLLOW_OP_XOR_in_pexpression2186); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2190);
					l=pexpression();
					state._fsp--;

					pushFollow(FOLLOW_pexpression_in_pexpression2194);
					r=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new XorExpression(find(t), l, r); 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:778:4: ^(t= OP_AND l= pexpression r= pexpression )
					{
					t=(CommonTree)match(input,OP_AND,FOLLOW_OP_AND_in_pexpression2205); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2209);
					l=pexpression();
					state._fsp--;

					pushFollow(FOLLOW_pexpression_in_pexpression2213);
					r=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new AndExpression(find(t), l, r); 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:779:4: ^(t= OP_LEFT l= pexpression r= pexpression )
					{
					t=(CommonTree)match(input,OP_LEFT,FOLLOW_OP_LEFT_in_pexpression2224); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2228);
					l=pexpression();
					state._fsp--;

					pushFollow(FOLLOW_pexpression_in_pexpression2232);
					r=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new LeftShiftExpression(find(t), l, r); 
					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighCompiler.g:780:4: ^(t= OP_RIGHT l= pexpression r= pexpression )
					{
					t=(CommonTree)match(input,OP_RIGHT,FOLLOW_OP_RIGHT_in_pexpression2243); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2247);
					l=pexpression();
					state._fsp--;

					pushFollow(FOLLOW_pexpression_in_pexpression2251);
					r=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new RightShiftExpression(find(t), l, r); 
					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighCompiler.g:781:4: ^(t= OP_ADD l= pexpression r= pexpression )
					{
					t=(CommonTree)match(input,OP_ADD,FOLLOW_OP_ADD_in_pexpression2262); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2266);
					l=pexpression();
					state._fsp--;

					pushFollow(FOLLOW_pexpression_in_pexpression2270);
					r=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new PlusExpression(find(t), l, r); 
					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighCompiler.g:782:4: ^(t= OP_SUB l= pexpression r= pexpression )
					{
					t=(CommonTree)match(input,OP_SUB,FOLLOW_OP_SUB_in_pexpression2281); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2285);
					l=pexpression();
					state._fsp--;

					pushFollow(FOLLOW_pexpression_in_pexpression2289);
					r=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new SubExpression(find(t), l, r); 
					}
					break;
				case 8 :
					// ghidra/sleigh/grammar/SleighCompiler.g:783:4: ^(t= OP_MULT l= pexpression r= pexpression )
					{
					t=(CommonTree)match(input,OP_MULT,FOLLOW_OP_MULT_in_pexpression2300); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2304);
					l=pexpression();
					state._fsp--;

					pushFollow(FOLLOW_pexpression_in_pexpression2308);
					r=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new MultExpression(find(t), l, r); 
					}
					break;
				case 9 :
					// ghidra/sleigh/grammar/SleighCompiler.g:784:4: ^(t= OP_DIV l= pexpression r= pexpression )
					{
					t=(CommonTree)match(input,OP_DIV,FOLLOW_OP_DIV_in_pexpression2319); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2323);
					l=pexpression();
					state._fsp--;

					pushFollow(FOLLOW_pexpression_in_pexpression2327);
					r=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new DivExpression(find(t), l, r); 
					}
					break;
				case 10 :
					// ghidra/sleigh/grammar/SleighCompiler.g:786:4: ^(t= OP_NEGATE l= pexpression )
					{
					t=(CommonTree)match(input,OP_NEGATE,FOLLOW_OP_NEGATE_in_pexpression2339); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2343);
					l=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new MinusExpression(find(t), l); 
					}
					break;
				case 11 :
					// ghidra/sleigh/grammar/SleighCompiler.g:787:4: ^(t= OP_INVERT l= pexpression )
					{
					t=(CommonTree)match(input,OP_INVERT,FOLLOW_OP_INVERT_in_pexpression2354); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2358);
					l=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new NotExpression(find(t), l); 
					}
					break;
				case 12 :
					// ghidra/sleigh/grammar/SleighCompiler.g:790:4: y= pattern_symbol[\"pattern expression\"]
					{
					pushFollow(FOLLOW_pattern_symbol_in_pexpression2370);
					y=pattern_symbol("pattern expression");
					state._fsp--;

					 value = y; 
					}
					break;
				case 13 :
					// ghidra/sleigh/grammar/SleighCompiler.g:791:4: i= integer
					{
					pushFollow(FOLLOW_integer_in_pexpression2380);
					i=integer();
					state._fsp--;

					 value = new ConstantValue(i.location, i.longValue()); 
					}
					break;
				case 14 :
					// ghidra/sleigh/grammar/SleighCompiler.g:792:4: ^( OP_PARENTHESIZED l= pexpression )
					{
					match(input,OP_PARENTHESIZED,FOLLOW_OP_PARENTHESIZED_in_pexpression2388); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression_in_pexpression2392);
					l=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "pexpression"



	// $ANTLR start "pexpression2"
	// ghidra/sleigh/grammar/SleighCompiler.g:795:1: pexpression2 returns [PatternExpression value] : ( ^(t= OP_OR l= pexpression2 r= pexpression2 ) | ^(t= OP_XOR l= pexpression2 r= pexpression2 ) | ^(t= OP_AND l= pexpression2 r= pexpression2 ) | ^(t= OP_LEFT l= pexpression2 r= pexpression2 ) | ^(t= OP_RIGHT l= pexpression2 r= pexpression2 ) | ^(t= OP_ADD l= pexpression2 r= pexpression2 ) | ^(t= OP_SUB l= pexpression2 r= pexpression2 ) | ^(t= OP_MULT l= pexpression2 r= pexpression2 ) | ^(t= OP_DIV l= pexpression2 r= pexpression2 ) | ^(t= OP_NEGATE l= pexpression2 ) | ^(t= OP_INVERT l= pexpression2 ) |y= pattern_symbol2[\"pattern expression\"] |i= integer | ^( OP_PARENTHESIZED l= pexpression2 ) );
	public final PatternExpression pexpression2() throws RecognitionException {
		PatternExpression value = null;


		CommonTree t=null;
		PatternExpression l =null;
		PatternExpression r =null;
		PatternExpression y =null;
		RadixBigInteger i =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:796:2: ( ^(t= OP_OR l= pexpression2 r= pexpression2 ) | ^(t= OP_XOR l= pexpression2 r= pexpression2 ) | ^(t= OP_AND l= pexpression2 r= pexpression2 ) | ^(t= OP_LEFT l= pexpression2 r= pexpression2 ) | ^(t= OP_RIGHT l= pexpression2 r= pexpression2 ) | ^(t= OP_ADD l= pexpression2 r= pexpression2 ) | ^(t= OP_SUB l= pexpression2 r= pexpression2 ) | ^(t= OP_MULT l= pexpression2 r= pexpression2 ) | ^(t= OP_DIV l= pexpression2 r= pexpression2 ) | ^(t= OP_NEGATE l= pexpression2 ) | ^(t= OP_INVERT l= pexpression2 ) |y= pattern_symbol2[\"pattern expression\"] |i= integer | ^( OP_PARENTHESIZED l= pexpression2 ) )
			int alt42=14;
			switch ( input.LA(1) ) {
			case OP_OR:
				{
				alt42=1;
				}
				break;
			case OP_XOR:
				{
				alt42=2;
				}
				break;
			case OP_AND:
				{
				alt42=3;
				}
				break;
			case OP_LEFT:
				{
				alt42=4;
				}
				break;
			case OP_RIGHT:
				{
				alt42=5;
				}
				break;
			case OP_ADD:
				{
				alt42=6;
				}
				break;
			case OP_SUB:
				{
				alt42=7;
				}
				break;
			case OP_MULT:
				{
				alt42=8;
				}
				break;
			case OP_DIV:
				{
				alt42=9;
				}
				break;
			case OP_NEGATE:
				{
				alt42=10;
				}
				break;
			case OP_INVERT:
				{
				alt42=11;
				}
				break;
			case OP_IDENTIFIER:
			case OP_WILDCARD:
				{
				alt42=12;
				}
				break;
			case OP_BIN_CONSTANT:
			case OP_DEC_CONSTANT:
			case OP_HEX_CONSTANT:
				{
				alt42=13;
				}
				break;
			case OP_PARENTHESIZED:
				{
				alt42=14;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 42, 0, input);
				throw nvae;
			}
			switch (alt42) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:796:4: ^(t= OP_OR l= pexpression2 r= pexpression2 )
					{
					t=(CommonTree)match(input,OP_OR,FOLLOW_OP_OR_in_pexpression22413); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22417);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression22421);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new OrExpression(find(t), l, r); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:797:4: ^(t= OP_XOR l= pexpression2 r= pexpression2 )
					{
					t=(CommonTree)match(input,OP_XOR,FOLLOW_OP_XOR_in_pexpression22432); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22436);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression22440);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new XorExpression(find(t), l, r); 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:798:4: ^(t= OP_AND l= pexpression2 r= pexpression2 )
					{
					t=(CommonTree)match(input,OP_AND,FOLLOW_OP_AND_in_pexpression22451); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22455);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression22459);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new AndExpression(find(t), l, r); 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:799:4: ^(t= OP_LEFT l= pexpression2 r= pexpression2 )
					{
					t=(CommonTree)match(input,OP_LEFT,FOLLOW_OP_LEFT_in_pexpression22470); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22474);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression22478);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new LeftShiftExpression(find(t), l, r); 
					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighCompiler.g:800:4: ^(t= OP_RIGHT l= pexpression2 r= pexpression2 )
					{
					t=(CommonTree)match(input,OP_RIGHT,FOLLOW_OP_RIGHT_in_pexpression22489); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22493);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression22497);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new RightShiftExpression(find(t), l, r); 
					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighCompiler.g:801:4: ^(t= OP_ADD l= pexpression2 r= pexpression2 )
					{
					t=(CommonTree)match(input,OP_ADD,FOLLOW_OP_ADD_in_pexpression22508); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22512);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression22516);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new PlusExpression(find(t), l, r); 
					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighCompiler.g:802:4: ^(t= OP_SUB l= pexpression2 r= pexpression2 )
					{
					t=(CommonTree)match(input,OP_SUB,FOLLOW_OP_SUB_in_pexpression22527); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22531);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression22535);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new SubExpression(find(t), l, r); 
					}
					break;
				case 8 :
					// ghidra/sleigh/grammar/SleighCompiler.g:803:4: ^(t= OP_MULT l= pexpression2 r= pexpression2 )
					{
					t=(CommonTree)match(input,OP_MULT,FOLLOW_OP_MULT_in_pexpression22546); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22550);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression22554);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new MultExpression(find(t), l, r); 
					}
					break;
				case 9 :
					// ghidra/sleigh/grammar/SleighCompiler.g:804:4: ^(t= OP_DIV l= pexpression2 r= pexpression2 )
					{
					t=(CommonTree)match(input,OP_DIV,FOLLOW_OP_DIV_in_pexpression22565); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22569);
					l=pexpression2();
					state._fsp--;

					pushFollow(FOLLOW_pexpression2_in_pexpression22573);
					r=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new DivExpression(find(t), l, r); 
					}
					break;
				case 10 :
					// ghidra/sleigh/grammar/SleighCompiler.g:806:4: ^(t= OP_NEGATE l= pexpression2 )
					{
					t=(CommonTree)match(input,OP_NEGATE,FOLLOW_OP_NEGATE_in_pexpression22585); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22589);
					l=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new MinusExpression(find(t), l); 
					}
					break;
				case 11 :
					// ghidra/sleigh/grammar/SleighCompiler.g:807:4: ^(t= OP_INVERT l= pexpression2 )
					{
					t=(CommonTree)match(input,OP_INVERT,FOLLOW_OP_INVERT_in_pexpression22600); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22604);
					l=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = new NotExpression(find(t), l); 
					}
					break;
				case 12 :
					// ghidra/sleigh/grammar/SleighCompiler.g:810:4: y= pattern_symbol2[\"pattern expression\"]
					{
					pushFollow(FOLLOW_pattern_symbol2_in_pexpression22616);
					y=pattern_symbol2("pattern expression");
					state._fsp--;

					 value = y; 
					}
					break;
				case 13 :
					// ghidra/sleigh/grammar/SleighCompiler.g:811:4: i= integer
					{
					pushFollow(FOLLOW_integer_in_pexpression22626);
					i=integer();
					state._fsp--;

					 value = new ConstantValue(i.location, i.longValue()); 
					}
					break;
				case 14 :
					// ghidra/sleigh/grammar/SleighCompiler.g:812:4: ^( OP_PARENTHESIZED l= pexpression2 )
					{
					match(input,OP_PARENTHESIZED,FOLLOW_OP_PARENTHESIZED_in_pexpression22634); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_pexpression2_in_pexpression22638);
					l=pexpression2();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "pexpression2"



	// $ANTLR start "pattern_symbol"
	// ghidra/sleigh/grammar/SleighCompiler.g:815:1: pattern_symbol[String purpose] returns [PatternExpression expr] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final PatternExpression pattern_symbol(String purpose) throws RecognitionException {
		PatternExpression expr = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:816:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt43=2;
			int LA43_0 = input.LA(1);
			if ( (LA43_0==OP_IDENTIFIER) ) {
				alt43=1;
			}
			else if ( (LA43_0==OP_WILDCARD) ) {
				alt43=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 43, 0, input);
				throw nvae;
			}

			switch (alt43) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:816:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_pattern_symbol2658); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								SleighSymbol sym = sc.findSymbol(s.getText());
								if (sym == null) {
									unknownSymbolError(s.getText(), find(s), "start, end, operand, epsilon, or varnode", purpose);
					            } else if(sym.getType() == symbol_type.operand_symbol) {
					                OperandSymbol os = (OperandSymbol) sym;
					                if (os.getDefiningSymbol() != null && os.getDefiningSymbol().getType() == symbol_type.subtable_symbol) {
					                    reportError(find(s), "Subtable symbol " + sym.getName() + " is not allowed in context block");
					                }
					                expr = os.getPatternExpression();
								} else if(sym.getType() == symbol_type.start_symbol
										|| sym.getType() == symbol_type.end_symbol
										|| sym.getType() == symbol_type.epsilon_symbol
										|| sym.getType() == symbol_type.varnode_symbol) {
									SpecificSymbol ss = (SpecificSymbol) sym;
									expr = ss.getPatternExpression();
								} else if(sym.getType() == symbol_type.value_symbol
										|| sym.getType() == symbol_type.valuemap_symbol
										|| sym.getType() == symbol_type.context_symbol
										|| sym.getType() == symbol_type.name_symbol
										|| sym.getType() == symbol_type.varnodelist_symbol) {
									if (sym.getType() == symbol_type.context_symbol) {
										FamilySymbol z = (FamilySymbol) sym;
										expr = z.getPatternValue();
									} else {
										reportError(find(s), "Global symbol " + sym.getName() + " is not allowed in action expression");
									}
								} else {
									wrongSymbolTypeError(sym, find(s), "start, end, operand, epsilon, or varnode", purpose);
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:847:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_pattern_symbol2672); 

								wildcardError(t, purpose);
								expr = null;
							
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return expr;
	}
	// $ANTLR end "pattern_symbol"



	// $ANTLR start "pattern_symbol2"
	// ghidra/sleigh/grammar/SleighCompiler.g:853:1: pattern_symbol2[String purpose] returns [PatternExpression expr] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final PatternExpression pattern_symbol2(String purpose) throws RecognitionException {
		PatternExpression expr = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:854:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt44=2;
			int LA44_0 = input.LA(1);
			if ( (LA44_0==OP_IDENTIFIER) ) {
				alt44=1;
			}
			else if ( (LA44_0==OP_WILDCARD) ) {
				alt44=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 44, 0, input);
				throw nvae;
			}

			switch (alt44) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:854:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_pattern_symbol22691); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								SleighSymbol sym = sc.findSymbol(s.getText());
								if (sym == null) {
									unknownSymbolError(s.getText(), find(s), "start, end, operand, epsilon, or varnode", purpose);
								} else if(sym.getType() == symbol_type.start_symbol
										|| sym.getType() == symbol_type.end_symbol
										|| sym.getType() == symbol_type.operand_symbol
										|| sym.getType() == symbol_type.epsilon_symbol
										|| sym.getType() == symbol_type.varnode_symbol) {
									SpecificSymbol ss = (SpecificSymbol) sym;
									expr = ss.getPatternExpression();
								} else if(sym.getType() == symbol_type.value_symbol
										|| sym.getType() == symbol_type.valuemap_symbol
										|| sym.getType() == symbol_type.context_symbol
										|| sym.getType() == symbol_type.name_symbol
										|| sym.getType() == symbol_type.varnodelist_symbol) {
									FamilySymbol z = (FamilySymbol) sym;
									expr = z.getPatternValue();
								} else {
									wrongSymbolTypeError(sym, find(s), "start, end, operand, epsilon, or varnode", purpose);
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:876:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_pattern_symbol22705); 

								wildcardError(t, purpose);
								expr = null;
							
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return expr;
	}
	// $ANTLR end "pattern_symbol2"



	// $ANTLR start "contextblock"
	// ghidra/sleigh/grammar/SleighCompiler.g:882:1: contextblock returns [VectorSTL<ContextChange> value] : ( ^( OP_CONTEXT_BLOCK r= cstatements ) | OP_NO_CONTEXT_BLOCK );
	public final VectorSTL<ContextChange> contextblock() throws RecognitionException {
		VectorSTL<ContextChange> value = null;


		VectorSTL<ContextChange> r =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:883:2: ( ^( OP_CONTEXT_BLOCK r= cstatements ) | OP_NO_CONTEXT_BLOCK )
			int alt45=2;
			int LA45_0 = input.LA(1);
			if ( (LA45_0==OP_CONTEXT_BLOCK) ) {
				alt45=1;
			}
			else if ( (LA45_0==OP_NO_CONTEXT_BLOCK) ) {
				alt45=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 45, 0, input);
				throw nvae;
			}

			switch (alt45) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:883:4: ^( OP_CONTEXT_BLOCK r= cstatements )
					{
					match(input,OP_CONTEXT_BLOCK,FOLLOW_OP_CONTEXT_BLOCK_in_contextblock2723); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_cstatements_in_contextblock2727);
					r=cstatements();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = r; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:884:4: OP_NO_CONTEXT_BLOCK
					{
					match(input,OP_NO_CONTEXT_BLOCK,FOLLOW_OP_NO_CONTEXT_BLOCK_in_contextblock2735); 
					 value = null; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "contextblock"



	// $ANTLR start "cstatements"
	// ghidra/sleigh/grammar/SleighCompiler.g:887:1: cstatements returns [VectorSTL<ContextChange> r] : ( cstatement[r] )+ ;
	public final VectorSTL<ContextChange> cstatements() throws RecognitionException {
		VectorSTL<ContextChange> r = null;



				r = new VectorSTL<ContextChange>();
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:891:2: ( ( cstatement[r] )+ )
			// ghidra/sleigh/grammar/SleighCompiler.g:891:4: ( cstatement[r] )+
			{
			// ghidra/sleigh/grammar/SleighCompiler.g:891:4: ( cstatement[r] )+
			int cnt46=0;
			loop46:
			while (true) {
				int alt46=2;
				int LA46_0 = input.LA(1);
				if ( (LA46_0==OP_APPLY||LA46_0==OP_ASSIGN) ) {
					alt46=1;
				}

				switch (alt46) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:891:4: cstatement[r]
					{
					pushFollow(FOLLOW_cstatement_in_cstatements2757);
					cstatement(r);
					state._fsp--;

					}
					break;

				default :
					if ( cnt46 >= 1 ) break loop46;
					EarlyExitException eee = new EarlyExitException(46, input);
					throw eee;
				}
				cnt46++;
			}

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return r;
	}
	// $ANTLR end "cstatements"



	// $ANTLR start "cstatement"
	// ghidra/sleigh/grammar/SleighCompiler.g:894:1: cstatement[VectorSTL<ContextChange> r] : ( ^( OP_ASSIGN ^( OP_IDENTIFIER id= . ) e= pexpression ) | ^( OP_APPLY ^( OP_IDENTIFIER id= . ) ^( OP_IDENTIFIER arg1= . ) ^( OP_IDENTIFIER arg2= . ) ) );
	public final void cstatement(VectorSTL<ContextChange> r) throws RecognitionException {
		CommonTree id=null;
		CommonTree arg1=null;
		CommonTree arg2=null;
		PatternExpression e =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:895:2: ( ^( OP_ASSIGN ^( OP_IDENTIFIER id= . ) e= pexpression ) | ^( OP_APPLY ^( OP_IDENTIFIER id= . ) ^( OP_IDENTIFIER arg1= . ) ^( OP_IDENTIFIER arg2= . ) ) )
			int alt47=2;
			int LA47_0 = input.LA(1);
			if ( (LA47_0==OP_ASSIGN) ) {
				alt47=1;
			}
			else if ( (LA47_0==OP_APPLY) ) {
				alt47=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 47, 0, input);
				throw nvae;
			}

			switch (alt47) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:895:4: ^( OP_ASSIGN ^( OP_IDENTIFIER id= . ) e= pexpression )
					{
					match(input,OP_ASSIGN,FOLLOW_OP_ASSIGN_in_cstatement2772); 
					match(input, Token.DOWN, null); 
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_cstatement2775); 
					match(input, Token.DOWN, null); 
					id=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					pushFollow(FOLLOW_pexpression_in_cstatement2784);
					e=pexpression();
					state._fsp--;

					match(input, Token.UP, null); 


								SleighSymbol sym = sc.findSymbol(id.getText());
								if (sym == null) {
									unknownSymbolError(id.getText(), find(id), "context or operand", "context block lvalue");
								} else if(sym.getType() == symbol_type.context_symbol) {
									ContextSymbol t = (ContextSymbol) sym;
									if (!sc.contextMod(r, t, e)) {
										reportError(find(id), "Cannot use 'inst_next' to set context variable: " + t.getName());
									}
								} else if(sym.getType() == symbol_type.operand_symbol) {
									OperandSymbol t = (OperandSymbol) sym;
									sc.defineOperand(find(id), t, e);
								} else {
									wrongSymbolTypeError(sym, find(id), "context or operand", "context block lvalue");
								}	
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:911:4: ^( OP_APPLY ^( OP_IDENTIFIER id= . ) ^( OP_IDENTIFIER arg1= . ) ^( OP_IDENTIFIER arg2= . ) )
					{
					match(input,OP_APPLY,FOLLOW_OP_APPLY_in_cstatement2793); 
					match(input, Token.DOWN, null); 
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_cstatement2796); 
					match(input, Token.DOWN, null); 
					id=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_cstatement2804); 
					match(input, Token.DOWN, null); 
					arg1=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_cstatement2812); 
					match(input, Token.DOWN, null); 
					arg2=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					match(input, Token.UP, null); 


								if (!"globalset".equals(id.getText())) {
									reportError(find(id), "unknown context block function " + id.getText());
								} else {
									SleighSymbol sym = sc.findSymbol(arg2.getText());
									if (sym == null) {
										unknownSymbolError(arg2.getText(), find(arg2), "context", "globalset call");
									} else if(sym.getType() == symbol_type.context_symbol) {
										ContextSymbol t = (ContextSymbol) sym;
										sym = sc.findSymbol(arg1.getText());
										if (sym == null) {
											unknownSymbolError(arg1.getText(), find(arg1), "family or specific", "globalset call");
										} else if(sym.getType() == symbol_type.value_symbol
												|| sym.getType() == symbol_type.valuemap_symbol
												|| sym.getType() == symbol_type.context_symbol
												|| sym.getType() == symbol_type.name_symbol
												|| sym.getType() == symbol_type.varnodelist_symbol
												|| sym.getType() == symbol_type.start_symbol
												|| sym.getType() == symbol_type.end_symbol
												|| sym.getType() == symbol_type.operand_symbol
												|| sym.getType() == symbol_type.epsilon_symbol
												|| sym.getType() == symbol_type.varnode_symbol) {
											sc.contextSet(r, (TripleSymbol) sym, t);
										} else {
											wrongSymbolTypeError(sym, find(arg1), "family or specific", "globalset call");
										}
									} else {
										wrongSymbolTypeError(sym, find(arg2), "context", "globalset call");
									}
								}
							
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "cstatement"


	protected static class semantic_scope {
		SectionVector sections;
		boolean containsMultipleSections;
		boolean nextStatementMustBeSectionLabel;
		boolean canContainSections;
	}
	protected Stack<semantic_scope> semantic_stack = new Stack<semantic_scope>();


	// $ANTLR start "semantic"
	// ghidra/sleigh/grammar/SleighCompiler.g:944:1: semantic[ParsingEnvironment pe, PcodeCompile pcode, Tree where, boolean sectionsAllowed, boolean isMacroParse] returns [SectionVector rtl] : ^(x= OP_SEMANTIC c= code_block[find($x)] ) ;
	public final SectionVector semantic(ParsingEnvironment pe, PcodeCompile pcode, Tree where, boolean sectionsAllowed, boolean isMacroParse) throws RecognitionException {
		semantic_stack.push(new semantic_scope());
		SectionVector rtl = null;


		CommonTree x=null;
		ConstructTpl c =null;


				ParsingEnvironment oldEnv = this.env;
				SleighCompile oldSC = sc;
				sc = null; // TODO: force failure with improper use of sc instead of pcode
				this.env = pe;
				this.pcode = pcode;
				
				semantic_stack.peek().sections = null;
				semantic_stack.peek().containsMultipleSections = false;
				semantic_stack.peek().nextStatementMustBeSectionLabel = false;
				semantic_stack.peek().canContainSections = sectionsAllowed;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:966:2: ( ^(x= OP_SEMANTIC c= code_block[find($x)] ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:966:4: ^(x= OP_SEMANTIC c= code_block[find($x)] )
			{
			x=(CommonTree)match(input,OP_SEMANTIC,FOLLOW_OP_SEMANTIC_in_semantic2856); 
			if ( input.LA(1)==Token.DOWN ) {
				match(input, Token.DOWN, null); 
				pushFollow(FOLLOW_code_block_in_semantic2860);
				c=code_block(find(x));
				state._fsp--;


							if (c != null) {
								if (c.getOpvec().empty() && c.getResult() == null) {
									pcode.recordNop(find(where));
								}
								if (semantic_stack.peek().containsMultipleSections) {
									semantic_stack.peek().sections = pcode.finalNamedSection(semantic_stack.peek().sections, c);
								} else {
									if (!isMacroParse) {
										semantic_stack.peek().sections = pcode.standaloneSection(c);
									} else {
										macrodef_stack.peek().macrobody = c;
									}
								}
							}
						
				match(input, Token.UP, null); 
			}

			}


					rtl = semantic_stack.peek().sections;
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
			semantic_stack.pop();

				   this.sc = oldSC;
				   this.env = oldEnv;
				   this.pcode = null;
				
		}
		return rtl;
	}
	// $ANTLR end "semantic"


	protected static class code_block_scope {
		Location stmtLocation;
	}
	protected Stack<code_block_scope> code_block_stack = new Stack<code_block_scope>();


	// $ANTLR start "code_block"
	// ghidra/sleigh/grammar/SleighCompiler.g:990:1: code_block[Location startingPoint] returns [ConstructTpl rtl] : ( statements | OP_NOP );
	public final ConstructTpl code_block(Location startingPoint) throws RecognitionException {
		Block_stack.push(new Block_scope());
		code_block_stack.push(new code_block_scope());
		ConstructTpl rtl = null;



				Block_stack.peek().ct = new ConstructTpl(startingPoint);
				code_block_stack.peek().stmtLocation = new Location("<internal error populating statement location>", 0);
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1002:2: ( statements | OP_NOP )
			int alt48=2;
			int LA48_0 = input.LA(1);
			if ( (LA48_0==UP||LA48_0==OP_APPLY||LA48_0==OP_ASSIGN||(LA48_0 >= OP_BUILD && LA48_0 <= OP_CALL)||LA48_0==OP_CROSSBUILD||LA48_0==OP_EXPORT||LA48_0==OP_GOTO||LA48_0==OP_IF||LA48_0==OP_LABEL||LA48_0==OP_LOCAL||LA48_0==OP_RETURN||LA48_0==OP_SECTION_LABEL) ) {
				alt48=1;
			}
			else if ( (LA48_0==OP_NOP) ) {
				alt48=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 48, 0, input);
				throw nvae;
			}

			switch (alt48) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1002:4: statements
					{
					pushFollow(FOLLOW_statements_in_code_block2911);
					statements();
					state._fsp--;

					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1003:4: OP_NOP
					{
					match(input,OP_NOP,FOLLOW_OP_NOP_in_code_block2916); 
					}
					break;

			}

					rtl = Block_stack.peek().ct;
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
			Block_stack.pop();
			code_block_stack.pop();
		}
		return rtl;
	}
	// $ANTLR end "code_block"



	// $ANTLR start "statements"
	// ghidra/sleigh/grammar/SleighCompiler.g:1006:1: statements : ( statement )* ;
	public final void statements() throws RecognitionException {
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1007:2: ( ( statement )* )
			// ghidra/sleigh/grammar/SleighCompiler.g:1007:4: ( statement )*
			{
			// ghidra/sleigh/grammar/SleighCompiler.g:1007:4: ( statement )*
			loop49:
			while (true) {
				int alt49=2;
				int LA49_0 = input.LA(1);
				if ( (LA49_0==OP_APPLY||LA49_0==OP_ASSIGN||(LA49_0 >= OP_BUILD && LA49_0 <= OP_CALL)||LA49_0==OP_CROSSBUILD||LA49_0==OP_EXPORT||LA49_0==OP_GOTO||LA49_0==OP_IF||LA49_0==OP_LABEL||LA49_0==OP_LOCAL||LA49_0==OP_RETURN||LA49_0==OP_SECTION_LABEL) ) {
					alt49=1;
				}

				switch (alt49) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1007:4: statement
					{
					pushFollow(FOLLOW_statement_in_statements2927);
					statement();
					state._fsp--;

					}
					break;

				default :
					break loop49;
				}
			}

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "statements"



	// $ANTLR start "statement"
	// ghidra/sleigh/grammar/SleighCompiler.g:1010:1: statement : (r= assignment | declaration |r= funcall |r= build_stmt |r= crossbuild_stmt |r= goto_stmt |r= cond_stmt |r= call_stmt |r= return_stmt |l= label |e= export[$Block::ct] |s= section_label );
	public final void statement() throws RecognitionException {
		Return_stack.push(new Return_scope());

		VectorSTL<OpTpl> r =null;
		Pair<Location,LabelSymbol> l =null;
		ConstructTpl e =null;
		Pair<Location,SectionSymbol> s =null;


				VectorSTL<OpTpl> ops = new VectorSTL<OpTpl>();
				Return_stack.peek().noReturn = false;
				boolean wasSectionLabel = false;
				boolean lookingForSectionLabel = semantic_stack.peek().nextStatementMustBeSectionLabel;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1027:2: (r= assignment | declaration |r= funcall |r= build_stmt |r= crossbuild_stmt |r= goto_stmt |r= cond_stmt |r= call_stmt |r= return_stmt |l= label |e= export[$Block::ct] |s= section_label )
			int alt50=12;
			switch ( input.LA(1) ) {
			case OP_ASSIGN:
				{
				alt50=1;
				}
				break;
			case OP_LOCAL:
				{
				int LA50_2 = input.LA(2);
				if ( (LA50_2==DOWN) ) {
					int LA50_13 = input.LA(3);
					if ( (LA50_13==OP_ASSIGN) ) {
						alt50=1;
					}
					else if ( (LA50_13==OP_IDENTIFIER||LA50_13==OP_WILDCARD) ) {
						alt50=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 50, 13, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 50, 2, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			case OP_APPLY:
				{
				alt50=3;
				}
				break;
			case OP_BUILD:
				{
				alt50=4;
				}
				break;
			case OP_CROSSBUILD:
				{
				alt50=5;
				}
				break;
			case OP_GOTO:
				{
				alt50=6;
				}
				break;
			case OP_IF:
				{
				alt50=7;
				}
				break;
			case OP_CALL:
				{
				alt50=8;
				}
				break;
			case OP_RETURN:
				{
				alt50=9;
				}
				break;
			case OP_LABEL:
				{
				alt50=10;
				}
				break;
			case OP_EXPORT:
				{
				alt50=11;
				}
				break;
			case OP_SECTION_LABEL:
				{
				alt50=12;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 50, 0, input);
				throw nvae;
			}
			switch (alt50) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1027:4: r= assignment
					{
					pushFollow(FOLLOW_assignment_in_statement2959);
					r=assignment();
					state._fsp--;

					 ops = r; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1028:4: declaration
					{
					pushFollow(FOLLOW_declaration_in_statement2971);
					declaration();
					state._fsp--;

					 ops = null; 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1029:4: r= funcall
					{
					pushFollow(FOLLOW_funcall_in_statement2983);
					r=funcall();
					state._fsp--;

					 ops = r; 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1030:4: r= build_stmt
					{
					pushFollow(FOLLOW_build_stmt_in_statement3000);
					r=build_stmt();
					state._fsp--;

					 ops = r; 
					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1031:4: r= crossbuild_stmt
					{
					pushFollow(FOLLOW_crossbuild_stmt_in_statement3014);
					r=crossbuild_stmt();
					state._fsp--;

					 ops = r; 
					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1032:4: r= goto_stmt
					{
					pushFollow(FOLLOW_goto_stmt_in_statement3023);
					r=goto_stmt();
					state._fsp--;

					 ops = r; 
					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1033:4: r= cond_stmt
					{
					pushFollow(FOLLOW_cond_stmt_in_statement3038);
					r=cond_stmt();
					state._fsp--;

					 ops = r; 
					}
					break;
				case 8 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1034:4: r= call_stmt
					{
					pushFollow(FOLLOW_call_stmt_in_statement3053);
					r=call_stmt();
					state._fsp--;

					 ops = r; 
					}
					break;
				case 9 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1035:4: r= return_stmt
					{
					pushFollow(FOLLOW_return_stmt_in_statement3068);
					r=return_stmt();
					state._fsp--;

					 ops = r; 
					}
					break;
				case 10 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1036:4: l= label
					{
					pushFollow(FOLLOW_label_in_statement3081);
					l=label();
					state._fsp--;


								if (l != null) {
									ops = pcode.placeLabel(l.first, l.second);
								}
							
					}
					break;
				case 11 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1041:4: e= export[$Block::ct]
					{
					pushFollow(FOLLOW_export_in_statement3090);
					e=export(Block_stack.peek().ct);
					state._fsp--;


								if (semantic_stack.peek().containsMultipleSections) {
									reportError(code_block_stack.peek().stmtLocation, "Export only allowed in default section");
								}
								Block_stack.peek().ct = e;
								semantic_stack.peek().nextStatementMustBeSectionLabel = true;
							
					}
					break;
				case 12 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1048:4: s= section_label
					{
					pushFollow(FOLLOW_section_label_in_statement3100);
					s=section_label();
					state._fsp--;


								if(!semantic_stack.peek().canContainSections) {
									reportError(code_block_stack.peek().stmtLocation, "No sections allowed");
								}
								wasSectionLabel = true;
								if (semantic_stack.peek().containsMultipleSections) {
									semantic_stack.peek().sections = pcode.nextNamedSection(semantic_stack.peek().sections, Block_stack.peek().ct, s.second);
								} else {
									semantic_stack.peek().sections = pcode.firstNamedSection(Block_stack.peek().ct, s.second);
								}
								if (Block_stack.peek().ct.getOpvec().empty() && Block_stack.peek().ct.getResult() == null) {
										pcode.recordNop(s.first);
								}
								semantic_stack.peek().containsMultipleSections = true;
								Block_stack.peek().ct = new ConstructTpl(s.first);
							
					}
					break;

			}

					if (lookingForSectionLabel && !wasSectionLabel) {
						reportError(code_block_stack.peek().stmtLocation, "No statements allowed after export");
					}
					semantic_stack.peek().nextStatementMustBeSectionLabel = false;
					if (ops != null && !Block_stack.peek().ct.addOpList(ops)) {
						reportError(code_block_stack.peek().stmtLocation, "Multiple delayslot declarations");
					}
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
			Return_stack.pop();

		}
	}
	// $ANTLR end "statement"



	// $ANTLR start "declaration"
	// ghidra/sleigh/grammar/SleighCompiler.g:1066:1: declaration : ( ^( OP_LOCAL n= unbound_identifier[\"sized local declaration\"] i= integer ) | ^( OP_LOCAL n= unbound_identifier[\"local declaration\"] ) );
	public final void declaration() throws RecognitionException {
		Tree n =null;
		RadixBigInteger i =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1067:2: ( ^( OP_LOCAL n= unbound_identifier[\"sized local declaration\"] i= integer ) | ^( OP_LOCAL n= unbound_identifier[\"local declaration\"] ) )
			int alt51=2;
			alt51 = dfa51.predict(input);
			switch (alt51) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1067:4: ^( OP_LOCAL n= unbound_identifier[\"sized local declaration\"] i= integer )
					{
					match(input,OP_LOCAL,FOLLOW_OP_LOCAL_in_declaration3114); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_unbound_identifier_in_declaration3118);
					n=unbound_identifier("sized local declaration");
					state._fsp--;

					pushFollow(FOLLOW_integer_in_declaration3123);
					i=integer();
					state._fsp--;

					match(input, Token.UP, null); 


								pcode.newLocalDefinition(find(n), n.getText(), i.intValue());
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1070:4: ^( OP_LOCAL n= unbound_identifier[\"local declaration\"] )
					{
					match(input,OP_LOCAL,FOLLOW_OP_LOCAL_in_declaration3132); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_unbound_identifier_in_declaration3136);
					n=unbound_identifier("local declaration");
					state._fsp--;

					match(input, Token.UP, null); 


								pcode.newLocalDefinition(find(n), n.getText());
							
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
	}
	// $ANTLR end "declaration"



	// $ANTLR start "label"
	// ghidra/sleigh/grammar/SleighCompiler.g:1075:1: label returns [Pair<Location,LabelSymbol> result] : ^( OP_LABEL ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD ) ) ;
	public final Pair<Location,LabelSymbol> label() throws RecognitionException {
		Pair<Location,LabelSymbol> result = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1076:2: ( ^( OP_LABEL ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD ) ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:1076:4: ^( OP_LABEL ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD ) )
			{
			match(input,OP_LABEL,FOLLOW_OP_LABEL_in_label3156); 
			match(input, Token.DOWN, null); 
			// ghidra/sleigh/grammar/SleighCompiler.g:1076:15: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt52=2;
			int LA52_0 = input.LA(1);
			if ( (LA52_0==OP_IDENTIFIER) ) {
				alt52=1;
			}
			else if ( (LA52_0==OP_WILDCARD) ) {
				alt52=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 52, 0, input);
				throw nvae;
			}

			switch (alt52) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1076:16: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_label3160); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


										SleighSymbol sym = pcode.findSymbol(s.getText());
										if (sym != null) {
											if(sym.getType() != symbol_type.label_symbol) {
												wrongSymbolTypeError(sym, find(s), "label", "label");
											} else {
												result = new Pair<Location,LabelSymbol>(find(s), (LabelSymbol) sym);
											}
										} else {
											Location where = find(s);
											result = new Pair<Location,LabelSymbol>(where, pcode.defineLabel(where, s.getText()));
										}
									
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1089:6: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_label3176); 

										wildcardError(t, "label");
									
					}
					break;

			}

			match(input, Token.UP, null); 

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return result;
	}
	// $ANTLR end "label"



	// $ANTLR start "section_label"
	// ghidra/sleigh/grammar/SleighCompiler.g:1094:1: section_label returns [Pair<Location,SectionSymbol> result] : ^( OP_SECTION_LABEL ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD ) ) ;
	public final Pair<Location,SectionSymbol> section_label() throws RecognitionException {
		Pair<Location,SectionSymbol> result = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1095:2: ( ^( OP_SECTION_LABEL ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD ) ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:1095:4: ^( OP_SECTION_LABEL ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD ) )
			{
			match(input,OP_SECTION_LABEL,FOLLOW_OP_SECTION_LABEL_in_section_label3196); 
			match(input, Token.DOWN, null); 
			// ghidra/sleigh/grammar/SleighCompiler.g:1095:23: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt53=2;
			int LA53_0 = input.LA(1);
			if ( (LA53_0==OP_IDENTIFIER) ) {
				alt53=1;
			}
			else if ( (LA53_0==OP_WILDCARD) ) {
				alt53=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 53, 0, input);
				throw nvae;
			}

			switch (alt53) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1095:24: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_section_label3200); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


										SleighSymbol sym = pcode.findSymbol(s.getText());
										if (sym != null) {
											if(sym.getType() != symbol_type.section_symbol) {
												wrongSymbolTypeError(sym, find(s), "section", "section");
											} else {
												result = new Pair<Location,SectionSymbol>(find(s), (SectionSymbol) sym);
											}
										} else {
											Location where = find(s);
											result = new Pair<Location,SectionSymbol>(where, pcode.newSectionSymbol(where, s.getText()));
										}
									
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1108:6: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_section_label3216); 

										wildcardError(t, "section");
									
					}
					break;

			}

			match(input, Token.UP, null); 

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return result;
	}
	// $ANTLR end "section_label"



	// $ANTLR start "section_symbol"
	// ghidra/sleigh/grammar/SleighCompiler.g:1113:1: section_symbol[String purpose] returns [SectionSymbol value] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final SectionSymbol section_symbol(String purpose) throws RecognitionException {
		SectionSymbol value = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1114:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt54=2;
			int LA54_0 = input.LA(1);
			if ( (LA54_0==OP_IDENTIFIER) ) {
				alt54=1;
			}
			else if ( (LA54_0==OP_WILDCARD) ) {
				alt54=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 54, 0, input);
				throw nvae;
			}

			switch (alt54) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1114:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_section_symbol3237); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								Location location = find(s);
								SleighSymbol sym = pcode.findSymbol(s.getText());
								if (sym == null) {
									value = pcode.newSectionSymbol(location, s.getText());
								} else if(sym.getType() != symbol_type.section_symbol) {
									wrongSymbolTypeError(sym, find(s), "section", purpose);
								} else {
									value = (SectionSymbol) sym;
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1125:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_section_symbol3251); 

								wildcardError(t, purpose);
							
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "section_symbol"



	// $ANTLR start "assignment"
	// ghidra/sleigh/grammar/SleighCompiler.g:1130:1: assignment returns [VectorSTL<OpTpl> value] : ( ^(t= OP_ASSIGN ^( OP_BITRANGE ss= specific_symbol[\"bit range assignment\"] a= integer b= integer ) e= expr ) | ^(t= OP_ASSIGN ^( OP_DECLARATIVE_SIZE n= unbound_identifier[\"variable declaration/assignment\"] i= integer ) e= expr ) | ^( OP_LOCAL t= OP_ASSIGN ^( OP_DECLARATIVE_SIZE n= unbound_identifier[\"variable declaration/assignment\"] i= integer ) e= expr ) | ^( OP_LOCAL t= OP_ASSIGN n= unbound_identifier[\"variable declaration/assignment\"] e= expr ) | ^(t= OP_ASSIGN ^( OP_IDENTIFIER id= . ) e= expr ) | ^( OP_ASSIGN t= OP_WILDCARD e= expr ) | ^(t= OP_ASSIGN s= sizedstar f= expr ) );
	public final VectorSTL<OpTpl> assignment() throws RecognitionException {
		VectorSTL<OpTpl> value = null;


		CommonTree t=null;
		CommonTree id=null;
		SpecificSymbol ss =null;
		RadixBigInteger a =null;
		RadixBigInteger b =null;
		ExprTree e =null;
		Tree n =null;
		RadixBigInteger i =null;
		Pair<StarQuality, ExprTree> s =null;
		ExprTree f =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1134:2: ( ^(t= OP_ASSIGN ^( OP_BITRANGE ss= specific_symbol[\"bit range assignment\"] a= integer b= integer ) e= expr ) | ^(t= OP_ASSIGN ^( OP_DECLARATIVE_SIZE n= unbound_identifier[\"variable declaration/assignment\"] i= integer ) e= expr ) | ^( OP_LOCAL t= OP_ASSIGN ^( OP_DECLARATIVE_SIZE n= unbound_identifier[\"variable declaration/assignment\"] i= integer ) e= expr ) | ^( OP_LOCAL t= OP_ASSIGN n= unbound_identifier[\"variable declaration/assignment\"] e= expr ) | ^(t= OP_ASSIGN ^( OP_IDENTIFIER id= . ) e= expr ) | ^( OP_ASSIGN t= OP_WILDCARD e= expr ) | ^(t= OP_ASSIGN s= sizedstar f= expr ) )
			int alt55=7;
			int LA55_0 = input.LA(1);
			if ( (LA55_0==OP_ASSIGN) ) {
				int LA55_1 = input.LA(2);
				if ( (LA55_1==DOWN) ) {
					switch ( input.LA(3) ) {
					case OP_BITRANGE:
						{
						alt55=1;
						}
						break;
					case OP_DECLARATIVE_SIZE:
						{
						alt55=2;
						}
						break;
					case OP_IDENTIFIER:
						{
						alt55=5;
						}
						break;
					case OP_WILDCARD:
						{
						alt55=6;
						}
						break;
					case OP_DEREFERENCE:
						{
						alt55=7;
						}
						break;
					default:
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 55, 3, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 55, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

			}
			else if ( (LA55_0==OP_LOCAL) ) {
				int LA55_2 = input.LA(2);
				if ( (LA55_2==DOWN) ) {
					int LA55_4 = input.LA(3);
					if ( (LA55_4==OP_ASSIGN) ) {
						int LA55_10 = input.LA(4);
						if ( (LA55_10==OP_DECLARATIVE_SIZE) ) {
							alt55=3;
						}
						else if ( (LA55_10==OP_IDENTIFIER||LA55_10==OP_WILDCARD) ) {
							alt55=4;
						}

						else {
							int nvaeMark = input.mark();
							try {
								for (int nvaeConsume = 0; nvaeConsume < 4 - 1; nvaeConsume++) {
									input.consume();
								}
								NoViableAltException nvae =
									new NoViableAltException("", 55, 10, input);
								throw nvae;
							} finally {
								input.rewind(nvaeMark);
							}
						}

					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 55, 4, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 55, 2, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 55, 0, input);
				throw nvae;
			}

			switch (alt55) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1134:4: ^(t= OP_ASSIGN ^( OP_BITRANGE ss= specific_symbol[\"bit range assignment\"] a= integer b= integer ) e= expr )
					{
					t=(CommonTree)match(input,OP_ASSIGN,FOLLOW_OP_ASSIGN_in_assignment3277); 
					match(input, Token.DOWN, null); 
					match(input,OP_BITRANGE,FOLLOW_OP_BITRANGE_in_assignment3280); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_specific_symbol_in_assignment3284);
					ss=specific_symbol("bit range assignment");
					state._fsp--;

					pushFollow(FOLLOW_integer_in_assignment3289);
					a=integer();
					state._fsp--;

					pushFollow(FOLLOW_integer_in_assignment3293);
					b=integer();
					state._fsp--;

					match(input, Token.UP, null); 

					pushFollow(FOLLOW_expr_in_assignment3298);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								value = pcode.assignBitRange(find(t), ss.getVarnode(), a.intValue(), b.intValue(), e);	
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1137:4: ^(t= OP_ASSIGN ^( OP_DECLARATIVE_SIZE n= unbound_identifier[\"variable declaration/assignment\"] i= integer ) e= expr )
					{
					t=(CommonTree)match(input,OP_ASSIGN,FOLLOW_OP_ASSIGN_in_assignment3309); 
					match(input, Token.DOWN, null); 
					match(input,OP_DECLARATIVE_SIZE,FOLLOW_OP_DECLARATIVE_SIZE_in_assignment3312); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_unbound_identifier_in_assignment3316);
					n=unbound_identifier("variable declaration/assignment");
					state._fsp--;

					pushFollow(FOLLOW_integer_in_assignment3321);
					i=integer();
					state._fsp--;

					match(input, Token.UP, null); 

					pushFollow(FOLLOW_expr_in_assignment3326);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								value = pcode.newOutput(find(n), true, e, n.getText(), i.intValue());
							
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1140:4: ^( OP_LOCAL t= OP_ASSIGN ^( OP_DECLARATIVE_SIZE n= unbound_identifier[\"variable declaration/assignment\"] i= integer ) e= expr )
					{
					match(input,OP_LOCAL,FOLLOW_OP_LOCAL_in_assignment3335); 
					match(input, Token.DOWN, null); 
					t=(CommonTree)match(input,OP_ASSIGN,FOLLOW_OP_ASSIGN_in_assignment3339); 
					match(input,OP_DECLARATIVE_SIZE,FOLLOW_OP_DECLARATIVE_SIZE_in_assignment3342); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_unbound_identifier_in_assignment3346);
					n=unbound_identifier("variable declaration/assignment");
					state._fsp--;

					pushFollow(FOLLOW_integer_in_assignment3351);
					i=integer();
					state._fsp--;

					match(input, Token.UP, null); 

					pushFollow(FOLLOW_expr_in_assignment3356);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								value = pcode.newOutput(find(n), true, e, n.getText(), i.intValue());
							
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1143:4: ^( OP_LOCAL t= OP_ASSIGN n= unbound_identifier[\"variable declaration/assignment\"] e= expr )
					{
					match(input,OP_LOCAL,FOLLOW_OP_LOCAL_in_assignment3365); 
					match(input, Token.DOWN, null); 
					t=(CommonTree)match(input,OP_ASSIGN,FOLLOW_OP_ASSIGN_in_assignment3369); 
					pushFollow(FOLLOW_unbound_identifier_in_assignment3373);
					n=unbound_identifier("variable declaration/assignment");
					state._fsp--;

					pushFollow(FOLLOW_expr_in_assignment3378);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								value = pcode.newOutput(find(n), true, e, n.getText());
							
					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1146:4: ^(t= OP_ASSIGN ^( OP_IDENTIFIER id= . ) e= expr )
					{
					t=(CommonTree)match(input,OP_ASSIGN,FOLLOW_OP_ASSIGN_in_assignment3389); 
					match(input, Token.DOWN, null); 
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_assignment3392); 
					match(input, Token.DOWN, null); 
					id=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					pushFollow(FOLLOW_expr_in_assignment3401);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								SleighSymbol sym = pcode.findSymbol(id.getText());
								if (sym == null) {
									value = pcode.newOutput(find(id), false, e, id.getText());	
								} else if(sym.getType() != symbol_type.start_symbol
										&& sym.getType() != symbol_type.end_symbol
										&& sym.getType() != symbol_type.operand_symbol
										&& sym.getType() != symbol_type.epsilon_symbol
										&& sym.getType() != symbol_type.varnode_symbol) {
									wrongSymbolTypeError(sym, find(id), "start, end, operand, epsilon, or varnode", "assignment");
								} else {
									VarnodeTpl v = ((SpecificSymbol) sym).getVarnode();
									e.setOutput(find(t), v);
									value = ExprTree.toVector(e);
								}	
							
					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1162:4: ^( OP_ASSIGN t= OP_WILDCARD e= expr )
					{
					match(input,OP_ASSIGN,FOLLOW_OP_ASSIGN_in_assignment3410); 
					match(input, Token.DOWN, null); 
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_assignment3414); 
					pushFollow(FOLLOW_expr_in_assignment3418);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								wildcardError(t, "assignment");
							
					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1165:4: ^(t= OP_ASSIGN s= sizedstar f= expr )
					{
					t=(CommonTree)match(input,OP_ASSIGN,FOLLOW_OP_ASSIGN_in_assignment3429); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_sizedstar_in_assignment3433);
					s=sizedstar();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_assignment3437);
					f=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								value = pcode.createStore(find(t), s.first, s.second, f);
							
					}
					break;

			}

					code_block_stack.peek().stmtLocation = find(t);
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "assignment"



	// $ANTLR start "bitrange"
	// ghidra/sleigh/grammar/SleighCompiler.g:1170:1: bitrange returns [ExprTree value] : ^(t= OP_BITRANGE ss= specific_symbol[\"bit range\"] a= integer b= integer ) ;
	public final ExprTree bitrange() throws RecognitionException {
		ExprTree value = null;


		CommonTree t=null;
		SpecificSymbol ss =null;
		RadixBigInteger a =null;
		RadixBigInteger b =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1171:2: ( ^(t= OP_BITRANGE ss= specific_symbol[\"bit range\"] a= integer b= integer ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:1171:4: ^(t= OP_BITRANGE ss= specific_symbol[\"bit range\"] a= integer b= integer )
			{
			t=(CommonTree)match(input,OP_BITRANGE,FOLLOW_OP_BITRANGE_in_bitrange3458); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_specific_symbol_in_bitrange3462);
			ss=specific_symbol("bit range");
			state._fsp--;

			pushFollow(FOLLOW_integer_in_bitrange3467);
			a=integer();
			state._fsp--;

			pushFollow(FOLLOW_integer_in_bitrange3471);
			b=integer();
			state._fsp--;

			match(input, Token.UP, null); 

			 value = pcode.createBitRange(find(t), ss, a.intValue(), b.intValue()); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "bitrange"



	// $ANTLR start "sizedstar"
	// ghidra/sleigh/grammar/SleighCompiler.g:1174:1: sizedstar returns [Pair<StarQuality, ExprTree> value] : ( ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] i= integer e= expr ) | ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] e= expr ) | ^(t= OP_DEREFERENCE i= integer e= expr ) | ^(t= OP_DEREFERENCE e= expr ) );
	public final Pair<StarQuality, ExprTree> sizedstar() throws RecognitionException {
		Pair<StarQuality, ExprTree> value = null;


		CommonTree t=null;
		SpaceSymbol s =null;
		RadixBigInteger i =null;
		ExprTree e =null;


				StarQuality q = null;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1181:2: ( ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] i= integer e= expr ) | ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] e= expr ) | ^(t= OP_DEREFERENCE i= integer e= expr ) | ^(t= OP_DEREFERENCE e= expr ) )
			int alt56=4;
			alt56 = dfa56.predict(input);
			switch (alt56) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1181:4: ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] i= integer e= expr )
					{
					t=(CommonTree)match(input,OP_DEREFERENCE,FOLLOW_OP_DEREFERENCE_in_sizedstar3504); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_space_symbol_in_sizedstar3508);
					s=space_symbol("sized star operator");
					state._fsp--;

					pushFollow(FOLLOW_integer_in_sizedstar3513);
					i=integer();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_sizedstar3517);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								q = new StarQuality(find(t));
								q.setSize(i.intValue());
								q.setId(new ConstTpl(s.getSpace()));
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1186:4: ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] e= expr )
					{
					t=(CommonTree)match(input,OP_DEREFERENCE,FOLLOW_OP_DEREFERENCE_in_sizedstar3528); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_space_symbol_in_sizedstar3532);
					s=space_symbol("sized star operator");
					state._fsp--;

					pushFollow(FOLLOW_expr_in_sizedstar3537);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								q = new StarQuality(find(t));
								q.setSize(0);
								q.setId(new ConstTpl(s.getSpace()));
							
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1191:4: ^(t= OP_DEREFERENCE i= integer e= expr )
					{
					t=(CommonTree)match(input,OP_DEREFERENCE,FOLLOW_OP_DEREFERENCE_in_sizedstar3548); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_integer_in_sizedstar3552);
					i=integer();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_sizedstar3556);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								q = new StarQuality(find(t));
								q.setSize(i.intValue());
								q.setId(new ConstTpl(pcode.getDefaultSpace()));
							
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1196:4: ^(t= OP_DEREFERENCE e= expr )
					{
					t=(CommonTree)match(input,OP_DEREFERENCE,FOLLOW_OP_DEREFERENCE_in_sizedstar3567); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_sizedstar3571);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								q = new StarQuality(find(t));
								q.setSize(0);
								q.setId(new ConstTpl(pcode.getDefaultSpace()));
							
					}
					break;

			}

					value = new Pair<StarQuality, ExprTree>(q, e);
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "sizedstar"



	// $ANTLR start "sizedstarv"
	// ghidra/sleigh/grammar/SleighCompiler.g:1203:1: sizedstarv returns [Pair<StarQuality, VarnodeTpl> value] : ( ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] i= integer ss= specific_symbol[\"varnode reference\"] ) | ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] ss= specific_symbol[\"varnode reference\"] ) | ^(t= OP_DEREFERENCE i= integer ss= specific_symbol[\"varnode reference\"] ) | ^(t= OP_DEREFERENCE ss= specific_symbol[\"varnode reference\"] ) );
	public final Pair<StarQuality, VarnodeTpl> sizedstarv() throws RecognitionException {
		Pair<StarQuality, VarnodeTpl> value = null;


		CommonTree t=null;
		SpaceSymbol s =null;
		RadixBigInteger i =null;
		SpecificSymbol ss =null;


				StarQuality q = null;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1210:2: ( ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] i= integer ss= specific_symbol[\"varnode reference\"] ) | ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] ss= specific_symbol[\"varnode reference\"] ) | ^(t= OP_DEREFERENCE i= integer ss= specific_symbol[\"varnode reference\"] ) | ^(t= OP_DEREFERENCE ss= specific_symbol[\"varnode reference\"] ) )
			int alt57=4;
			alt57 = dfa57.predict(input);
			switch (alt57) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1210:4: ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] i= integer ss= specific_symbol[\"varnode reference\"] )
					{
					t=(CommonTree)match(input,OP_DEREFERENCE,FOLLOW_OP_DEREFERENCE_in_sizedstarv3604); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_space_symbol_in_sizedstarv3608);
					s=space_symbol("sized star operator");
					state._fsp--;

					pushFollow(FOLLOW_integer_in_sizedstarv3613);
					i=integer();
					state._fsp--;

					pushFollow(FOLLOW_specific_symbol_in_sizedstarv3617);
					ss=specific_symbol("varnode reference");
					state._fsp--;

					match(input, Token.UP, null); 


								q = new StarQuality(find(t));
								q.setSize(i.intValue());
								q.setId(new ConstTpl(s.getSpace()));
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1215:4: ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] ss= specific_symbol[\"varnode reference\"] )
					{
					t=(CommonTree)match(input,OP_DEREFERENCE,FOLLOW_OP_DEREFERENCE_in_sizedstarv3629); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_space_symbol_in_sizedstarv3633);
					s=space_symbol("sized star operator");
					state._fsp--;

					pushFollow(FOLLOW_specific_symbol_in_sizedstarv3638);
					ss=specific_symbol("varnode reference");
					state._fsp--;

					match(input, Token.UP, null); 


								q = new StarQuality(find(t));
								q.setSize(0);
								q.setId(new ConstTpl(s.getSpace()));
							
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1220:4: ^(t= OP_DEREFERENCE i= integer ss= specific_symbol[\"varnode reference\"] )
					{
					t=(CommonTree)match(input,OP_DEREFERENCE,FOLLOW_OP_DEREFERENCE_in_sizedstarv3650); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_integer_in_sizedstarv3654);
					i=integer();
					state._fsp--;

					pushFollow(FOLLOW_specific_symbol_in_sizedstarv3658);
					ss=specific_symbol("varnode reference");
					state._fsp--;

					match(input, Token.UP, null); 


								q = new StarQuality(find(t));
								q.setSize(i.intValue());
								q.setId(new ConstTpl(pcode.getDefaultSpace()));
							
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1225:4: ^(t= OP_DEREFERENCE ss= specific_symbol[\"varnode reference\"] )
					{
					t=(CommonTree)match(input,OP_DEREFERENCE,FOLLOW_OP_DEREFERENCE_in_sizedstarv3670); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_specific_symbol_in_sizedstarv3674);
					ss=specific_symbol("varnode reference");
					state._fsp--;

					match(input, Token.UP, null); 


								q = new StarQuality(find(t));
								q.setSize(0);
								q.setId(new ConstTpl(pcode.getDefaultSpace()));
							
					}
					break;

			}

					value = new Pair<StarQuality, VarnodeTpl>(q, ss.getVarnode());
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "sizedstarv"



	// $ANTLR start "funcall"
	// ghidra/sleigh/grammar/SleighCompiler.g:1232:1: funcall returns [VectorSTL<OpTpl> value] : e= expr_apply ;
	public final VectorSTL<OpTpl> funcall() throws RecognitionException {
		VectorSTL<OpTpl> value = null;


		Object e =null;


				Return_stack.peek().noReturn = true;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1236:2: (e= expr_apply )
			// ghidra/sleigh/grammar/SleighCompiler.g:1236:4: e= expr_apply
			{
			pushFollow(FOLLOW_expr_apply_in_funcall3701);
			e=expr_apply();
			state._fsp--;

			 value = (VectorSTL<OpTpl>) e; 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "funcall"



	// $ANTLR start "build_stmt"
	// ghidra/sleigh/grammar/SleighCompiler.g:1239:1: build_stmt returns [VectorSTL<OpTpl> ops] : ^(t= OP_BUILD s= operand_symbol[\"build statement\"] ) ;
	public final VectorSTL<OpTpl> build_stmt() throws RecognitionException {
		VectorSTL<OpTpl> ops = null;


		CommonTree t=null;
		OperandSymbol s =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1243:2: ( ^(t= OP_BUILD s= operand_symbol[\"build statement\"] ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:1243:4: ^(t= OP_BUILD s= operand_symbol[\"build statement\"] )
			{
			t=(CommonTree)match(input,OP_BUILD,FOLLOW_OP_BUILD_in_build_stmt3727); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_operand_symbol_in_build_stmt3731);
			s=operand_symbol("build statement");
			state._fsp--;

			match(input, Token.UP, null); 


						ops = pcode.createOpConst(find(t), OpCode.CPUI_MULTIEQUAL, s.getIndex());
					
			}


					code_block_stack.peek().stmtLocation = find(t);
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return ops;
	}
	// $ANTLR end "build_stmt"



	// $ANTLR start "crossbuild_stmt"
	// ghidra/sleigh/grammar/SleighCompiler.g:1248:1: crossbuild_stmt returns [VectorSTL<OpTpl> ops] : ^(t= OP_CROSSBUILD v= varnode s= section_symbol[\"crossbuild statement\"] ) ;
	public final VectorSTL<OpTpl> crossbuild_stmt() throws RecognitionException {
		VectorSTL<OpTpl> ops = null;


		CommonTree t=null;
		VarnodeTpl v =null;
		SectionSymbol s =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1252:2: ( ^(t= OP_CROSSBUILD v= varnode s= section_symbol[\"crossbuild statement\"] ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:1252:4: ^(t= OP_CROSSBUILD v= varnode s= section_symbol[\"crossbuild statement\"] )
			{
			t=(CommonTree)match(input,OP_CROSSBUILD,FOLLOW_OP_CROSSBUILD_in_crossbuild_stmt3759); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_varnode_in_crossbuild_stmt3763);
			v=varnode();
			state._fsp--;

			pushFollow(FOLLOW_section_symbol_in_crossbuild_stmt3767);
			s=section_symbol("crossbuild statement");
			state._fsp--;

			match(input, Token.UP, null); 


						ops = pcode.createCrossBuild(find(t), v, s);
					
			}


					code_block_stack.peek().stmtLocation = find(t);
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return ops;
	}
	// $ANTLR end "crossbuild_stmt"



	// $ANTLR start "goto_stmt"
	// ghidra/sleigh/grammar/SleighCompiler.g:1257:1: goto_stmt returns [VectorSTL<OpTpl> ops] : ^(t= OP_GOTO j= jumpdest[\"goto destination\"] ) ;
	public final VectorSTL<OpTpl> goto_stmt() throws RecognitionException {
		Jump_stack.push(new Jump_scope());

		VectorSTL<OpTpl> ops = null;


		CommonTree t=null;
		ExprTree j =null;


				Jump_stack.peek().indirect = false;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1265:2: ( ^(t= OP_GOTO j= jumpdest[\"goto destination\"] ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:1265:4: ^(t= OP_GOTO j= jumpdest[\"goto destination\"] )
			{
			t=(CommonTree)match(input,OP_GOTO,FOLLOW_OP_GOTO_in_goto_stmt3807); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_jumpdest_in_goto_stmt3811);
			j=jumpdest("goto destination");
			state._fsp--;

			match(input, Token.UP, null); 


						ops = pcode.createOpNoOut(find(t), Jump_stack.peek().indirect ? OpCode.CPUI_BRANCHIND : OpCode.CPUI_BRANCH, j);
					
			}


					code_block_stack.peek().stmtLocation = find(t);
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
			Jump_stack.pop();

		}
		return ops;
	}
	// $ANTLR end "goto_stmt"



	// $ANTLR start "jump_symbol"
	// ghidra/sleigh/grammar/SleighCompiler.g:1270:1: jump_symbol[String purpose] returns [VarnodeTpl value] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final VarnodeTpl jump_symbol(String purpose) throws RecognitionException {
		VarnodeTpl value = null;


		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1271:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt58=2;
			int LA58_0 = input.LA(1);
			if ( (LA58_0==OP_IDENTIFIER) ) {
				alt58=1;
			}
			else if ( (LA58_0==OP_WILDCARD) ) {
				alt58=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 58, 0, input);
				throw nvae;
			}

			switch (alt58) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1271:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_jump_symbol3832); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 


								SleighSymbol sym = pcode.findSymbol(s.getText());
								if (sym == null) {
									unknownSymbolError(s.getText(), find(s), "start, end, or operand", purpose);
								} else if(sym.getType() == symbol_type.start_symbol || sym.getType() == symbol_type.end_symbol) {
									SpecificSymbol ss = (SpecificSymbol) sym;
									value = new VarnodeTpl(find(s), new ConstTpl(ConstTpl.const_type.j_curspace),
										ss.getVarnode().getOffset(),
										new ConstTpl(ConstTpl.const_type.j_curspace_size));
								} else if(sym.getType() == symbol_type.operand_symbol) {
									OperandSymbol os = (OperandSymbol) sym;
									value = os.getVarnode();
									os.setCodeAddress();
								} else {
									wrongSymbolTypeError(sym, find(s), "start, end, or operand", purpose);
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1288:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_jump_symbol3846); 

								wildcardError(t, purpose);
								value = null;
							
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "jump_symbol"



	// $ANTLR start "jumpdest"
	// ghidra/sleigh/grammar/SleighCompiler.g:1294:1: jumpdest[String purpose] returns [ExprTree value] : ( ^(t= OP_JUMPDEST_SYMBOL ss= jump_symbol[purpose] ) | ^(t= OP_JUMPDEST_DYNAMIC e= expr ) | ^(t= OP_JUMPDEST_ABSOLUTE i= integer ) | ^(t= OP_JUMPDEST_RELATIVE i= integer s= space_symbol[purpose] ) | ^(t= OP_JUMPDEST_LABEL l= label ) );
	public final ExprTree jumpdest(String purpose) throws RecognitionException {
		ExprTree value = null;


		CommonTree t=null;
		VarnodeTpl ss =null;
		ExprTree e =null;
		RadixBigInteger i =null;
		SpaceSymbol s =null;
		Pair<Location,LabelSymbol> l =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1295:2: ( ^(t= OP_JUMPDEST_SYMBOL ss= jump_symbol[purpose] ) | ^(t= OP_JUMPDEST_DYNAMIC e= expr ) | ^(t= OP_JUMPDEST_ABSOLUTE i= integer ) | ^(t= OP_JUMPDEST_RELATIVE i= integer s= space_symbol[purpose] ) | ^(t= OP_JUMPDEST_LABEL l= label ) )
			int alt59=5;
			switch ( input.LA(1) ) {
			case OP_JUMPDEST_SYMBOL:
				{
				alt59=1;
				}
				break;
			case OP_JUMPDEST_DYNAMIC:
				{
				alt59=2;
				}
				break;
			case OP_JUMPDEST_ABSOLUTE:
				{
				alt59=3;
				}
				break;
			case OP_JUMPDEST_RELATIVE:
				{
				alt59=4;
				}
				break;
			case OP_JUMPDEST_LABEL:
				{
				alt59=5;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 59, 0, input);
				throw nvae;
			}
			switch (alt59) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1295:4: ^(t= OP_JUMPDEST_SYMBOL ss= jump_symbol[purpose] )
					{
					t=(CommonTree)match(input,OP_JUMPDEST_SYMBOL,FOLLOW_OP_JUMPDEST_SYMBOL_in_jumpdest3867); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_jump_symbol_in_jumpdest3871);
					ss=jump_symbol(purpose);
					state._fsp--;

					match(input, Token.UP, null); 


								value = new ExprTree(find(t), ss);
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1298:4: ^(t= OP_JUMPDEST_DYNAMIC e= expr )
					{
					t=(CommonTree)match(input,OP_JUMPDEST_DYNAMIC,FOLLOW_OP_JUMPDEST_DYNAMIC_in_jumpdest3883); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_jumpdest3887);
					e=expr();
					state._fsp--;

					match(input, Token.UP, null); 


								value = e;
								if(Jump_stack.isEmpty()) {
									invalidDynamicTargetError(find(t), purpose);
								} else {
									Jump_stack.peek().indirect = true;
								}
							
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1306:4: ^(t= OP_JUMPDEST_ABSOLUTE i= integer )
					{
					t=(CommonTree)match(input,OP_JUMPDEST_ABSOLUTE,FOLLOW_OP_JUMPDEST_ABSOLUTE_in_jumpdest3898); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_integer_in_jumpdest3902);
					i=integer();
					state._fsp--;

					match(input, Token.UP, null); 


								value = new ExprTree(find(t), new VarnodeTpl(find(t), new ConstTpl(ConstTpl.const_type.j_curspace),
									new ConstTpl(ConstTpl.const_type.real, i.intValue()),
									new ConstTpl(ConstTpl.const_type.j_curspace_size)));
							
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1311:4: ^(t= OP_JUMPDEST_RELATIVE i= integer s= space_symbol[purpose] )
					{
					t=(CommonTree)match(input,OP_JUMPDEST_RELATIVE,FOLLOW_OP_JUMPDEST_RELATIVE_in_jumpdest3913); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_integer_in_jumpdest3917);
					i=integer();
					state._fsp--;

					pushFollow(FOLLOW_space_symbol_in_jumpdest3921);
					s=space_symbol(purpose);
					state._fsp--;

					match(input, Token.UP, null); 


								AddrSpace spc = s.getSpace();
								value = new ExprTree(find(t), new VarnodeTpl(find(t), new ConstTpl(spc),
									new ConstTpl(ConstTpl.const_type.real, i.intValue()),
									new ConstTpl(ConstTpl.const_type.real, spc.getAddrSize())));
							
					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1317:4: ^(t= OP_JUMPDEST_LABEL l= label )
					{
					t=(CommonTree)match(input,OP_JUMPDEST_LABEL,FOLLOW_OP_JUMPDEST_LABEL_in_jumpdest3933); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_label_in_jumpdest3937);
					l=label();
					state._fsp--;

					match(input, Token.UP, null); 


								value = new ExprTree(find(t), new VarnodeTpl(find(t), new ConstTpl(pcode.getConstantSpace()),
									new ConstTpl(ConstTpl.const_type.j_relative, l.second.getIndex()),
									new ConstTpl(ConstTpl.const_type.real, 4)));
								l.second.incrementRefCount();
							
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "jumpdest"



	// $ANTLR start "cond_stmt"
	// ghidra/sleigh/grammar/SleighCompiler.g:1325:1: cond_stmt returns [VectorSTL<OpTpl> ops] : ^(t= OP_IF e= expr ^( OP_GOTO j= jumpdest[\"goto destination\"] ) ) ;
	public final VectorSTL<OpTpl> cond_stmt() throws RecognitionException {
		VectorSTL<OpTpl> ops = null;


		CommonTree t=null;
		ExprTree e =null;
		ExprTree j =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1329:2: ( ^(t= OP_IF e= expr ^( OP_GOTO j= jumpdest[\"goto destination\"] ) ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:1329:4: ^(t= OP_IF e= expr ^( OP_GOTO j= jumpdest[\"goto destination\"] ) )
			{
			t=(CommonTree)match(input,OP_IF,FOLLOW_OP_IF_in_cond_stmt3964); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_expr_in_cond_stmt3968);
			e=expr();
			state._fsp--;

			match(input,OP_GOTO,FOLLOW_OP_GOTO_in_cond_stmt3971); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_jumpdest_in_cond_stmt3975);
			j=jumpdest("goto destination");
			state._fsp--;

			match(input, Token.UP, null); 

			match(input, Token.UP, null); 


						ops = pcode.createOpNoOut(find(t), OpCode.CPUI_CBRANCH, j, e);
					
			}


					code_block_stack.peek().stmtLocation = find(t);
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return ops;
	}
	// $ANTLR end "cond_stmt"



	// $ANTLR start "call_stmt"
	// ghidra/sleigh/grammar/SleighCompiler.g:1334:1: call_stmt returns [VectorSTL<OpTpl> ops] : ^(t= OP_CALL j= jumpdest[\"call destination\"] ) ;
	public final VectorSTL<OpTpl> call_stmt() throws RecognitionException {
		Jump_stack.push(new Jump_scope());

		VectorSTL<OpTpl> ops = null;


		CommonTree t=null;
		ExprTree j =null;


				Jump_stack.peek().indirect = false;
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1342:2: ( ^(t= OP_CALL j= jumpdest[\"call destination\"] ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:1342:4: ^(t= OP_CALL j= jumpdest[\"call destination\"] )
			{
			t=(CommonTree)match(input,OP_CALL,FOLLOW_OP_CALL_in_call_stmt4016); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_jumpdest_in_call_stmt4020);
			j=jumpdest("call destination");
			state._fsp--;

			match(input, Token.UP, null); 


						ops = pcode.createOpNoOut(find(t), Jump_stack.peek().indirect ? OpCode.CPUI_CALLIND : OpCode.CPUI_CALL, j);
					
			}


					code_block_stack.peek().stmtLocation = find(t);
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
			Jump_stack.pop();

		}
		return ops;
	}
	// $ANTLR end "call_stmt"



	// $ANTLR start "return_stmt"
	// ghidra/sleigh/grammar/SleighCompiler.g:1347:1: return_stmt returns [VectorSTL<OpTpl> ops] : ^(t= OP_RETURN e= expr ) ;
	public final VectorSTL<OpTpl> return_stmt() throws RecognitionException {
		VectorSTL<OpTpl> ops = null;


		CommonTree t=null;
		ExprTree e =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1351:2: ( ^(t= OP_RETURN e= expr ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:1351:4: ^(t= OP_RETURN e= expr )
			{
			t=(CommonTree)match(input,OP_RETURN,FOLLOW_OP_RETURN_in_return_stmt4048); 
			match(input, Token.DOWN, null); 
			pushFollow(FOLLOW_expr_in_return_stmt4052);
			e=expr();
			state._fsp--;

			match(input, Token.UP, null); 


						ops = pcode.createOpNoOut(find(t), OpCode.CPUI_RETURN, e);
					
			}


					code_block_stack.peek().stmtLocation = find(t);
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return ops;
	}
	// $ANTLR end "return_stmt"



	// $ANTLR start "export"
	// ghidra/sleigh/grammar/SleighCompiler.g:1356:1: export[ConstructTpl rtl] returns [ConstructTpl value] : ( ^(t= OP_EXPORT q= sizedstarv ) | ^(t= OP_EXPORT v= varnode ) );
	public final ConstructTpl export(ConstructTpl rtl) throws RecognitionException {
		ConstructTpl value = null;


		CommonTree t=null;
		Pair<StarQuality, VarnodeTpl> q =null;
		VarnodeTpl v =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1357:2: ( ^(t= OP_EXPORT q= sizedstarv ) | ^(t= OP_EXPORT v= varnode ) )
			int alt60=2;
			int LA60_0 = input.LA(1);
			if ( (LA60_0==OP_EXPORT) ) {
				int LA60_1 = input.LA(2);
				if ( (LA60_1==DOWN) ) {
					int LA60_2 = input.LA(3);
					if ( (LA60_2==OP_DEREFERENCE) ) {
						alt60=1;
					}
					else if ( (LA60_2==OP_ADDRESS_OF||LA60_2==OP_IDENTIFIER||LA60_2==OP_TRUNCATION_SIZE||LA60_2==OP_WILDCARD) ) {
						alt60=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 60, 2, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 60, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 60, 0, input);
				throw nvae;
			}

			switch (alt60) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1357:4: ^(t= OP_EXPORT q= sizedstarv )
					{
					t=(CommonTree)match(input,OP_EXPORT,FOLLOW_OP_EXPORT_in_export4074); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_sizedstarv_in_export4078);
					q=sizedstarv();
					state._fsp--;

					match(input, Token.UP, null); 


								value = pcode.setResultStarVarnode(rtl, q.first, q.second);
								code_block_stack.peek().stmtLocation = find(t);
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1361:4: ^(t= OP_EXPORT v= varnode )
					{
					t=(CommonTree)match(input,OP_EXPORT,FOLLOW_OP_EXPORT_in_export4089); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_varnode_in_export4093);
					v=varnode();
					state._fsp--;

					match(input, Token.UP, null); 


								value = pcode.setResultVarnode(rtl, v);
								code_block_stack.peek().stmtLocation = find(t);
							
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "export"



	// $ANTLR start "expr"
	// ghidra/sleigh/grammar/SleighCompiler.g:1367:1: expr returns [ExprTree value] : ( ^(t= OP_BOOL_OR l= expr r= expr ) | ^(t= OP_BOOL_XOR l= expr r= expr ) | ^(t= OP_BOOL_AND l= expr r= expr ) | ^(t= OP_OR l= expr r= expr ) | ^(t= OP_XOR l= expr r= expr ) | ^(t= OP_AND l= expr r= expr ) | ^(t= OP_EQUAL l= expr r= expr ) | ^(t= OP_NOTEQUAL l= expr r= expr ) | ^(t= OP_FEQUAL l= expr r= expr ) | ^(t= OP_FNOTEQUAL l= expr r= expr ) | ^(t= OP_LESS l= expr r= expr ) | ^(t= OP_GREATEQUAL l= expr r= expr ) | ^(t= OP_LESSEQUAL l= expr r= expr ) | ^(t= OP_GREAT l= expr r= expr ) | ^(t= OP_SLESS l= expr r= expr ) | ^(t= OP_SGREATEQUAL l= expr r= expr ) | ^(t= OP_SLESSEQUAL l= expr r= expr ) | ^(t= OP_SGREAT l= expr r= expr ) | ^(t= OP_FLESS l= expr r= expr ) | ^(t= OP_FGREATEQUAL l= expr r= expr ) | ^(t= OP_FLESSEQUAL l= expr r= expr ) | ^(t= OP_FGREAT l= expr r= expr ) | ^(t= OP_LEFT l= expr r= expr ) | ^(t= OP_RIGHT l= expr r= expr ) | ^(t= OP_SRIGHT l= expr r= expr ) | ^(t= OP_ADD l= expr r= expr ) | ^(t= OP_SUB l= expr r= expr ) | ^(t= OP_FADD l= expr r= expr ) | ^(t= OP_FSUB l= expr r= expr ) | ^(t= OP_MULT l= expr r= expr ) | ^(t= OP_DIV l= expr r= expr ) | ^(t= OP_REM l= expr r= expr ) | ^(t= OP_SDIV l= expr r= expr ) | ^(t= OP_SREM l= expr r= expr ) | ^(t= OP_FMULT l= expr r= expr ) | ^(t= OP_FDIV l= expr r= expr ) | ^(t= OP_NOT l= expr ) | ^(t= OP_INVERT l= expr ) | ^(t= OP_NEGATE l= expr ) | ^(t= OP_FNEGATE l= expr ) |s= sizedstar |a= expr_apply |v= varnode |b= bitrange |i= integer | ^( OP_PARENTHESIZED l= expr ) | ^(t= OP_BITRANGE2 ss= specific_symbol[\"expression\"] i= integer ) );
	public final ExprTree expr() throws RecognitionException {
		ExprTree value = null;


		CommonTree t=null;
		ExprTree l =null;
		ExprTree r =null;
		Pair<StarQuality, ExprTree> s =null;
		Object a =null;
		VarnodeTpl v =null;
		ExprTree b =null;
		RadixBigInteger i =null;
		SpecificSymbol ss =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1368:2: ( ^(t= OP_BOOL_OR l= expr r= expr ) | ^(t= OP_BOOL_XOR l= expr r= expr ) | ^(t= OP_BOOL_AND l= expr r= expr ) | ^(t= OP_OR l= expr r= expr ) | ^(t= OP_XOR l= expr r= expr ) | ^(t= OP_AND l= expr r= expr ) | ^(t= OP_EQUAL l= expr r= expr ) | ^(t= OP_NOTEQUAL l= expr r= expr ) | ^(t= OP_FEQUAL l= expr r= expr ) | ^(t= OP_FNOTEQUAL l= expr r= expr ) | ^(t= OP_LESS l= expr r= expr ) | ^(t= OP_GREATEQUAL l= expr r= expr ) | ^(t= OP_LESSEQUAL l= expr r= expr ) | ^(t= OP_GREAT l= expr r= expr ) | ^(t= OP_SLESS l= expr r= expr ) | ^(t= OP_SGREATEQUAL l= expr r= expr ) | ^(t= OP_SLESSEQUAL l= expr r= expr ) | ^(t= OP_SGREAT l= expr r= expr ) | ^(t= OP_FLESS l= expr r= expr ) | ^(t= OP_FGREATEQUAL l= expr r= expr ) | ^(t= OP_FLESSEQUAL l= expr r= expr ) | ^(t= OP_FGREAT l= expr r= expr ) | ^(t= OP_LEFT l= expr r= expr ) | ^(t= OP_RIGHT l= expr r= expr ) | ^(t= OP_SRIGHT l= expr r= expr ) | ^(t= OP_ADD l= expr r= expr ) | ^(t= OP_SUB l= expr r= expr ) | ^(t= OP_FADD l= expr r= expr ) | ^(t= OP_FSUB l= expr r= expr ) | ^(t= OP_MULT l= expr r= expr ) | ^(t= OP_DIV l= expr r= expr ) | ^(t= OP_REM l= expr r= expr ) | ^(t= OP_SDIV l= expr r= expr ) | ^(t= OP_SREM l= expr r= expr ) | ^(t= OP_FMULT l= expr r= expr ) | ^(t= OP_FDIV l= expr r= expr ) | ^(t= OP_NOT l= expr ) | ^(t= OP_INVERT l= expr ) | ^(t= OP_NEGATE l= expr ) | ^(t= OP_FNEGATE l= expr ) |s= sizedstar |a= expr_apply |v= varnode |b= bitrange |i= integer | ^( OP_PARENTHESIZED l= expr ) | ^(t= OP_BITRANGE2 ss= specific_symbol[\"expression\"] i= integer ) )
			int alt61=47;
			switch ( input.LA(1) ) {
			case OP_BOOL_OR:
				{
				alt61=1;
				}
				break;
			case OP_BOOL_XOR:
				{
				alt61=2;
				}
				break;
			case OP_BOOL_AND:
				{
				alt61=3;
				}
				break;
			case OP_OR:
				{
				alt61=4;
				}
				break;
			case OP_XOR:
				{
				alt61=5;
				}
				break;
			case OP_AND:
				{
				alt61=6;
				}
				break;
			case OP_EQUAL:
				{
				alt61=7;
				}
				break;
			case OP_NOTEQUAL:
				{
				alt61=8;
				}
				break;
			case OP_FEQUAL:
				{
				alt61=9;
				}
				break;
			case OP_FNOTEQUAL:
				{
				alt61=10;
				}
				break;
			case OP_LESS:
				{
				alt61=11;
				}
				break;
			case OP_GREATEQUAL:
				{
				alt61=12;
				}
				break;
			case OP_LESSEQUAL:
				{
				alt61=13;
				}
				break;
			case OP_GREAT:
				{
				alt61=14;
				}
				break;
			case OP_SLESS:
				{
				alt61=15;
				}
				break;
			case OP_SGREATEQUAL:
				{
				alt61=16;
				}
				break;
			case OP_SLESSEQUAL:
				{
				alt61=17;
				}
				break;
			case OP_SGREAT:
				{
				alt61=18;
				}
				break;
			case OP_FLESS:
				{
				alt61=19;
				}
				break;
			case OP_FGREATEQUAL:
				{
				alt61=20;
				}
				break;
			case OP_FLESSEQUAL:
				{
				alt61=21;
				}
				break;
			case OP_FGREAT:
				{
				alt61=22;
				}
				break;
			case OP_LEFT:
				{
				alt61=23;
				}
				break;
			case OP_RIGHT:
				{
				alt61=24;
				}
				break;
			case OP_SRIGHT:
				{
				alt61=25;
				}
				break;
			case OP_ADD:
				{
				alt61=26;
				}
				break;
			case OP_SUB:
				{
				alt61=27;
				}
				break;
			case OP_FADD:
				{
				alt61=28;
				}
				break;
			case OP_FSUB:
				{
				alt61=29;
				}
				break;
			case OP_MULT:
				{
				alt61=30;
				}
				break;
			case OP_DIV:
				{
				alt61=31;
				}
				break;
			case OP_REM:
				{
				alt61=32;
				}
				break;
			case OP_SDIV:
				{
				alt61=33;
				}
				break;
			case OP_SREM:
				{
				alt61=34;
				}
				break;
			case OP_FMULT:
				{
				alt61=35;
				}
				break;
			case OP_FDIV:
				{
				alt61=36;
				}
				break;
			case OP_NOT:
				{
				alt61=37;
				}
				break;
			case OP_INVERT:
				{
				alt61=38;
				}
				break;
			case OP_NEGATE:
				{
				alt61=39;
				}
				break;
			case OP_FNEGATE:
				{
				alt61=40;
				}
				break;
			case OP_DEREFERENCE:
				{
				alt61=41;
				}
				break;
			case OP_APPLY:
				{
				alt61=42;
				}
				break;
			case OP_ADDRESS_OF:
			case OP_IDENTIFIER:
			case OP_TRUNCATION_SIZE:
			case OP_WILDCARD:
				{
				alt61=43;
				}
				break;
			case OP_BITRANGE:
				{
				alt61=44;
				}
				break;
			case OP_BIN_CONSTANT:
			case OP_DEC_CONSTANT:
			case OP_HEX_CONSTANT:
				{
				alt61=45;
				}
				break;
			case OP_PARENTHESIZED:
				{
				alt61=46;
				}
				break;
			case OP_BITRANGE2:
				{
				alt61=47;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 61, 0, input);
				throw nvae;
			}
			switch (alt61) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1368:4: ^(t= OP_BOOL_OR l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_BOOL_OR,FOLLOW_OP_BOOL_OR_in_expr4114); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4118);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4122);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_BOOL_OR,l,r); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1369:4: ^(t= OP_BOOL_XOR l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_BOOL_XOR,FOLLOW_OP_BOOL_XOR_in_expr4133); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4137);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4141);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_BOOL_XOR,l,r); 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1370:4: ^(t= OP_BOOL_AND l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_BOOL_AND,FOLLOW_OP_BOOL_AND_in_expr4152); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4156);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4160);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_BOOL_AND,l,r); 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1372:4: ^(t= OP_OR l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_OR,FOLLOW_OP_OR_in_expr4172); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4176);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4180);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_OR,l,r); 
					}
					break;
				case 5 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1373:4: ^(t= OP_XOR l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_XOR,FOLLOW_OP_XOR_in_expr4191); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4195);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4199);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_XOR,l,r); 
					}
					break;
				case 6 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1374:4: ^(t= OP_AND l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_AND,FOLLOW_OP_AND_in_expr4210); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4214);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4218);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_AND,l,r); 
					}
					break;
				case 7 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1376:4: ^(t= OP_EQUAL l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_EQUAL,FOLLOW_OP_EQUAL_in_expr4230); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4234);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4238);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_EQUAL,l,r); 
					}
					break;
				case 8 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1377:4: ^(t= OP_NOTEQUAL l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_NOTEQUAL,FOLLOW_OP_NOTEQUAL_in_expr4249); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4253);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4257);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_NOTEQUAL,l,r); 
					}
					break;
				case 9 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1378:4: ^(t= OP_FEQUAL l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_FEQUAL,FOLLOW_OP_FEQUAL_in_expr4268); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4272);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4276);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_EQUAL,l,r); 
					}
					break;
				case 10 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1379:4: ^(t= OP_FNOTEQUAL l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_FNOTEQUAL,FOLLOW_OP_FNOTEQUAL_in_expr4287); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4291);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4295);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_NOTEQUAL,l,r); 
					}
					break;
				case 11 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1381:4: ^(t= OP_LESS l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_LESS,FOLLOW_OP_LESS_in_expr4307); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4311);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4315);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_LESS,l,r); 
					}
					break;
				case 12 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1382:4: ^(t= OP_GREATEQUAL l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_GREATEQUAL,FOLLOW_OP_GREATEQUAL_in_expr4326); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4330);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4334);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_LESSEQUAL,r,l); 
					}
					break;
				case 13 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1383:4: ^(t= OP_LESSEQUAL l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_LESSEQUAL,FOLLOW_OP_LESSEQUAL_in_expr4345); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4349);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4353);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_LESSEQUAL,l,r); 
					}
					break;
				case 14 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1384:4: ^(t= OP_GREAT l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_GREAT,FOLLOW_OP_GREAT_in_expr4364); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4368);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4372);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_LESS,r,l); 
					}
					break;
				case 15 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1385:4: ^(t= OP_SLESS l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_SLESS,FOLLOW_OP_SLESS_in_expr4383); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4387);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4391);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_SLESS,l,r); 
					}
					break;
				case 16 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1386:4: ^(t= OP_SGREATEQUAL l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_SGREATEQUAL,FOLLOW_OP_SGREATEQUAL_in_expr4402); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4406);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4410);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_SLESSEQUAL,r,l); 
					}
					break;
				case 17 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1387:4: ^(t= OP_SLESSEQUAL l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_SLESSEQUAL,FOLLOW_OP_SLESSEQUAL_in_expr4421); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4425);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4429);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_SLESSEQUAL,l,r); 
					}
					break;
				case 18 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1388:4: ^(t= OP_SGREAT l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_SGREAT,FOLLOW_OP_SGREAT_in_expr4440); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4444);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4448);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_SLESS,r,l); 
					}
					break;
				case 19 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1389:4: ^(t= OP_FLESS l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_FLESS,FOLLOW_OP_FLESS_in_expr4459); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4463);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4467);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_LESS,l,r); 
					}
					break;
				case 20 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1390:4: ^(t= OP_FGREATEQUAL l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_FGREATEQUAL,FOLLOW_OP_FGREATEQUAL_in_expr4478); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4482);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4486);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_LESSEQUAL,r,l); 
					}
					break;
				case 21 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1391:4: ^(t= OP_FLESSEQUAL l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_FLESSEQUAL,FOLLOW_OP_FLESSEQUAL_in_expr4497); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4501);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4505);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_LESSEQUAL,l,r); 
					}
					break;
				case 22 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1392:4: ^(t= OP_FGREAT l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_FGREAT,FOLLOW_OP_FGREAT_in_expr4516); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4520);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4524);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_LESS,r,l); 
					}
					break;
				case 23 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1394:4: ^(t= OP_LEFT l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_LEFT,FOLLOW_OP_LEFT_in_expr4536); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4540);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4544);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_LEFT,l,r); 
					}
					break;
				case 24 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1395:4: ^(t= OP_RIGHT l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_RIGHT,FOLLOW_OP_RIGHT_in_expr4555); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4559);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4563);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_RIGHT,l,r); 
					}
					break;
				case 25 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1396:4: ^(t= OP_SRIGHT l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_SRIGHT,FOLLOW_OP_SRIGHT_in_expr4574); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4578);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4582);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_SRIGHT,l,r); 
					}
					break;
				case 26 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1398:4: ^(t= OP_ADD l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_ADD,FOLLOW_OP_ADD_in_expr4594); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4598);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4602);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_ADD,l,r); 
					}
					break;
				case 27 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1399:4: ^(t= OP_SUB l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_SUB,FOLLOW_OP_SUB_in_expr4613); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4617);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4621);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_SUB,l,r); 
					}
					break;
				case 28 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1400:4: ^(t= OP_FADD l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_FADD,FOLLOW_OP_FADD_in_expr4632); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4636);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4640);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_ADD,l,r); 
					}
					break;
				case 29 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1401:4: ^(t= OP_FSUB l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_FSUB,FOLLOW_OP_FSUB_in_expr4651); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4655);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4659);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_SUB,l,r); 
					}
					break;
				case 30 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1403:4: ^(t= OP_MULT l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_MULT,FOLLOW_OP_MULT_in_expr4671); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4675);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4679);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_MULT,l,r); 
					}
					break;
				case 31 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1404:4: ^(t= OP_DIV l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_DIV,FOLLOW_OP_DIV_in_expr4690); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4694);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4698);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_DIV,l,r); 
					}
					break;
				case 32 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1405:4: ^(t= OP_REM l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_REM,FOLLOW_OP_REM_in_expr4709); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4713);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4717);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_REM,l,r); 
					}
					break;
				case 33 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1406:4: ^(t= OP_SDIV l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_SDIV,FOLLOW_OP_SDIV_in_expr4728); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4732);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4736);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_SDIV,l,r); 
					}
					break;
				case 34 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1407:4: ^(t= OP_SREM l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_SREM,FOLLOW_OP_SREM_in_expr4747); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4751);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4755);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_SREM,l,r); 
					}
					break;
				case 35 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1408:4: ^(t= OP_FMULT l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_FMULT,FOLLOW_OP_FMULT_in_expr4766); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4770);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4774);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_MULT,l,r); 
					}
					break;
				case 36 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1409:4: ^(t= OP_FDIV l= expr r= expr )
					{
					t=(CommonTree)match(input,OP_FDIV,FOLLOW_OP_FDIV_in_expr4785); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4789);
					l=expr();
					state._fsp--;

					pushFollow(FOLLOW_expr_in_expr4793);
					r=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_DIV,l,r); 
					}
					break;
				case 37 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1411:4: ^(t= OP_NOT l= expr )
					{
					t=(CommonTree)match(input,OP_NOT,FOLLOW_OP_NOT_in_expr4805); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4809);
					l=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_BOOL_NEGATE,l); 
					}
					break;
				case 38 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1412:4: ^(t= OP_INVERT l= expr )
					{
					t=(CommonTree)match(input,OP_INVERT,FOLLOW_OP_INVERT_in_expr4820); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4824);
					l=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_NEGATE,l); 
					}
					break;
				case 39 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1413:4: ^(t= OP_NEGATE l= expr )
					{
					t=(CommonTree)match(input,OP_NEGATE,FOLLOW_OP_NEGATE_in_expr4835); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4839);
					l=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_INT_2COMP,l); 
					}
					break;
				case 40 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1414:4: ^(t= OP_FNEGATE l= expr )
					{
					t=(CommonTree)match(input,OP_FNEGATE,FOLLOW_OP_FNEGATE_in_expr4850); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4854);
					l=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_NEG,l); 
					}
					break;
				case 41 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1415:4: s= sizedstar
					{
					pushFollow(FOLLOW_sizedstar_in_expr4864);
					s=sizedstar();
					state._fsp--;

					 value = pcode.createLoad(s.first.location, s.first, s.second); 
					}
					break;
				case 42 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1417:4: a= expr_apply
					{
					pushFollow(FOLLOW_expr_apply_in_expr4874);
					a=expr_apply();
					state._fsp--;

					 value = (ExprTree) a; 
					}
					break;
				case 43 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1418:4: v= varnode
					{
					pushFollow(FOLLOW_varnode_in_expr4883);
					v=varnode();
					state._fsp--;

					 value = new ExprTree(v.location, v); 
					}
					break;
				case 44 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1419:4: b= bitrange
					{
					pushFollow(FOLLOW_bitrange_in_expr4892);
					b=bitrange();
					state._fsp--;

					 value = b; 
					}
					break;
				case 45 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1420:4: i= integer
					{
					pushFollow(FOLLOW_integer_in_expr4901);
					i=integer();
					state._fsp--;

					 value = new ExprTree(i.location, new VarnodeTpl(i.location, new ConstTpl(pcode.getConstantSpace()),
									new ConstTpl(ConstTpl.const_type.real, i.longValue()),
									new ConstTpl(ConstTpl.const_type.real, 0)));
							
					}
					break;
				case 46 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1424:4: ^( OP_PARENTHESIZED l= expr )
					{
					match(input,OP_PARENTHESIZED,FOLLOW_OP_PARENTHESIZED_in_expr4909); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_expr_in_expr4913);
					l=expr();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = l; 
					}
					break;
				case 47 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1426:4: ^(t= OP_BITRANGE2 ss= specific_symbol[\"expression\"] i= integer )
					{
					t=(CommonTree)match(input,OP_BITRANGE2,FOLLOW_OP_BITRANGE2_in_expr4925); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_specific_symbol_in_expr4929);
					ss=specific_symbol("expression");
					state._fsp--;

					pushFollow(FOLLOW_integer_in_expr4934);
					i=integer();
					state._fsp--;

					match(input, Token.UP, null); 


								value = pcode.createBitRange(find(t), ss, 0, (i.intValue() * 8));
							
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "expr"



	// $ANTLR start "expr_apply"
	// ghidra/sleigh/grammar/SleighCompiler.g:1431:1: expr_apply returns [Object value] : ( ^(x= OP_APPLY ^(t= OP_IDENTIFIER s= . ) o= expr_operands ) | ^(x= OP_APPLY t= OP_WILDCARD o= expr_operands ) );
	public final Object expr_apply() throws RecognitionException {
		Object value = null;


		CommonTree x=null;
		CommonTree t=null;
		CommonTree s=null;
		VectorSTL<ExprTree> o =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1435:2: ( ^(x= OP_APPLY ^(t= OP_IDENTIFIER s= . ) o= expr_operands ) | ^(x= OP_APPLY t= OP_WILDCARD o= expr_operands ) )
			int alt62=2;
			int LA62_0 = input.LA(1);
			if ( (LA62_0==OP_APPLY) ) {
				int LA62_1 = input.LA(2);
				if ( (LA62_1==DOWN) ) {
					int LA62_2 = input.LA(3);
					if ( (LA62_2==OP_IDENTIFIER) ) {
						alt62=1;
					}
					else if ( (LA62_2==OP_WILDCARD) ) {
						alt62=2;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 62, 2, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 62, 1, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 62, 0, input);
				throw nvae;
			}

			switch (alt62) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1435:4: ^(x= OP_APPLY ^(t= OP_IDENTIFIER s= . ) o= expr_operands )
					{
					x=(CommonTree)match(input,OP_APPLY,FOLLOW_OP_APPLY_in_expr_apply4961); 
					match(input, Token.DOWN, null); 
					t=(CommonTree)match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_expr_apply4966); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					pushFollow(FOLLOW_expr_operands_in_expr_apply4975);
					o=expr_operands();
					state._fsp--;

					match(input, Token.UP, null); 


								Object internalFunction = pcode.findInternalFunction(find(s), s.getText(), o);
								if (internalFunction == null) {
									SleighSymbol sym = pcode.findSymbol(s.getText());
									if (sym == null) {
										unknownSymbolError(s.getText(), find(s), "macro, userop, or specific symbol", "macro, user operation, or subpiece application");
									} else if(sym.getType() == symbol_type.userop_symbol) {
										if(Return_stack.peek().noReturn) {
											value = pcode.createUserOpNoOut(find(s), (UserOpSymbol) sym, o);
										} else {
											value = pcode.createUserOp((UserOpSymbol) sym, o);
										}
									} else if(sym.getType() == symbol_type.macro_symbol) {
										if(Return_stack.peek().noReturn) {
											value = pcode.createMacroUse(find(x), (MacroSymbol) sym, o);
										} else {
											pcode.reportError(find(t), "macro invocation not allowed as expression");
										}
									} else if(sym.getType() == symbol_type.start_symbol
										|| sym.getType() == symbol_type.end_symbol
										|| sym.getType() == symbol_type.operand_symbol
										|| sym.getType() == symbol_type.epsilon_symbol
										|| sym.getType() == symbol_type.varnode_symbol) {
										if (o.size() != 1) {
											pcode.reportError(find(t), "subpiece operation requires a single operand");
										} else {
											value = pcode.createOp(find(s), OpCode.CPUI_SUBPIECE,new ExprTree(find(s), ((SpecificSymbol)sym).getVarnode()), o.get(0));
										}
									} else {
										wrongSymbolTypeError(sym, find(s), "macro, userop, or specific symbol", "macro, user operation, or subpiece application");
									}
								} else {
									value = internalFunction;
								}
							
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1470:4: ^(x= OP_APPLY t= OP_WILDCARD o= expr_operands )
					{
					x=(CommonTree)match(input,OP_APPLY,FOLLOW_OP_APPLY_in_expr_apply4986); 
					match(input, Token.DOWN, null); 
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_expr_apply4990); 
					pushFollow(FOLLOW_expr_operands_in_expr_apply4994);
					o=expr_operands();
					state._fsp--;

					match(input, Token.UP, null); 


								wildcardError(t, "function application");
							
					}
					break;

			}

					code_block_stack.peek().stmtLocation = find(x);
				
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "expr_apply"



	// $ANTLR start "expr_operands"
	// ghidra/sleigh/grammar/SleighCompiler.g:1475:1: expr_operands returns [VectorSTL<ExprTree> value] : (e= expr )* ;
	public final VectorSTL<ExprTree> expr_operands() throws RecognitionException {
		VectorSTL<ExprTree> value = null;


		ExprTree e =null;


				value = new VectorSTL<ExprTree>();
			
		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1479:2: ( (e= expr )* )
			// ghidra/sleigh/grammar/SleighCompiler.g:1479:4: (e= expr )*
			{
			// ghidra/sleigh/grammar/SleighCompiler.g:1479:4: (e= expr )*
			loop63:
			while (true) {
				int alt63=2;
				int LA63_0 = input.LA(1);
				if ( ((LA63_0 >= OP_ADD && LA63_0 <= OP_ADDRESS_OF)||(LA63_0 >= OP_AND && LA63_0 <= OP_APPLY)||(LA63_0 >= OP_BIN_CONSTANT && LA63_0 <= OP_BITRANGE2)||(LA63_0 >= OP_BOOL_AND && LA63_0 <= OP_BOOL_XOR)||LA63_0==OP_DEC_CONSTANT||LA63_0==OP_DEREFERENCE||LA63_0==OP_DIV||LA63_0==OP_EQUAL||(LA63_0 >= OP_FADD && LA63_0 <= OP_FGREATEQUAL)||(LA63_0 >= OP_FLESS && LA63_0 <= OP_FSUB)||(LA63_0 >= OP_GREAT && LA63_0 <= OP_GREATEQUAL)||(LA63_0 >= OP_HEX_CONSTANT && LA63_0 <= OP_IDENTIFIER)||LA63_0==OP_INVERT||(LA63_0 >= OP_LEFT && LA63_0 <= OP_LESSEQUAL)||LA63_0==OP_MULT||LA63_0==OP_NEGATE||(LA63_0 >= OP_NOT && LA63_0 <= OP_NOTEQUAL)||(LA63_0 >= OP_OR && LA63_0 <= OP_PARENTHESIZED)||LA63_0==OP_REM||(LA63_0 >= OP_RIGHT && LA63_0 <= OP_SDIV)||(LA63_0 >= OP_SGREAT && LA63_0 <= OP_SGREATEQUAL)||(LA63_0 >= OP_SLESS && LA63_0 <= OP_SLESSEQUAL)||(LA63_0 >= OP_SREM && LA63_0 <= OP_SRIGHT)||LA63_0==OP_SUB||LA63_0==OP_TRUNCATION_SIZE||LA63_0==OP_WILDCARD||LA63_0==OP_XOR) ) {
					alt63=1;
				}

				switch (alt63) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1479:5: e= expr
					{
					pushFollow(FOLLOW_expr_in_expr_operands5021);
					e=expr();
					state._fsp--;

					 value.push_back(e); 
					}
					break;

				default :
					break loop63;
				}
			}

			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "expr_operands"



	// $ANTLR start "varnode"
	// ghidra/sleigh/grammar/SleighCompiler.g:1482:1: varnode returns [VarnodeTpl value] : (ss= specific_symbol[\"varnode reference\"] | ^(t= OP_TRUNCATION_SIZE n= integer m= integer ) | ^( OP_ADDRESS_OF ^( OP_SIZING_SIZE i= integer ) v= varnode ) | ^( OP_ADDRESS_OF v= varnode ) );
	public final VarnodeTpl varnode() throws RecognitionException {
		VarnodeTpl value = null;


		CommonTree t=null;
		SpecificSymbol ss =null;
		RadixBigInteger n =null;
		RadixBigInteger m =null;
		RadixBigInteger i =null;
		VarnodeTpl v =null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1483:2: (ss= specific_symbol[\"varnode reference\"] | ^(t= OP_TRUNCATION_SIZE n= integer m= integer ) | ^( OP_ADDRESS_OF ^( OP_SIZING_SIZE i= integer ) v= varnode ) | ^( OP_ADDRESS_OF v= varnode ) )
			int alt64=4;
			switch ( input.LA(1) ) {
			case OP_IDENTIFIER:
			case OP_WILDCARD:
				{
				alt64=1;
				}
				break;
			case OP_TRUNCATION_SIZE:
				{
				alt64=2;
				}
				break;
			case OP_ADDRESS_OF:
				{
				int LA64_3 = input.LA(2);
				if ( (LA64_3==DOWN) ) {
					int LA64_4 = input.LA(3);
					if ( (LA64_4==OP_SIZING_SIZE) ) {
						alt64=3;
					}
					else if ( (LA64_4==OP_ADDRESS_OF||LA64_4==OP_IDENTIFIER||LA64_4==OP_TRUNCATION_SIZE||LA64_4==OP_WILDCARD) ) {
						alt64=4;
					}

					else {
						int nvaeMark = input.mark();
						try {
							for (int nvaeConsume = 0; nvaeConsume < 3 - 1; nvaeConsume++) {
								input.consume();
							}
							NoViableAltException nvae =
								new NoViableAltException("", 64, 4, input);
							throw nvae;
						} finally {
							input.rewind(nvaeMark);
						}
					}

				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 64, 3, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 64, 0, input);
				throw nvae;
			}
			switch (alt64) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1483:4: ss= specific_symbol[\"varnode reference\"]
					{
					pushFollow(FOLLOW_specific_symbol_in_varnode5042);
					ss=specific_symbol("varnode reference");
					state._fsp--;

					 value = ss.getVarnode(); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1484:4: ^(t= OP_TRUNCATION_SIZE n= integer m= integer )
					{
					t=(CommonTree)match(input,OP_TRUNCATION_SIZE,FOLLOW_OP_TRUNCATION_SIZE_in_varnode5053); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_integer_in_varnode5057);
					n=integer();
					state._fsp--;

					pushFollow(FOLLOW_integer_in_varnode5061);
					m=integer();
					state._fsp--;

					match(input, Token.UP, null); 


								if (m.longValue() > 8) {
									reportError(find(t), "Constant varnode size must not exceed 8 (" +
									n.longValue() + ":" + m.longValue() + ")");
								}
								value = new VarnodeTpl(find(t), new ConstTpl(pcode.getConstantSpace()),
									new ConstTpl(ConstTpl.const_type.real, n.longValue()),
									new ConstTpl(ConstTpl.const_type.real, m.longValue()));
							
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1493:4: ^( OP_ADDRESS_OF ^( OP_SIZING_SIZE i= integer ) v= varnode )
					{
					match(input,OP_ADDRESS_OF,FOLLOW_OP_ADDRESS_OF_in_varnode5070); 
					match(input, Token.DOWN, null); 
					match(input,OP_SIZING_SIZE,FOLLOW_OP_SIZING_SIZE_in_varnode5073); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_integer_in_varnode5077);
					i=integer();
					state._fsp--;

					match(input, Token.UP, null); 

					pushFollow(FOLLOW_varnode_in_varnode5082);
					v=varnode();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.addressOf(v, i.intValue()); 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1494:4: ^( OP_ADDRESS_OF v= varnode )
					{
					match(input,OP_ADDRESS_OF,FOLLOW_OP_ADDRESS_OF_in_varnode5091); 
					match(input, Token.DOWN, null); 
					pushFollow(FOLLOW_varnode_in_varnode5095);
					v=varnode();
					state._fsp--;

					match(input, Token.UP, null); 

					 value = pcode.addressOf(v, 0); 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "varnode"



	// $ANTLR start "qstring"
	// ghidra/sleigh/grammar/SleighCompiler.g:1497:1: qstring returns [String value] : ^( OP_QSTRING s= . ) ;
	public final String qstring() throws RecognitionException {
		String value = null;


		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1498:2: ( ^( OP_QSTRING s= . ) )
			// ghidra/sleigh/grammar/SleighCompiler.g:1498:4: ^( OP_QSTRING s= . )
			{
			match(input,OP_QSTRING,FOLLOW_OP_QSTRING_in_qstring5114); 
			match(input, Token.DOWN, null); 
			s=(CommonTree)input.LT(1);
			matchAny(input); 
			match(input, Token.UP, null); 

			 value = s.getText(); 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "qstring"


	public static class identifier_return extends TreeRuleReturnScope {
		public String value;
		public Tree tree;
	};


	// $ANTLR start "identifier"
	// ghidra/sleigh/grammar/SleighCompiler.g:1501:1: identifier returns [String value, Tree tree] : ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD );
	public final SleighCompiler.identifier_return identifier() throws RecognitionException {
		SleighCompiler.identifier_return retval = new SleighCompiler.identifier_return();
		retval.start = input.LT(1);

		CommonTree t=null;
		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1502:2: ( ^( OP_IDENTIFIER s= . ) |t= OP_WILDCARD )
			int alt65=2;
			int LA65_0 = input.LA(1);
			if ( (LA65_0==OP_IDENTIFIER) ) {
				alt65=1;
			}
			else if ( (LA65_0==OP_WILDCARD) ) {
				alt65=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 65, 0, input);
				throw nvae;
			}

			switch (alt65) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1502:4: ^( OP_IDENTIFIER s= . )
					{
					match(input,OP_IDENTIFIER,FOLLOW_OP_IDENTIFIER_in_identifier5137); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					 retval.value = s.getText(); retval.tree = s; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1503:4: t= OP_WILDCARD
					{
					t=(CommonTree)match(input,OP_WILDCARD,FOLLOW_OP_WILDCARD_in_identifier5151); 
					 retval.value = null; retval.tree = s; 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return retval;
	}
	// $ANTLR end "identifier"



	// $ANTLR start "integer"
	// ghidra/sleigh/grammar/SleighCompiler.g:1506:1: integer returns [RadixBigInteger value] : ( ^( OP_HEX_CONSTANT s= . ) | ^( OP_DEC_CONSTANT s= . ) | ^( OP_BIN_CONSTANT s= . ) );
	public final RadixBigInteger integer() throws RecognitionException {
		RadixBigInteger value = null;


		CommonTree s=null;

		try {
			// ghidra/sleigh/grammar/SleighCompiler.g:1507:2: ( ^( OP_HEX_CONSTANT s= . ) | ^( OP_DEC_CONSTANT s= . ) | ^( OP_BIN_CONSTANT s= . ) )
			int alt66=3;
			switch ( input.LA(1) ) {
			case OP_HEX_CONSTANT:
				{
				alt66=1;
				}
				break;
			case OP_DEC_CONSTANT:
				{
				alt66=2;
				}
				break;
			case OP_BIN_CONSTANT:
				{
				alt66=3;
				}
				break;
			default:
				NoViableAltException nvae =
					new NoViableAltException("", 66, 0, input);
				throw nvae;
			}
			switch (alt66) {
				case 1 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1507:4: ^( OP_HEX_CONSTANT s= . )
					{
					match(input,OP_HEX_CONSTANT,FOLLOW_OP_HEX_CONSTANT_in_integer5169); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					 value = new RadixBigInteger(find(s), s.getText().substring(2), 16); check(value); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1508:4: ^( OP_DEC_CONSTANT s= . )
					{
					match(input,OP_DEC_CONSTANT,FOLLOW_OP_DEC_CONSTANT_in_integer5182); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					 value = new RadixBigInteger(find(s), s.getText()); check(value); 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/SleighCompiler.g:1509:4: ^( OP_BIN_CONSTANT s= . )
					{
					match(input,OP_BIN_CONSTANT,FOLLOW_OP_BIN_CONSTANT_in_integer5195); 
					match(input, Token.DOWN, null); 
					s=(CommonTree)input.LT(1);
					matchAny(input); 
					match(input, Token.UP, null); 

					 value = new RadixBigInteger(find(s), s.getText().substring(2), 2); check(value); 
					}
					break;

			}
		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return value;
	}
	// $ANTLR end "integer"

	// Delegated rules


	protected DFA51 dfa51 = new DFA51(this);
	protected DFA56 dfa56 = new DFA56(this);
	protected DFA57 dfa57 = new DFA57(this);
	static final String DFA51_eotS =
		"\15\uffff";
	static final String DFA51_eofS =
		"\15\uffff";
	static final String DFA51_minS =
		"\1\u009a\1\2\1\u008b\1\2\1\3\1\4\2\uffff\1\2\1\4\3\3";
	static final String DFA51_maxS =
		"\1\u009a\1\2\1\u00cb\1\2\1\u008a\1\u00ed\2\uffff\1\3\1\u00ed\1\u008a\1"+
		"\u00ed\1\3";
	static final String DFA51_acceptS =
		"\6\uffff\1\1\1\2\5\uffff";
	static final String DFA51_specialS =
		"\15\uffff}>";
	static final String[] DFA51_transitionS = {
			"\1\1",
			"\1\2",
			"\1\3\77\uffff\1\4",
			"\1\5",
			"\1\7\127\uffff\1\6\21\uffff\1\6\34\uffff\1\6",
			"\u00ea\10",
			"",
			"",
			"\1\11\1\12",
			"\u00ea\13",
			"\1\7\127\uffff\1\6\21\uffff\1\6\34\uffff\1\6",
			"\1\14\u00ea\13",
			"\1\12"
	};

	static final short[] DFA51_eot = DFA.unpackEncodedString(DFA51_eotS);
	static final short[] DFA51_eof = DFA.unpackEncodedString(DFA51_eofS);
	static final char[] DFA51_min = DFA.unpackEncodedStringToUnsignedChars(DFA51_minS);
	static final char[] DFA51_max = DFA.unpackEncodedStringToUnsignedChars(DFA51_maxS);
	static final short[] DFA51_accept = DFA.unpackEncodedString(DFA51_acceptS);
	static final short[] DFA51_special = DFA.unpackEncodedString(DFA51_specialS);
	static final short[][] DFA51_transition;

	static {
		int numStates = DFA51_transitionS.length;
		DFA51_transition = new short[numStates][];
		for (int i=0; i<numStates; i++) {
			DFA51_transition[i] = DFA.unpackEncodedString(DFA51_transitionS[i]);
		}
	}

	protected class DFA51 extends DFA {

		public DFA51(BaseRecognizer recognizer) {
			this.recognizer = recognizer;
			this.decisionNumber = 51;
			this.eot = DFA51_eot;
			this.eof = DFA51_eof;
			this.min = DFA51_min;
			this.max = DFA51_max;
			this.accept = DFA51_accept;
			this.special = DFA51_special;
			this.transition = DFA51_transition;
		}
		@Override
		public String getDescription() {
			return "1066:1: declaration : ( ^( OP_LOCAL n= unbound_identifier[\"sized local declaration\"] i= integer ) | ^( OP_LOCAL n= unbound_identifier[\"local declaration\"] ) );";
		}
	}

	static final String DFA56_eotS =
		"\71\uffff";
	static final String DFA56_eofS =
		"\71\uffff";
	static final String DFA56_minS =
		"\1\157\1\2\1\123\1\2\1\3\3\2\1\uffff\1\4\3\2\1\uffff\3\4\1\2\3\4\3\2\1"+
		"\4\1\3\3\2\1\4\1\3\1\4\1\3\1\4\2\3\1\4\1\3\1\4\1\3\1\4\2\3\1\uffff\4\3"+
		"\1\uffff\10\3";
	static final String DFA56_maxS =
		"\1\157\1\2\1\u00ce\1\2\1\u00ce\3\2\1\uffff\1\u00ed\3\2\1\uffff\3\u00ed"+
		"\1\3\3\u00ed\3\3\1\u00ed\1\u00ce\3\3\1\u00ed\1\u00ce\1\u00ed\1\u00ce\1"+
		"\u00ed\1\u00ce\2\u00ed\1\u00ce\1\u00ed\1\u00ce\1\u00ed\1\u00ce\1\u00ed"+
		"\1\uffff\2\u00ed\1\3\1\u00ed\1\uffff\2\u00ed\6\3";
	static final String DFA56_acceptS =
		"\10\uffff\1\4\4\uffff\1\2\35\uffff\1\3\4\uffff\1\1\10\uffff";
	static final String DFA56_specialS =
		"\71\uffff}>";
	static final String[] DFA56_transitionS = {
			"\1\1",
			"\1\2",
			"\2\10\1\uffff\2\10\3\uffff\1\7\2\10\2\uffff\3\10\12\uffff\1\6\1\uffff"+
			"\1\10\1\uffff\1\10\4\uffff\1\10\1\uffff\5\10\3\uffff\6\10\1\uffff\2\10"+
			"\1\uffff\1\5\1\3\3\uffff\1\10\6\uffff\3\10\3\uffff\1\10\1\uffff\1\10"+
			"\3\uffff\2\10\3\uffff\2\10\3\uffff\1\10\1\uffff\2\10\3\uffff\2\10\3\uffff"+
			"\2\10\2\uffff\2\10\2\uffff\1\10\3\uffff\1\10\6\uffff\1\4\2\uffff\1\10",
			"\1\11",
			"\1\10\117\uffff\2\15\1\uffff\2\15\3\uffff\1\14\2\15\2\uffff\3\15\12"+
			"\uffff\1\13\1\uffff\1\15\1\uffff\1\15\4\uffff\1\15\1\uffff\5\15\3\uffff"+
			"\6\15\1\uffff\2\15\1\uffff\1\12\1\15\3\uffff\1\15\6\uffff\3\15\3\uffff"+
			"\1\15\1\uffff\1\15\3\uffff\2\15\3\uffff\2\15\3\uffff\1\15\1\uffff\2\15"+
			"\3\uffff\2\15\3\uffff\2\15\2\uffff\2\15\2\uffff\1\15\3\uffff\1\15\6\uffff"+
			"\1\15\2\uffff\1\15",
			"\1\16",
			"\1\17",
			"\1\20",
			"",
			"\u00ea\21",
			"\1\22",
			"\1\23",
			"\1\24",
			"",
			"\u00ea\25",
			"\u00ea\26",
			"\u00ea\27",
			"\1\30\1\31",
			"\u00ea\32",
			"\u00ea\33",
			"\u00ea\34",
			"\1\35\1\36",
			"\1\37\1\40",
			"\1\41\1\42",
			"\u00ea\43",
			"\1\10\117\uffff\2\15\1\uffff\2\15\3\uffff\1\14\2\15\2\uffff\3\15\12"+
			"\uffff\1\13\1\uffff\1\15\1\uffff\1\15\4\uffff\1\15\1\uffff\5\15\3\uffff"+
			"\6\15\1\uffff\2\15\1\uffff\1\12\1\15\3\uffff\1\15\6\uffff\3\15\3\uffff"+
			"\1\15\1\uffff\1\15\3\uffff\2\15\3\uffff\2\15\3\uffff\1\15\1\uffff\2\15"+
			"\3\uffff\2\15\3\uffff\2\15\2\uffff\2\15\2\uffff\1\15\3\uffff\1\15\6\uffff"+
			"\1\15\2\uffff\1\15",
			"\1\44\1\45",
			"\1\46\1\47",
			"\1\50\1\51",
			"\u00ea\52",
			"\1\10\117\uffff\2\53\1\uffff\2\53\3\uffff\3\53\2\uffff\3\53\12\uffff"+
			"\1\53\1\uffff\1\53\1\uffff\1\53\4\uffff\1\53\1\uffff\5\53\3\uffff\6\53"+
			"\1\uffff\2\53\1\uffff\2\53\3\uffff\1\53\6\uffff\3\53\3\uffff\1\53\1\uffff"+
			"\1\53\3\uffff\2\53\3\uffff\2\53\3\uffff\1\53\1\uffff\2\53\3\uffff\2\53"+
			"\3\uffff\2\53\2\uffff\2\53\2\uffff\1\53\3\uffff\1\53\6\uffff\1\53\2\uffff"+
			"\1\53",
			"\u00ea\54",
			"\1\10\117\uffff\2\53\1\uffff\2\53\3\uffff\3\53\2\uffff\3\53\12\uffff"+
			"\1\53\1\uffff\1\53\1\uffff\1\53\4\uffff\1\53\1\uffff\5\53\3\uffff\6\53"+
			"\1\uffff\2\53\1\uffff\2\53\3\uffff\1\53\6\uffff\3\53\3\uffff\1\53\1\uffff"+
			"\1\53\3\uffff\2\53\3\uffff\2\53\3\uffff\1\53\1\uffff\2\53\3\uffff\2\53"+
			"\3\uffff\2\53\2\uffff\2\53\2\uffff\1\53\3\uffff\1\53\6\uffff\1\53\2\uffff"+
			"\1\53",
			"\u00ea\55",
			"\1\10\117\uffff\2\53\1\uffff\2\53\3\uffff\3\53\2\uffff\3\53\12\uffff"+
			"\1\53\1\uffff\1\53\1\uffff\1\53\4\uffff\1\53\1\uffff\5\53\3\uffff\6\53"+
			"\1\uffff\2\53\1\uffff\2\53\3\uffff\1\53\6\uffff\3\53\3\uffff\1\53\1\uffff"+
			"\1\53\3\uffff\2\53\3\uffff\2\53\3\uffff\1\53\1\uffff\2\53\3\uffff\2\53"+
			"\3\uffff\2\53\2\uffff\2\53\2\uffff\1\53\3\uffff\1\53\6\uffff\1\53\2\uffff"+
			"\1\53",
			"\1\56\u00ea\43",
			"\u00ea\57",
			"\1\15\117\uffff\2\60\1\uffff\2\60\3\uffff\3\60\2\uffff\3\60\12\uffff"+
			"\1\60\1\uffff\1\60\1\uffff\1\60\4\uffff\1\60\1\uffff\5\60\3\uffff\6\60"+
			"\1\uffff\2\60\1\uffff\2\60\3\uffff\1\60\6\uffff\3\60\3\uffff\1\60\1\uffff"+
			"\1\60\3\uffff\2\60\3\uffff\2\60\3\uffff\1\60\1\uffff\2\60\3\uffff\2\60"+
			"\3\uffff\2\60\2\uffff\2\60\2\uffff\1\60\3\uffff\1\60\6\uffff\1\60\2\uffff"+
			"\1\60",
			"\u00ea\61",
			"\1\15\117\uffff\2\60\1\uffff\2\60\3\uffff\3\60\2\uffff\3\60\12\uffff"+
			"\1\60\1\uffff\1\60\1\uffff\1\60\4\uffff\1\60\1\uffff\5\60\3\uffff\6\60"+
			"\1\uffff\2\60\1\uffff\2\60\3\uffff\1\60\6\uffff\3\60\3\uffff\1\60\1\uffff"+
			"\1\60\3\uffff\2\60\3\uffff\2\60\3\uffff\1\60\1\uffff\2\60\3\uffff\2\60"+
			"\3\uffff\2\60\2\uffff\2\60\2\uffff\1\60\3\uffff\1\60\6\uffff\1\60\2\uffff"+
			"\1\60",
			"\u00ea\62",
			"\1\15\117\uffff\2\60\1\uffff\2\60\3\uffff\3\60\2\uffff\3\60\12\uffff"+
			"\1\60\1\uffff\1\60\1\uffff\1\60\4\uffff\1\60\1\uffff\5\60\3\uffff\6\60"+
			"\1\uffff\2\60\1\uffff\2\60\3\uffff\1\60\6\uffff\3\60\3\uffff\1\60\1\uffff"+
			"\1\60\3\uffff\2\60\3\uffff\2\60\3\uffff\1\60\1\uffff\2\60\3\uffff\2\60"+
			"\3\uffff\2\60\2\uffff\2\60\2\uffff\1\60\3\uffff\1\60\6\uffff\1\60\2\uffff"+
			"\1\60",
			"\1\63\u00ea\52",
			"",
			"\1\64\u00ea\54",
			"\1\65\u00ea\55",
			"\1\31",
			"\1\66\u00ea\57",
			"",
			"\1\67\u00ea\61",
			"\1\70\u00ea\62",
			"\1\36",
			"\1\40",
			"\1\42",
			"\1\45",
			"\1\47",
			"\1\51"
	};

	static final short[] DFA56_eot = DFA.unpackEncodedString(DFA56_eotS);
	static final short[] DFA56_eof = DFA.unpackEncodedString(DFA56_eofS);
	static final char[] DFA56_min = DFA.unpackEncodedStringToUnsignedChars(DFA56_minS);
	static final char[] DFA56_max = DFA.unpackEncodedStringToUnsignedChars(DFA56_maxS);
	static final short[] DFA56_accept = DFA.unpackEncodedString(DFA56_acceptS);
	static final short[] DFA56_special = DFA.unpackEncodedString(DFA56_specialS);
	static final short[][] DFA56_transition;

	static {
		int numStates = DFA56_transitionS.length;
		DFA56_transition = new short[numStates][];
		for (int i=0; i<numStates; i++) {
			DFA56_transition[i] = DFA.unpackEncodedString(DFA56_transitionS[i]);
		}
	}

	protected class DFA56 extends DFA {

		public DFA56(BaseRecognizer recognizer) {
			this.recognizer = recognizer;
			this.decisionNumber = 56;
			this.eot = DFA56_eot;
			this.eof = DFA56_eof;
			this.min = DFA56_min;
			this.max = DFA56_max;
			this.accept = DFA56_accept;
			this.special = DFA56_special;
			this.transition = DFA56_transition;
		}
		@Override
		public String getDescription() {
			return "1174:1: sizedstar returns [Pair<StarQuality, ExprTree> value] : ( ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] i= integer e= expr ) | ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] e= expr ) | ^(t= OP_DEREFERENCE i= integer e= expr ) | ^(t= OP_DEREFERENCE e= expr ) );";
		}
	}

	static final String DFA57_eotS =
		"\17\uffff";
	static final String DFA57_eofS =
		"\17\uffff";
	static final String DFA57_minS =
		"\1\157\1\2\1\133\1\2\1\3\1\uffff\1\4\3\uffff\1\2\1\4\3\3";
	static final String DFA57_maxS =
		"\1\157\1\2\1\u00cb\1\2\1\u00cb\1\uffff\1\u00ed\3\uffff\1\3\1\u00ed\1\u00cb"+
		"\1\u00ed\1\3";
	static final String DFA57_acceptS =
		"\5\uffff\1\3\1\uffff\1\1\1\2\1\4\5\uffff";
	static final String DFA57_specialS =
		"\17\uffff}>";
	static final String[] DFA57_transitionS = {
			"\1\1",
			"\1\2",
			"\1\5\21\uffff\1\5\34\uffff\1\5\1\3\77\uffff\1\4",
			"\1\6",
			"\1\11\127\uffff\1\7\21\uffff\1\7\34\uffff\1\7\1\10\77\uffff\1\10",
			"",
			"\u00ea\12",
			"",
			"",
			"",
			"\1\13\1\14",
			"\u00ea\15",
			"\1\11\127\uffff\1\7\21\uffff\1\7\34\uffff\1\7\1\10\77\uffff\1\10",
			"\1\16\u00ea\15",
			"\1\14"
	};

	static final short[] DFA57_eot = DFA.unpackEncodedString(DFA57_eotS);
	static final short[] DFA57_eof = DFA.unpackEncodedString(DFA57_eofS);
	static final char[] DFA57_min = DFA.unpackEncodedStringToUnsignedChars(DFA57_minS);
	static final char[] DFA57_max = DFA.unpackEncodedStringToUnsignedChars(DFA57_maxS);
	static final short[] DFA57_accept = DFA.unpackEncodedString(DFA57_acceptS);
	static final short[] DFA57_special = DFA.unpackEncodedString(DFA57_specialS);
	static final short[][] DFA57_transition;

	static {
		int numStates = DFA57_transitionS.length;
		DFA57_transition = new short[numStates][];
		for (int i=0; i<numStates; i++) {
			DFA57_transition[i] = DFA.unpackEncodedString(DFA57_transitionS[i]);
		}
	}

	protected class DFA57 extends DFA {

		public DFA57(BaseRecognizer recognizer) {
			this.recognizer = recognizer;
			this.decisionNumber = 57;
			this.eot = DFA57_eot;
			this.eof = DFA57_eof;
			this.min = DFA57_min;
			this.max = DFA57_max;
			this.accept = DFA57_accept;
			this.special = DFA57_special;
			this.transition = DFA57_transition;
		}
		@Override
		public String getDescription() {
			return "1203:1: sizedstarv returns [Pair<StarQuality, VarnodeTpl> value] : ( ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] i= integer ss= specific_symbol[\"varnode reference\"] ) | ^(t= OP_DEREFERENCE s= space_symbol[\"sized star operator\"] ss= specific_symbol[\"varnode reference\"] ) | ^(t= OP_DEREFERENCE i= integer ss= specific_symbol[\"varnode reference\"] ) | ^(t= OP_DEREFERENCE ss= specific_symbol[\"varnode reference\"] ) );";
		}
	}

	public static final BitSet FOLLOW_endiandef_in_root80 = new BitSet(new long[]{0x0000000000000002L,0x000000C040200000L,0x0400040028000000L,0x0000000000001388L});
	public static final BitSet FOLLOW_definition_in_root86 = new BitSet(new long[]{0x0000000000000002L,0x000000C040200000L,0x0400040028000000L,0x0000000000001388L});
	public static final BitSet FOLLOW_constructorlike_in_root92 = new BitSet(new long[]{0x0000000000000002L,0x000000C040200000L,0x0400040028000000L,0x0000000000001388L});
	public static final BitSet FOLLOW_OP_ENDIAN_in_endiandef109 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_endian_in_endiandef113 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_BIG_in_endian131 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_LITTLE_in_endian141 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_aligndef_in_definition155 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_tokendef_in_definition160 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_contextdef_in_definition165 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_spacedef_in_definition170 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_varnodedef_in_definition175 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_bitrangedef_in_definition180 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_pcodeopdef_in_definition185 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_valueattach_in_definition190 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_nameattach_in_definition195 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_varattach_in_definition200 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_ALIGNMENT_in_aligndef215 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_aligndef219 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_TOKEN_in_tokendef245 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_specific_identifier_in_tokendef249 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_tokendef254 = new BitSet(new long[]{0x0000000000000000L,0x4000000000000000L});
	public static final BitSet FOLLOW_fielddefs_in_tokendef258 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FIELDDEFS_in_fielddefs271 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_fielddef_in_fielddefs273 = new BitSet(new long[]{0x0000000000000008L,0x2000000000000000L});
	public static final BitSet FOLLOW_OP_FIELDDEF_in_fielddef299 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_unbound_identifier_in_fielddef303 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_fielddef308 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_fielddef312 = new BitSet(new long[]{0x0000000000000000L,0x8000000000000000L,0x0000004000000000L});
	public static final BitSet FOLLOW_fieldmods_in_fielddef316 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FIELD_MODS_in_fieldmods331 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_fieldmod_in_fieldmods333 = new BitSet(new long[]{0x0000000000000008L,0x0000080000000000L,0x0020000100000200L});
	public static final BitSet FOLLOW_OP_NO_FIELD_MOD_in_fieldmods340 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_SIGNED_in_fieldmod356 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_NOFLOW_in_fieldmod368 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_HEX_in_fieldmod380 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_DEC_in_fieldmod392 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_specific_identifier414 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_specific_identifier428 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_unbound_identifier447 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_unbound_identifier461 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_varnode_symbol480 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_varnode_symbol494 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_value_symbol513 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_value_symbol527 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_operand_symbol546 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_operand_symbol560 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_space_symbol579 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_space_symbol593 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_specific_symbol612 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_specific_symbol626 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_family_symbol645 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_family_symbol659 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_CONTEXT_in_contextdef684 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_varnode_symbol_in_contextdef688 = new BitSet(new long[]{0x0000000000000000L,0x4000000000000000L});
	public static final BitSet FOLLOW_fielddefs_in_contextdef693 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SPACE_in_spacedef717 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_unbound_identifier_in_spacedef721 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0800000000000000L});
	public static final BitSet FOLLOW_spacemods_in_spacedef728 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SPACEMODS_in_spacemods743 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_spacemod_in_spacemods745 = new BitSet(new long[]{0x0000000000000008L,0x0000400000000000L,0x0040000000000000L,0x0000000000002020L});
	public static final BitSet FOLLOW_typemod_in_spacemod758 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_sizemod_in_spacemod763 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_wordsizemod_in_spacemod768 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_DEFAULT_in_spacemod773 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_TYPE_in_typemod787 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_specific_identifier_in_typemod791 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SIZE_in_sizemod807 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_sizemod811 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_WORDSIZE_in_wordsizemod826 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_wordsizemod830 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_VARNODE_in_varnodedef845 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_space_symbol_in_varnodedef849 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_varnodedef854 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_varnodedef858 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000001000L});
	public static final BitSet FOLLOW_identifierlist_in_varnodedef862 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_LIST_in_identifierlist893 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_identifierlist901 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_identifierlist917 = new BitSet(new long[]{0x0000000000000008L,0x0000000000000000L,0x0000000000000800L,0x0000000000000800L});
	public static final BitSet FOLLOW_OP_STRING_OR_IDENT_LIST_in_stringoridentlist945 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_stringorident_in_stringoridentlist950 = new BitSet(new long[]{0x0000000000000008L,0x0000000000000000L,0x0000080000000800L,0x0000000000000800L});
	public static final BitSet FOLLOW_identifier_in_stringorident973 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_qstring_in_stringorident982 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_BITRANGES_in_bitrangedef996 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_sbitrange_in_bitrangedef998 = new BitSet(new long[]{0x0000000000000008L,0x0000000010000000L});
	public static final BitSet FOLLOW_OP_BITRANGE_in_sbitrange1012 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_sbitrange1015 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_varnode_symbol_in_sbitrange1024 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_sbitrange1029 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_sbitrange1033 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_PCODEOP_in_pcodeopdef1048 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_identifierlist_in_pcodeopdef1052 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_VALUES_in_valueattach1073 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_valuelist_in_valueattach1077 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000004000L});
	public static final BitSet FOLLOW_intblist_in_valueattach1082 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_INTBLIST_in_intblist1107 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_intbpart_in_intblist1112 = new BitSet(new long[]{0x0000000000000008L,0x0000200008000000L,0x0000000040000400L,0x0000000000000800L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_intbpart1135 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_NEGATE_in_intbpart1143 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_intbpart1147 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_integer_in_intbpart1157 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_NAMES_in_nameattach1177 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_valuelist_in_nameattach1181 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x8000000000000000L});
	public static final BitSet FOLLOW_stringoridentlist_in_nameattach1186 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_VARIABLES_in_varattach1207 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_valuelist_in_varattach1211 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000001000L});
	public static final BitSet FOLLOW_varlist_in_varattach1216 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_LIST_in_valuelist1249 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_value_symbol_in_valuelist1254 = new BitSet(new long[]{0x0000000000000008L,0x0000000000000000L,0x0000000000000800L,0x0000000000000800L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_LIST_in_varlist1285 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_varnode_symbol_in_varlist1290 = new BitSet(new long[]{0x0000000000000008L,0x0000000000000000L,0x0000000000000800L,0x0000000000000800L});
	public static final BitSet FOLLOW_macrodef_in_constructorlike1308 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_withblock_in_constructorlike1315 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_constructor_in_constructorlike1322 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_MACRO_in_macrodef1347 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_unbound_identifier_in_macrodef1351 = new BitSet(new long[]{0x0000000000000000L,0x0010000001000000L});
	public static final BitSet FOLLOW_arguments_in_macrodef1356 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0002000000000000L});
	public static final BitSet FOLLOW_semantic_in_macrodef1362 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ARGUMENTS_in_arguments1394 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_arguments1398 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_EMPTY_LIST_in_arguments1413 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_WITH_in_withblock1425 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_id_or_nil_in_withblock1429 = new BitSet(new long[]{0x0000000000000000L,0x0000000080000000L,0x0000000080000000L});
	public static final BitSet FOLLOW_bitpat_or_nil_in_withblock1433 = new BitSet(new long[]{0x0000000000000000L,0x0000010000000000L,0x0000002000000000L});
	public static final BitSet FOLLOW_contextblock_in_withblock1437 = new BitSet(new long[]{0x0000000000000000L,0x0000040000000000L});
	public static final BitSet FOLLOW_constructorlikelist_in_withblock1443 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_identifier_in_id_or_nil1465 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_NIL_in_id_or_nil1472 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_bitpattern_in_bitpat_or_nil1491 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_NIL_in_bitpat_or_nil1498 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_CTLIST_in_constructorlikelist1512 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_definition_in_constructorlikelist1516 = new BitSet(new long[]{0x0000000000000008L,0x000000C040200000L,0x0400040028000000L,0x0000000000001388L});
	public static final BitSet FOLLOW_constructorlike_in_constructorlikelist1520 = new BitSet(new long[]{0x0000000000000008L,0x000000C040200000L,0x0400040028000000L,0x0000000000001388L});
	public static final BitSet FOLLOW_OP_CONSTRUCTOR_in_constructor1537 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_ctorstart_in_constructor1541 = new BitSet(new long[]{0x0000000000000000L,0x0000000080000000L});
	public static final BitSet FOLLOW_bitpattern_in_constructor1545 = new BitSet(new long[]{0x0000000000000000L,0x0000010000000000L,0x0000002000000000L});
	public static final BitSet FOLLOW_contextblock_in_constructor1549 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000020000000000L});
	public static final BitSet FOLLOW_ctorsemantic_in_constructor1553 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_PCODE_in_ctorsemantic1574 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_semantic_in_ctorsemantic1578 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_PCODE_in_ctorsemantic1588 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_UNIMPL_in_ctorsemantic1590 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_BIT_PATTERN_in_bitpattern1609 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pequation_in_bitpattern1613 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SUBTABLE_in_ctorstart1645 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_ctorstart1649 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_ctorstart1663 = new BitSet(new long[]{0x0000000000000000L,0x0001000000000000L});
	public static final BitSet FOLLOW_display_in_ctorstart1670 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_TABLE_in_ctorstart1682 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_display_in_ctorstart1688 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DISPLAY_in_display1705 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pieces_in_display1709 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_printpiece_in_pieces1723 = new BitSet(new long[]{0x0000000000000002L,0x0000002000000000L,0x4000080000000800L,0x0000000000000400L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_printpiece1744 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_whitespace_in_printpiece1758 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_CONCATENATE_in_printpiece1765 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_string_in_printpiece1772 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_WHITESPACE_in_whitespace1790 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_STRING_in_string1813 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_QSTRING_in_string1826 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_BOOL_OR_in_pequation1857 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pequation_in_pequation1861 = new BitSet(new long[]{0x0000000000000000L,0x004C000300000000L,0x0004010801800980L,0x0000000000000800L});
	public static final BitSet FOLLOW_pequation_in_pequation1865 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SEQUENCE_in_pequation1876 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pequation_in_pequation1880 = new BitSet(new long[]{0x0000000000000000L,0x004C000300000000L,0x0004010801800980L,0x0000000000000800L});
	public static final BitSet FOLLOW_pequation_in_pequation1884 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_BOOL_AND_in_pequation1895 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pequation_in_pequation1899 = new BitSet(new long[]{0x0000000000000000L,0x004C000300000000L,0x0004010801800980L,0x0000000000000800L});
	public static final BitSet FOLLOW_pequation_in_pequation1903 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ELLIPSIS_in_pequation1915 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pequation_in_pequation1919 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ELLIPSIS_RIGHT_in_pequation1930 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pequation_in_pequation1934 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_EQUAL_in_pequation1946 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_family_or_operand_symbol_in_pequation1950 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression2_in_pequation1955 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_NOTEQUAL_in_pequation1966 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_family_symbol_in_pequation1970 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression2_in_pequation1975 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LESS_in_pequation1986 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_family_symbol_in_pequation1990 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression2_in_pequation1995 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LESSEQUAL_in_pequation2006 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_family_symbol_in_pequation2010 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression2_in_pequation2015 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_GREAT_in_pequation2026 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_family_symbol_in_pequation2030 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression2_in_pequation2035 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_GREATEQUAL_in_pequation2046 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_family_symbol_in_pequation2050 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression2_in_pequation2055 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_pequation_symbol_in_pequation2066 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_PARENTHESIZED_in_pequation2075 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pequation_in_pequation2079 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_family_or_operand_symbol2100 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_family_or_operand_symbol2114 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_pequation_symbol2133 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_pequation_symbol2147 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_OR_in_pexpression2167 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2171 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2175 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_XOR_in_pexpression2186 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2190 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2194 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_AND_in_pexpression2205 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2209 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2213 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LEFT_in_pexpression2224 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2228 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2232 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_RIGHT_in_pexpression2243 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2247 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2251 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ADD_in_pexpression2262 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2266 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2270 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SUB_in_pexpression2281 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2285 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2289 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_MULT_in_pexpression2300 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2304 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2308 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DIV_in_pexpression2319 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2323 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2327 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_NEGATE_in_pexpression2339 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2343 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_INVERT_in_pexpression2354 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2358 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_pattern_symbol_in_pexpression2370 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_integer_in_pexpression2380 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_PARENTHESIZED_in_pexpression2388 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_pexpression2392 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_OR_in_pexpression22413 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22417 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22421 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_XOR_in_pexpression22432 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22436 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22440 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_AND_in_pexpression22451 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22455 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22459 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LEFT_in_pexpression22470 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22474 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22478 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_RIGHT_in_pexpression22489 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22493 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22497 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ADD_in_pexpression22508 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22512 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22516 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SUB_in_pexpression22527 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22531 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22535 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_MULT_in_pexpression22546 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22550 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22554 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DIV_in_pexpression22565 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22569 = new BitSet(new long[]{0x0000000000000000L,0x0002200008480000L,0x0000418050408C00L,0x0000000000004801L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22573 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_NEGATE_in_pexpression22585 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22589 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_INVERT_in_pexpression22600 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22604 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_pattern_symbol2_in_pexpression22616 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_integer_in_pexpression22626 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_PARENTHESIZED_in_pexpression22634 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression2_in_pexpression22638 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_pattern_symbol2658 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_pattern_symbol2672 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_pattern_symbol22691 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_pattern_symbol22705 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_CONTEXT_BLOCK_in_contextblock2723 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_cstatements_in_contextblock2727 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_NO_CONTEXT_BLOCK_in_contextblock2735 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_cstatement_in_cstatements2757 = new BitSet(new long[]{0x0000000000000002L,0x0000000002800000L});
	public static final BitSet FOLLOW_OP_ASSIGN_in_cstatement2772 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_cstatement2775 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_pexpression_in_cstatement2784 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_APPLY_in_cstatement2793 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_cstatement2796 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_cstatement2804 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_cstatement2812 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_SEMANTIC_in_semantic2856 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_code_block_in_semantic2860 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_statements_in_code_block2911 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_NOP_in_code_block2916 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_statement_in_statements2927 = new BitSet(new long[]{0x0000000000000002L,0x0080021802800000L,0x0001200004202040L});
	public static final BitSet FOLLOW_assignment_in_statement2959 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_declaration_in_statement2971 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_funcall_in_statement2983 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_build_stmt_in_statement3000 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_crossbuild_stmt_in_statement3014 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_goto_stmt_in_statement3023 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_cond_stmt_in_statement3038 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_call_stmt_in_statement3053 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_return_stmt_in_statement3068 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_label_in_statement3081 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_export_in_statement3090 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_section_label_in_statement3100 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_LOCAL_in_declaration3114 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_unbound_identifier_in_declaration3118 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_declaration3123 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LOCAL_in_declaration3132 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_unbound_identifier_in_declaration3136 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LABEL_in_label3156 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_label3160 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_label3176 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SECTION_LABEL_in_section_label3196 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_section_label3200 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_section_label3216 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_section_symbol3237 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_section_symbol3251 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_ASSIGN_in_assignment3277 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_BITRANGE_in_assignment3280 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_specific_symbol_in_assignment3284 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_assignment3289 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_assignment3293 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_expr_in_assignment3298 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ASSIGN_in_assignment3309 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_DECLARATIVE_SIZE_in_assignment3312 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_unbound_identifier_in_assignment3316 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_assignment3321 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_expr_in_assignment3326 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LOCAL_in_assignment3335 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_ASSIGN_in_assignment3339 = new BitSet(new long[]{0x0000000000000000L,0x0000100000000000L});
	public static final BitSet FOLLOW_OP_DECLARATIVE_SIZE_in_assignment3342 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_unbound_identifier_in_assignment3346 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_assignment3351 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_expr_in_assignment3356 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LOCAL_in_assignment3365 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_ASSIGN_in_assignment3369 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000800L,0x0000000000000800L});
	public static final BitSet FOLLOW_unbound_identifier_in_assignment3373 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_assignment3378 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ASSIGN_in_assignment3389 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_assignment3392 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_assignment3401 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ASSIGN_in_assignment3410 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_assignment3414 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_assignment3418 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ASSIGN_in_assignment3429 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_sizedstar_in_assignment3433 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_assignment3437 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_BITRANGE_in_bitrange3458 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_specific_symbol_in_bitrange3462 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_bitrange3467 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_bitrange3471 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DEREFERENCE_in_sizedstar3504 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_space_symbol_in_sizedstar3508 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_sizedstar3513 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_sizedstar3517 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DEREFERENCE_in_sizedstar3528 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_space_symbol_in_sizedstar3532 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_sizedstar3537 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DEREFERENCE_in_sizedstar3548 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_sizedstar3552 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_sizedstar3556 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DEREFERENCE_in_sizedstar3567 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_sizedstar3571 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DEREFERENCE_in_sizedstarv3604 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_space_symbol_in_sizedstarv3608 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_sizedstarv3613 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000800L,0x0000000000000800L});
	public static final BitSet FOLLOW_specific_symbol_in_sizedstarv3617 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DEREFERENCE_in_sizedstarv3629 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_space_symbol_in_sizedstarv3633 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000800L,0x0000000000000800L});
	public static final BitSet FOLLOW_specific_symbol_in_sizedstarv3638 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DEREFERENCE_in_sizedstarv3650 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_sizedstarv3654 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000800L,0x0000000000000800L});
	public static final BitSet FOLLOW_specific_symbol_in_sizedstarv3658 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DEREFERENCE_in_sizedstarv3670 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_specific_symbol_in_sizedstarv3674 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_expr_apply_in_funcall3701 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_BUILD_in_build_stmt3727 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_operand_symbol_in_build_stmt3731 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_CROSSBUILD_in_crossbuild_stmt3759 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_varnode_in_crossbuild_stmt3763 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000800L,0x0000000000000800L});
	public static final BitSet FOLLOW_section_symbol_in_crossbuild_stmt3767 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_GOTO_in_goto_stmt3807 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_jumpdest_in_goto_stmt3811 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_jump_symbol3832 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_jump_symbol3846 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_JUMPDEST_SYMBOL_in_jumpdest3867 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_jump_symbol_in_jumpdest3871 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_JUMPDEST_DYNAMIC_in_jumpdest3883 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_jumpdest3887 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_JUMPDEST_ABSOLUTE_in_jumpdest3898 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_jumpdest3902 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_JUMPDEST_RELATIVE_in_jumpdest3913 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_jumpdest3917 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000800L,0x0000000000000800L});
	public static final BitSet FOLLOW_space_symbol_in_jumpdest3921 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_JUMPDEST_LABEL_in_jumpdest3933 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_label_in_jumpdest3937 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_IF_in_cond_stmt3964 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_cond_stmt3968 = new BitSet(new long[]{0x0000000000000000L,0x0000000000000000L,0x0000000000000040L});
	public static final BitSet FOLLOW_OP_GOTO_in_cond_stmt3971 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_jumpdest_in_cond_stmt3975 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_CALL_in_call_stmt4016 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_jumpdest_in_call_stmt4020 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_RETURN_in_return_stmt4048 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_return_stmt4052 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_EXPORT_in_export4074 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_sizedstarv_in_export4078 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_EXPORT_in_export4089 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_varnode_in_export4093 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_BOOL_OR_in_expr4114 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4118 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4122 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_BOOL_XOR_in_expr4133 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4137 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4141 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_BOOL_AND_in_expr4152 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4156 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4160 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_OR_in_expr4172 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4176 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4180 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_XOR_in_expr4191 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4195 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4199 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_AND_in_expr4210 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4214 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4218 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_EQUAL_in_expr4230 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4234 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4238 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_NOTEQUAL_in_expr4249 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4253 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4257 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FEQUAL_in_expr4268 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4272 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4276 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FNOTEQUAL_in_expr4287 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4291 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4295 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LESS_in_expr4307 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4311 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4315 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_GREATEQUAL_in_expr4326 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4330 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4334 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LESSEQUAL_in_expr4345 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4349 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4353 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_GREAT_in_expr4364 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4368 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4372 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SLESS_in_expr4383 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4387 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4391 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SGREATEQUAL_in_expr4402 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4406 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4410 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SLESSEQUAL_in_expr4421 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4425 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4429 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SGREAT_in_expr4440 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4444 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4448 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FLESS_in_expr4459 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4463 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4467 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FGREATEQUAL_in_expr4478 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4482 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4486 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FLESSEQUAL_in_expr4497 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4501 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4505 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FGREAT_in_expr4516 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4520 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4524 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_LEFT_in_expr4536 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4540 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4544 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_RIGHT_in_expr4555 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4559 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4563 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SRIGHT_in_expr4574 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4578 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4582 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ADD_in_expr4594 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4598 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4602 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SUB_in_expr4613 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4617 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4621 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FADD_in_expr4632 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4636 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4640 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FSUB_in_expr4651 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4655 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4659 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_MULT_in_expr4671 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4675 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4679 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_DIV_in_expr4690 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4694 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4698 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_REM_in_expr4709 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4713 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4717 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SDIV_in_expr4728 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4732 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4736 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_SREM_in_expr4747 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4751 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4755 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FMULT_in_expr4766 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4770 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4774 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FDIV_in_expr4785 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4789 = new BitSet(new long[]{0x0000000000000000L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_in_expr4793 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_NOT_in_expr4805 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4809 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_INVERT_in_expr4820 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4824 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_NEGATE_in_expr4835 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4839 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_FNEGATE_in_expr4850 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4854 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_sizedstar_in_expr4864 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_apply_in_expr4874 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_varnode_in_expr4883 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_bitrange_in_expr4892 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_integer_in_expr4901 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_PARENTHESIZED_in_expr4909 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_in_expr4913 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_BITRANGE2_in_expr4925 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_specific_symbol_in_expr4929 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_expr4934 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_APPLY_in_expr_apply4961 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_expr_apply4966 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_expr_operands_in_expr_apply4975 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_APPLY_in_expr_apply4986 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_expr_apply4990 = new BitSet(new long[]{0x0000000000000008L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_expr_operands_in_expr_apply4994 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_expr_in_expr_operands5021 = new BitSet(new long[]{0x0000000000000002L,0x1F42A00738D80000L,0x3318D18C51C08DBFL,0x0000000000004811L});
	public static final BitSet FOLLOW_specific_symbol_in_varnode5042 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_TRUNCATION_SIZE_in_varnode5053 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_varnode5057 = new BitSet(new long[]{0x0000000000000000L,0x0000200008000000L,0x0000000000000400L});
	public static final BitSet FOLLOW_integer_in_varnode5061 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ADDRESS_OF_in_varnode5070 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_SIZING_SIZE_in_varnode5073 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_integer_in_varnode5077 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_varnode_in_varnode5082 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_ADDRESS_OF_in_varnode5091 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_varnode_in_varnode5095 = new BitSet(new long[]{0x0000000000000008L});
	public static final BitSet FOLLOW_OP_QSTRING_in_qstring5114 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_IDENTIFIER_in_identifier5137 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_WILDCARD_in_identifier5151 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_OP_HEX_CONSTANT_in_integer5169 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_DEC_CONSTANT_in_integer5182 = new BitSet(new long[]{0x0000000000000004L});
	public static final BitSet FOLLOW_OP_BIN_CONSTANT_in_integer5195 = new BitSet(new long[]{0x0000000000000004L});
}
