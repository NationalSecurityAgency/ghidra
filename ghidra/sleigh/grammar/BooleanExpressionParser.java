package ghidra.sleigh.grammar;
// $ANTLR 3.5.2 ghidra/sleigh/grammar/BooleanExpression.g 2019-02-28 12:48:45

import org.antlr.runtime.*;
import java.util.Stack;
import java.util.List;
import java.util.ArrayList;

@SuppressWarnings("all")
public class BooleanExpressionParser extends Parser {
	public static final String[] tokenNames = new String[] {
		"<invalid>", "<EOR>", "<DOWN>", "<UP>", "ALPHA", "DIGIT", "ESCAPE", "HEXDIGIT", 
		"IDENTIFIER", "KEY_DEFINED", "OCTAL_ESCAPE", "OP_AND", "OP_EQ", "OP_NEQ", 
		"OP_NOT", "OP_OR", "OP_XOR", "QSTRING", "UNICODE_ESCAPE", "WS", "'('", 
		"')'"
	};
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
	public Parser[] getDelegates() {
		return new Parser[] {};
	}

	// delegators


	public BooleanExpressionParser(TokenStream input) {
		this(input, new RecognizerSharedState());
	}
	public BooleanExpressionParser(TokenStream input, RecognizerSharedState state) {
		super(input, state);
	}

	@Override public String[] getTokenNames() { return BooleanExpressionParser.tokenNames; }
	@Override public String getGrammarFileName() { return "ghidra/sleigh/grammar/BooleanExpression.g"; }


		public ExpressionEnvironment env;

		public static void main(String[] args) {
			try {
				CharStream input = new ANTLRFileStream(args[0]);
				BooleanExpressionLexer lex = new BooleanExpressionLexer(input);
				CommonTokenStream tokens = new CommonTokenStream(lex);
				BooleanExpressionParser parser = new BooleanExpressionParser(tokens);
				boolean result = parser.expression();
				System.out.println(result);
			} catch(Throwable t) {
				t.printStackTrace();
			}
	    }



	// $ANTLR start "expression"
	// ghidra/sleigh/grammar/BooleanExpression.g:31:1: expression returns [boolean b] : e= expr EOF ;
	public final boolean expression() throws RecognitionException {
		boolean b = false;


		boolean e =false;

		try {
			// ghidra/sleigh/grammar/BooleanExpression.g:32:2: (e= expr EOF )
			// ghidra/sleigh/grammar/BooleanExpression.g:32:4: e= expr EOF
			{
			pushFollow(FOLLOW_expr_in_expression85);
			e=expr();
			state._fsp--;

			match(input,EOF,FOLLOW_EOF_in_expression87); 
			 b = e; 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return b;
	}
	// $ANTLR end "expression"



	// $ANTLR start "expr"
	// ghidra/sleigh/grammar/BooleanExpression.g:35:1: expr returns [boolean b] : e= expr_or ;
	public final boolean expr() throws RecognitionException {
		boolean b = false;


		boolean e =false;

		try {
			// ghidra/sleigh/grammar/BooleanExpression.g:36:2: (e= expr_or )
			// ghidra/sleigh/grammar/BooleanExpression.g:36:4: e= expr_or
			{
			pushFollow(FOLLOW_expr_or_in_expr106);
			e=expr_or();
			state._fsp--;

			 b = e; 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return b;
	}
	// $ANTLR end "expr"



	// $ANTLR start "expr_or"
	// ghidra/sleigh/grammar/BooleanExpression.g:39:1: expr_or returns [boolean b] : lhs= expr_xor ( OP_OR rhs= expr_xor )* ;
	public final boolean expr_or() throws RecognitionException {
		boolean b = false;


		boolean lhs =false;
		boolean rhs =false;

		try {
			// ghidra/sleigh/grammar/BooleanExpression.g:40:2: (lhs= expr_xor ( OP_OR rhs= expr_xor )* )
			// ghidra/sleigh/grammar/BooleanExpression.g:40:4: lhs= expr_xor ( OP_OR rhs= expr_xor )*
			{
			pushFollow(FOLLOW_expr_xor_in_expr_or125);
			lhs=expr_xor();
			state._fsp--;

			 b = lhs; 
			// ghidra/sleigh/grammar/BooleanExpression.g:40:34: ( OP_OR rhs= expr_xor )*
			loop1:
			while (true) {
				int alt1=2;
				int LA1_0 = input.LA(1);
				if ( (LA1_0==OP_OR) ) {
					alt1=1;
				}

				switch (alt1) {
				case 1 :
					// ghidra/sleigh/grammar/BooleanExpression.g:40:35: OP_OR rhs= expr_xor
					{
					match(input,OP_OR,FOLLOW_OP_OR_in_expr_or130); 
					pushFollow(FOLLOW_expr_xor_in_expr_or134);
					rhs=expr_xor();
					state._fsp--;

					 b = b || rhs; 
					}
					break;

				default :
					break loop1;
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
		return b;
	}
	// $ANTLR end "expr_or"



	// $ANTLR start "expr_xor"
	// ghidra/sleigh/grammar/BooleanExpression.g:43:1: expr_xor returns [boolean b] : lhs= expr_and ( OP_XOR rhs= expr_and )* ;
	public final boolean expr_xor() throws RecognitionException {
		boolean b = false;


		boolean lhs =false;
		boolean rhs =false;

		try {
			// ghidra/sleigh/grammar/BooleanExpression.g:44:2: (lhs= expr_and ( OP_XOR rhs= expr_and )* )
			// ghidra/sleigh/grammar/BooleanExpression.g:44:4: lhs= expr_and ( OP_XOR rhs= expr_and )*
			{
			pushFollow(FOLLOW_expr_and_in_expr_xor155);
			lhs=expr_and();
			state._fsp--;

			 b = lhs; 
			// ghidra/sleigh/grammar/BooleanExpression.g:44:34: ( OP_XOR rhs= expr_and )*
			loop2:
			while (true) {
				int alt2=2;
				int LA2_0 = input.LA(1);
				if ( (LA2_0==OP_XOR) ) {
					alt2=1;
				}

				switch (alt2) {
				case 1 :
					// ghidra/sleigh/grammar/BooleanExpression.g:44:35: OP_XOR rhs= expr_and
					{
					match(input,OP_XOR,FOLLOW_OP_XOR_in_expr_xor160); 
					pushFollow(FOLLOW_expr_and_in_expr_xor164);
					rhs=expr_and();
					state._fsp--;

					 b = b ^ rhs; 
					}
					break;

				default :
					break loop2;
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
		return b;
	}
	// $ANTLR end "expr_xor"



	// $ANTLR start "expr_and"
	// ghidra/sleigh/grammar/BooleanExpression.g:47:1: expr_and returns [boolean b] : lhs= expr_not ( OP_AND rhs= expr_not )* ;
	public final boolean expr_and() throws RecognitionException {
		boolean b = false;


		boolean lhs =false;
		boolean rhs =false;

		try {
			// ghidra/sleigh/grammar/BooleanExpression.g:48:2: (lhs= expr_not ( OP_AND rhs= expr_not )* )
			// ghidra/sleigh/grammar/BooleanExpression.g:48:4: lhs= expr_not ( OP_AND rhs= expr_not )*
			{
			pushFollow(FOLLOW_expr_not_in_expr_and185);
			lhs=expr_not();
			state._fsp--;

			 b = lhs; 
			// ghidra/sleigh/grammar/BooleanExpression.g:48:34: ( OP_AND rhs= expr_not )*
			loop3:
			while (true) {
				int alt3=2;
				int LA3_0 = input.LA(1);
				if ( (LA3_0==OP_AND) ) {
					alt3=1;
				}

				switch (alt3) {
				case 1 :
					// ghidra/sleigh/grammar/BooleanExpression.g:48:35: OP_AND rhs= expr_not
					{
					match(input,OP_AND,FOLLOW_OP_AND_in_expr_and190); 
					pushFollow(FOLLOW_expr_not_in_expr_and194);
					rhs=expr_not();
					state._fsp--;

					 b = b && rhs; 
					}
					break;

				default :
					break loop3;
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
		return b;
	}
	// $ANTLR end "expr_and"



	// $ANTLR start "expr_not"
	// ghidra/sleigh/grammar/BooleanExpression.g:51:1: expr_not returns [boolean b] : ( OP_NOT e= expr_paren |e= expr_paren |e= expr_eq | KEY_DEFINED '(' id= IDENTIFIER ')' );
	public final boolean expr_not() throws RecognitionException {
		boolean b = false;


		Token id=null;
		boolean e =false;

		try {
			// ghidra/sleigh/grammar/BooleanExpression.g:52:2: ( OP_NOT e= expr_paren |e= expr_paren |e= expr_eq | KEY_DEFINED '(' id= IDENTIFIER ')' )
			int alt4=4;
			switch ( input.LA(1) ) {
			case OP_NOT:
				{
				alt4=1;
				}
				break;
			case 20:
				{
				alt4=2;
				}
				break;
			case IDENTIFIER:
			case QSTRING:
				{
				alt4=3;
				}
				break;
			case KEY_DEFINED:
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
					// ghidra/sleigh/grammar/BooleanExpression.g:52:4: OP_NOT e= expr_paren
					{
					match(input,OP_NOT,FOLLOW_OP_NOT_in_expr_not213); 
					pushFollow(FOLLOW_expr_paren_in_expr_not217);
					e=expr_paren();
					state._fsp--;

					 b = ! e; 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/BooleanExpression.g:53:4: e= expr_paren
					{
					pushFollow(FOLLOW_expr_paren_in_expr_not226);
					e=expr_paren();
					state._fsp--;

					 b = e; 
					}
					break;
				case 3 :
					// ghidra/sleigh/grammar/BooleanExpression.g:54:4: e= expr_eq
					{
					pushFollow(FOLLOW_expr_eq_in_expr_not242);
					e=expr_eq();
					state._fsp--;

					 b = e; 
					}
					break;
				case 4 :
					// ghidra/sleigh/grammar/BooleanExpression.g:55:4: KEY_DEFINED '(' id= IDENTIFIER ')'
					{
					match(input,KEY_DEFINED,FOLLOW_KEY_DEFINED_in_expr_not259); 
					match(input,20,FOLLOW_20_in_expr_not261); 
					id=(Token)match(input,IDENTIFIER,FOLLOW_IDENTIFIER_in_expr_not265); 
					match(input,21,FOLLOW_21_in_expr_not267); 
					 b = env.lookup((id!=null?id.getText():null)) != null; 
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
		return b;
	}
	// $ANTLR end "expr_not"



	// $ANTLR start "expr_paren"
	// ghidra/sleigh/grammar/BooleanExpression.g:58:1: expr_paren returns [boolean b] : '(' e= expr ')' ;
	public final boolean expr_paren() throws RecognitionException {
		boolean b = false;


		boolean e =false;

		try {
			// ghidra/sleigh/grammar/BooleanExpression.g:59:2: ( '(' e= expr ')' )
			// ghidra/sleigh/grammar/BooleanExpression.g:59:4: '(' e= expr ')'
			{
			match(input,20,FOLLOW_20_in_expr_paren284); 
			pushFollow(FOLLOW_expr_in_expr_paren288);
			e=expr();
			state._fsp--;

			match(input,21,FOLLOW_21_in_expr_paren290); 
			 b = e; 
			}

		}
		catch (RecognitionException re) {
			reportError(re);
			recover(input,re);
		}
		finally {
			// do for sure before leaving
		}
		return b;
	}
	// $ANTLR end "expr_paren"



	// $ANTLR start "expr_eq"
	// ghidra/sleigh/grammar/BooleanExpression.g:62:1: expr_eq returns [boolean b] : (lhs= expr_term OP_EQ rhs= expr_term |lhs= expr_term OP_NEQ rhs= expr_term );
	public final boolean expr_eq() throws RecognitionException {
		boolean b = false;


		String lhs =null;
		String rhs =null;

		try {
			// ghidra/sleigh/grammar/BooleanExpression.g:63:2: (lhs= expr_term OP_EQ rhs= expr_term |lhs= expr_term OP_NEQ rhs= expr_term )
			int alt5=2;
			int LA5_0 = input.LA(1);
			if ( (LA5_0==IDENTIFIER) ) {
				int LA5_1 = input.LA(2);
				if ( (LA5_1==OP_EQ) ) {
					alt5=1;
				}
				else if ( (LA5_1==OP_NEQ) ) {
					alt5=2;
				}

				else {
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
			else if ( (LA5_0==QSTRING) ) {
				int LA5_2 = input.LA(2);
				if ( (LA5_2==OP_EQ) ) {
					alt5=1;
				}
				else if ( (LA5_2==OP_NEQ) ) {
					alt5=2;
				}

				else {
					int nvaeMark = input.mark();
					try {
						input.consume();
						NoViableAltException nvae =
							new NoViableAltException("", 5, 2, input);
						throw nvae;
					} finally {
						input.rewind(nvaeMark);
					}
				}

			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 5, 0, input);
				throw nvae;
			}

			switch (alt5) {
				case 1 :
					// ghidra/sleigh/grammar/BooleanExpression.g:63:4: lhs= expr_term OP_EQ rhs= expr_term
					{
					pushFollow(FOLLOW_expr_term_in_expr_eq309);
					lhs=expr_term();
					state._fsp--;

					match(input,OP_EQ,FOLLOW_OP_EQ_in_expr_eq311); 
					pushFollow(FOLLOW_expr_term_in_expr_eq315);
					rhs=expr_term();
					state._fsp--;

					 b = env.equals(lhs, rhs); 
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/BooleanExpression.g:64:4: lhs= expr_term OP_NEQ rhs= expr_term
					{
					pushFollow(FOLLOW_expr_term_in_expr_eq325);
					lhs=expr_term();
					state._fsp--;

					match(input,OP_NEQ,FOLLOW_OP_NEQ_in_expr_eq327); 
					pushFollow(FOLLOW_expr_term_in_expr_eq331);
					rhs=expr_term();
					state._fsp--;

					 b = !env.equals(lhs, rhs); 
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
		return b;
	}
	// $ANTLR end "expr_eq"



	// $ANTLR start "expr_term"
	// ghidra/sleigh/grammar/BooleanExpression.g:67:1: expr_term returns [String s] : (id= IDENTIFIER |qs= QSTRING );
	public final String expr_term() throws RecognitionException {
		String s = null;


		Token id=null;
		Token qs=null;

		try {
			// ghidra/sleigh/grammar/BooleanExpression.g:68:2: (id= IDENTIFIER |qs= QSTRING )
			int alt6=2;
			int LA6_0 = input.LA(1);
			if ( (LA6_0==IDENTIFIER) ) {
				alt6=1;
			}
			else if ( (LA6_0==QSTRING) ) {
				alt6=2;
			}

			else {
				NoViableAltException nvae =
					new NoViableAltException("", 6, 0, input);
				throw nvae;
			}

			switch (alt6) {
				case 1 :
					// ghidra/sleigh/grammar/BooleanExpression.g:68:4: id= IDENTIFIER
					{
					id=(Token)match(input,IDENTIFIER,FOLLOW_IDENTIFIER_in_expr_term350); 
					 s = env.lookup((id!=null?id.getText():null));
											if (s == null)
												env.reportError("Macro: "+ (id!=null?id.getText():null) + " is undefined");
										  
					}
					break;
				case 2 :
					// ghidra/sleigh/grammar/BooleanExpression.g:72:4: qs= QSTRING
					{
					qs=(Token)match(input,QSTRING,FOLLOW_QSTRING_in_expr_term359); 
					s = (qs!=null?qs.getText():null).substring(1, (qs!=null?qs.getText():null).length() - 1); 
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
		return s;
	}
	// $ANTLR end "expr_term"

	// Delegated rules



	public static final BitSet FOLLOW_expr_in_expression85 = new BitSet(new long[]{0x0000000000000000L});
	public static final BitSet FOLLOW_EOF_in_expression87 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_or_in_expr106 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_xor_in_expr_or125 = new BitSet(new long[]{0x0000000000008002L});
	public static final BitSet FOLLOW_OP_OR_in_expr_or130 = new BitSet(new long[]{0x0000000000124300L});
	public static final BitSet FOLLOW_expr_xor_in_expr_or134 = new BitSet(new long[]{0x0000000000008002L});
	public static final BitSet FOLLOW_expr_and_in_expr_xor155 = new BitSet(new long[]{0x0000000000010002L});
	public static final BitSet FOLLOW_OP_XOR_in_expr_xor160 = new BitSet(new long[]{0x0000000000124300L});
	public static final BitSet FOLLOW_expr_and_in_expr_xor164 = new BitSet(new long[]{0x0000000000010002L});
	public static final BitSet FOLLOW_expr_not_in_expr_and185 = new BitSet(new long[]{0x0000000000000802L});
	public static final BitSet FOLLOW_OP_AND_in_expr_and190 = new BitSet(new long[]{0x0000000000124300L});
	public static final BitSet FOLLOW_expr_not_in_expr_and194 = new BitSet(new long[]{0x0000000000000802L});
	public static final BitSet FOLLOW_OP_NOT_in_expr_not213 = new BitSet(new long[]{0x0000000000100000L});
	public static final BitSet FOLLOW_expr_paren_in_expr_not217 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_paren_in_expr_not226 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_eq_in_expr_not242 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_KEY_DEFINED_in_expr_not259 = new BitSet(new long[]{0x0000000000100000L});
	public static final BitSet FOLLOW_20_in_expr_not261 = new BitSet(new long[]{0x0000000000000100L});
	public static final BitSet FOLLOW_IDENTIFIER_in_expr_not265 = new BitSet(new long[]{0x0000000000200000L});
	public static final BitSet FOLLOW_21_in_expr_not267 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_20_in_expr_paren284 = new BitSet(new long[]{0x0000000000124300L});
	public static final BitSet FOLLOW_expr_in_expr_paren288 = new BitSet(new long[]{0x0000000000200000L});
	public static final BitSet FOLLOW_21_in_expr_paren290 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_term_in_expr_eq309 = new BitSet(new long[]{0x0000000000001000L});
	public static final BitSet FOLLOW_OP_EQ_in_expr_eq311 = new BitSet(new long[]{0x0000000000020100L});
	public static final BitSet FOLLOW_expr_term_in_expr_eq315 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_expr_term_in_expr_eq325 = new BitSet(new long[]{0x0000000000002000L});
	public static final BitSet FOLLOW_OP_NEQ_in_expr_eq327 = new BitSet(new long[]{0x0000000000020100L});
	public static final BitSet FOLLOW_expr_term_in_expr_eq331 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_IDENTIFIER_in_expr_term350 = new BitSet(new long[]{0x0000000000000002L});
	public static final BitSet FOLLOW_QSTRING_in_expr_term359 = new BitSet(new long[]{0x0000000000000002L});
}
