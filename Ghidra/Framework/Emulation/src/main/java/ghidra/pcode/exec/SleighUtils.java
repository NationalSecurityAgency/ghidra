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
package ghidra.pcode.exec;

import java.io.*;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.antlr.runtime.*;
import org.antlr.runtime.tree.CommonTree;
import org.antlr.runtime.tree.Tree;

import ghidra.sleigh.grammar.*;

/**
 * A collection of utilities for parsing and manipulating Sleigh semantic source
 */
public enum SleighUtils {
	;

	public static final String CONDITION_ALWAYS = "1:1";
	public static final String UNCONDITIONAL_BREAK = """
			emu_swi();
			emu_exec_decoded();
			""";

	/**
	 * A Sleigh parsing error
	 */
	public record SleighParseErrorEntry(String header, String message, int start, int stop) {
		public String fullMessage() {
			return header + " " + message;
		}
	}

	/**
	 * An exception carrying one or more Sleigh parsing errors
	 */
	public static class SleighParseError extends RuntimeException {
		private final List<SleighParseErrorEntry> errors;

		public SleighParseError(Collection<SleighParseErrorEntry> errors) {
			super(errors.stream().map(e -> e.fullMessage()).collect(Collectors.joining("\n")));
			this.errors = List.copyOf(errors);
		}

		/**
		 * Get the actual errors
		 * 
		 * @return the list of entries
		 */
		public List<SleighParseErrorEntry> getErrors() {
			return errors;
		}
	}

	/**
	 * A function representing a non-terminal in the Sleigh semantic grammar
	 *
	 * @param <T> the return type
	 */
	public interface ParseFunction<T> {
		T apply(SleighParser parser) throws RecognitionException;
	}

	/**
	 * Parse a non-terminal symbol from the Sleigh semantic grammar
	 * 
	 * <p>
	 * Because the ANTLR parsing function for the non-terminal symbol depends on the "follows" set
	 * to determine when it has finished, we can't just invoke the function in isolation without
	 * some hacking. If EOF is not in the non-terminal's follows set, then it won't recognize EOF as
	 * completing the non-terminal. Instead, we have to present some token that it will recognize.
	 * Furthermore, regardless of the follow token, we have to check that all of the given input was
	 * consumed by the parser.
	 * 
	 * @param <T> the type of result from parsing
	 * @param nt the function from the parser implementing the non-terminal symbol
	 * @param text the text to parse
	 * @param follow a token that would ordinarily follow the non-terminal symbol, or empty for EOF
	 * @return the parsed result
	 */
	public static <T extends RuleReturnScope> T parseSleigh(ParseFunction<T> nt,
			String text, String follow) {
		LineArrayListWriter writer = new LineArrayListWriter();
		ParsingEnvironment env = new ParsingEnvironment(writer);

		// inject pcode statement lines into writer (needed for error reporting)
		BufferedReader r = new BufferedReader(new StringReader(text));
		String line;
		try {
			while ((line = r.readLine()) != null) {
				writer.write(line);
				writer.newLine();
			}
		}
		catch (IOException e) {
			throw new AssertionError(e);
		}

		String inputText = writer.toString().stripTrailing();
		CharStream input = new ANTLRStringStream(inputText + follow);

		env.getLocator().registerLocation(0, new Location("sleigh", 0));

		SleighLexer lex = new SleighLexer(input);
		lex.setEnv(env);
		UnbufferedTokenStream tokens = new UnbufferedTokenStream(lex);
		List<SleighParseErrorEntry> errors = new ArrayList<>();
		SleighParser parser = new SleighParser(tokens) {
			private void collectError(String[] tokenNames, RecognitionException e) {
				String hdr = getErrorHeader(e);
				String msg = getErrorMessage(e, tokenNames);
				CommonToken ct = (CommonToken) e.token;
				errors.add(new SleighParseErrorEntry(hdr, msg, ct.getStartIndex(),
					ct.getStopIndex()));
			}

			{
				this.gSemanticParser = new SleighParser_SemanticParser(input, state, this) {
					@Override
					public void displayRecognitionError(String[] tokenNames,
							RecognitionException e) {
						collectError(tokenNames, e);
					}

					@Override
					public void emitErrorMessage(String msg) {
						throw new AssertionError();
					}
				};
			}

			@Override
			public void displayRecognitionError(String[] tokenNames, RecognitionException e) {
				collectError(tokenNames, e);
			}

			@Override
			public void emitErrorMessage(String msg) {
				throw new AssertionError();
			}
		};
		parser.setEnv(env);
		parser.setLexer(lex);
		lex.pushMode(SleighRecognizerConstants.SEMANTIC);
		T t;
		try {
			t = nt.apply(parser);
		}
		catch (RecognitionException e) {
			parser.reportError(e);
			return null;
		}
		lex.popMode();

		CommonToken lastTok = (CommonToken) tokens.elementAt(0);
		if (follow.isEmpty()) {
			if (!tokens.isEOF(lastTok)) {
				parser.reportError(new UnwantedTokenException(Token.EOF, tokens));
			}
		}
		else {
			if (inputText.length() != lastTok.getStartIndex()) {
				parser.reportError(new UnwantedTokenException(Token.EOF, tokens));
			}
		}

		if (!errors.isEmpty()) {
			throw new SleighParseError(errors);
		}

		return t;
	}

	/**
	 * Parse a semantic block, that is a list of Sleigh semantic statements
	 * 
	 * @param sleigh the source
	 * @return the parse tree
	 */
	public static Tree parseSleighSemantic(String sleigh) {
		return parseSleigh(SleighParser::semantic, sleigh, "").getTree();
	}

	/**
	 * Parse a semantic expression
	 * 
	 * @param expression the expression as a string
	 * @return the parse tree
	 */
	public static Tree parseSleighExpression(String expression) {
		return parseSleigh(SleighParser::expr, expression, ";").getTree();
	}

	/**
	 * An exception indicating the parse tree did not match a pattern
	 */
	public static class MismatchException extends RuntimeException {
	}

	private static String getIdentifier(Tree tree) {
		if (tree.getType() != SleighParser.IDENTIFIER) {
			throw new MismatchException();
		}
		return tree.getText();
	}

	private static boolean isIdentifier(Tree tree, String id) {
		return id.equals(getIdentifier(tree));
	}

	private static void matchIdentifier(Tree tree, String id) {
		if (!isIdentifier(tree, id)) {
			throw new MismatchException();
		}
	}

	/**
	 * Get the children of a parse tree node
	 * 
	 * @param tree the node
	 * @return the list of children
	 */
	public static List<Tree> getChildren(Tree tree) {
		final int count = tree.getChildCount();
		List<Tree> children = Arrays.asList(new Tree[count]);
		for (int i = 0; i < count; i++) {
			children.set(i, tree.getChild(i));
		}
		return children;
	}

	/**
	 * Match the given tree to a given pattern
	 * 
	 * @param tree the (sub-)tree to match, actually its root node
	 * @param type the expected type of the given node
	 * @param onChildren actions (usually sub-matching) to perform on the children
	 */
	public static void matchTree(Tree tree, int type, Consumer<List<Tree>> onChildren) {
		if (tree.getType() != type) {
			throw new MismatchException();
		}
		onChildren.accept(getChildren(tree));
	}

	/**
	 * Require (as part of pattern matching) that the given list of children has a particular size
	 * 
	 * @param count the required size
	 * @param list the list of children
	 */
	public static void requireCount(int count, List<?> list) {
		if (count != list.size()) {
			throw new MismatchException();
		}
	}

	/**
	 * Match the given tree to a given pattern with per-child actions
	 * 
	 * @param tree the (sub-)tree to match, actually its root node
	 * @param type the expected type of the given node
	 * @param onChild a list of actions (usually sub-matching) to perform on each corresponding
	 *            child. The matcher will verify the number of children matches the number of
	 *            actions.
	 */
	@SafeVarargs
	public static void match(Tree tree, int type, Consumer<Tree>... onChild) {
		matchTree(tree, type, children -> {
			requireCount(onChild.length, children);
			for (int i = 0; i < onChild.length; i++) {
				onChild[i].accept(children.get(i));
			}
		});
	}

	public static void matchDereference(Tree tree, Consumer<Tree> onSpace, Consumer<Tree> onSize,
			Consumer<Tree> onOffset) {
		switch (tree.getChildCount()) {
			case 3:
				match(tree, SleighParser.OP_DEREFERENCE, onSpace, onSize, onOffset);
				return;
			case 2:
				Tree child0 = tree.getChild(0);
				switch (child0.getType()) {
					case SleighParser.OP_IDENTIFIER:
						match(tree, SleighParser.OP_DEREFERENCE, onSpace, onOffset);
						return;
					case SleighParser.OP_BIN_CONSTANT:
					case SleighParser.OP_DEC_CONSTANT:
					case SleighParser.OP_HEX_CONSTANT:
						match(tree, SleighParser.OP_DEREFERENCE, onSize, onOffset);
						return;
					default:
						throw new AssertionError(
							"OP_DEREFERENCE with 2 children where child[0] is " +
								SleighParser.tokenNames[child0.getType()]);
				}
			case 1:
				match(tree, SleighParser.OP_DEREFERENCE, onOffset);
				return;
			default:
				// Likely, the op is mismatched. Ensure the error message says so.
				match(tree, SleighParser.OP_DEREFERENCE);
				throw new AssertionError(
					"OP_DEREFERENCE with " + tree.getChildCount() + " children");
		}
	}

	/**
	 * Check if the given tree represents an unconditional breakpoint in the emulator
	 * 
	 * @param tree the result of parsing a semantic block
	 * @return true if an unconditional breakpoint, false otherwise
	 */
	public static boolean isUnconditionalBreakpoint(Tree tree) {
		try {
			match(tree, SleighParser.OP_SEMANTIC, wantApplyEmuSwi -> {
				match(wantApplyEmuSwi, SleighParser.OP_APPLY, wantId -> {
					match(wantId, SleighParser.OP_IDENTIFIER, id -> {
						matchIdentifier(id, "emu_swi");
					});
				});
			}, wantApplyEmuExecDecoded -> {
				match(wantApplyEmuExecDecoded, SleighParser.OP_APPLY, wantId -> {
					match(wantId, SleighParser.OP_IDENTIFIER, id -> {
						matchIdentifier(id, "emu_exec_decoded");
					});
				});
			});
			return true;
		}
		catch (MismatchException e) {
			return false;
		}
	}

	/**
	 * Check if the given tree represents a conditional breakpoint, and recover that condition
	 * 
	 * @param tree the result of parsing a semantic block
	 * @return the condition if matched, null otherwise
	 */
	public static String recoverConditionFromBreakpoint(Tree tree) {
		try {
			var l = new Object() {
				Tree cond;
				String labelId;
			};
			match(tree, SleighParser.OP_SEMANTIC, wantIf -> {
				match(wantIf, SleighParser.OP_IF, cond -> {
					l.cond = cond;
				}, wantGotoLabel -> {
					match(wantGotoLabel, SleighParser.OP_GOTO, wantJumpDest -> {
						match(wantJumpDest, SleighParser.OP_JUMPDEST_LABEL, wantLabel -> {
							match(wantLabel, SleighParser.OP_LABEL, wantId -> {
								match(wantId, SleighParser.OP_IDENTIFIER, id -> {
									l.labelId = getIdentifier(id);
								});
							});
						});
					});
				});
			}, wantApplyEmuSwi -> {
				match(wantApplyEmuSwi, SleighParser.OP_APPLY, wantId -> {
					match(wantId, SleighParser.OP_IDENTIFIER, id -> {
						matchIdentifier(id, "emu_swi");
					});
				});
			}, wantLabel -> {
				match(wantLabel, SleighParser.OP_LABEL, wantId -> {
					match(wantId, SleighParser.OP_IDENTIFIER, id -> {
						matchIdentifier(id, l.labelId);
					});
				});
			}, wantApplyEmuExecDecoded -> {
				match(wantApplyEmuExecDecoded, SleighParser.OP_APPLY, wantId -> {
					match(wantId, SleighParser.OP_IDENTIFIER, id -> {
						matchIdentifier(id, "emu_exec_decoded");
					});
				});
			});
			return generateSleighExpression(notTree(l.cond));
		}
		catch (MismatchException e) {
			return null;
		}
	}

	/**
	 * Check if the given Sleigh semantic block implements a conditional breakpoint, and recover
	 * that condition
	 * 
	 * @param sleigh the source for a Sleigh semantic block
	 * @return the condition if matched, null otherwise
	 */
	public static String recoverConditionFromBreakpoint(String sleigh) {
		try {
			Tree tree = parseSleighSemantic(sleigh);
			if (isUnconditionalBreakpoint(tree)) {
				return CONDITION_ALWAYS;
			}
			return recoverConditionFromBreakpoint(tree);
		}
		catch (SleighParseError e) {
			return null;
		}
	}

	public record AddressOf(String space, Tree offset) {
	}

	public static AddressOf recoverAddressOf(String defaultSpace, Tree tree) {
		var l = new Object() {
			String space = defaultSpace;
			Tree offset;
		};
		matchDereference(tree, wantSpaceId -> {
			match(wantSpaceId, SleighParser.OP_IDENTIFIER, id -> {
				l.space = getIdentifier(id);
			});
		}, wantSize -> {
			// I don't care about size
		}, wantOffset -> {
			l.offset = wantOffset;
		});
		return new AddressOf(l.space, removeParenthesisTree(Objects.requireNonNull(l.offset)));
	}

	public static AddressOf recoverAddressOf(String defaultSpace, String expression) {
		try {
			Tree tree = parseSleighExpression(expression);
			return recoverAddressOf(defaultSpace, tree);
		}
		catch (SleighParseError | MismatchException e) {
			return null;
		}
	}

	/**
	 * Synthesize a tree (node)
	 * 
	 * @param type the type of the node
	 * @param text the "text" of the node
	 * @param children the children
	 * @return the new node
	 */
	public static Tree makeTree(int type, String text, List<Tree> children) {
		CommonTree tree = new CommonTree(new CommonToken(type, text));
		tree.addChildren(children);
		return tree;
	}

	private static void catChildrenWithSep(Tree tree, String sep, int chopFront, int chopBack,
			StringBuilder sb) {
		int count = tree.getChildCount() - chopFront - chopBack;
		for (int i = 0; i < count; i++) {
			if (i != 0) {
				sb.append(sep);
			}
			generateSleighExpression(tree.getChild(i + chopFront), sb);
		}
	}

	private static void generateSleighExpression(Tree tree, StringBuilder sb) {
		switch (tree.getType()) {
			case SleighParser.BIN_INT:
			case SleighParser.DEC_INT:
			case SleighParser.HEX_INT:
			case SleighParser.IDENTIFIER:
				sb.append(tree.getText());
				break;

			case SleighParser.OP_BIN_CONSTANT:
			case SleighParser.OP_DEC_CONSTANT:
			case SleighParser.OP_HEX_CONSTANT:
			case SleighParser.OP_IDENTIFIER:
				generateSleighExpression(tree.getChild(0), sb);
				break;

			case SleighParser.OP_NOT:
				sb.append("!");
				generateSleighExpression(tree.getChild(0), sb);
				break;
			case SleighParser.OP_INVERT:
				sb.append("~");
				generateSleighExpression(tree.getChild(0), sb);
				break;
			case SleighParser.OP_NEGATE:
				sb.append("-");
				generateSleighExpression(tree.getChild(0), sb);
				break;
			case SleighParser.OP_FNEGATE:
				sb.append("f-");
				generateSleighExpression(tree.getChild(0), sb);
				break;

			case SleighParser.OP_ADD:
				catChildrenWithSep(tree, " + ", 0, 0, sb);
				break;
			case SleighParser.OP_SUB:
				catChildrenWithSep(tree, " - ", 0, 0, sb);
				break;
			case SleighParser.OP_MULT:
				catChildrenWithSep(tree, " * ", 0, 0, sb);
				break;
			case SleighParser.OP_DIV:
				catChildrenWithSep(tree, " / ", 0, 0, sb);
				break;
			case SleighParser.OP_REM:
				catChildrenWithSep(tree, " % ", 0, 0, sb);
				break;

			case SleighParser.OP_SDIV:
				catChildrenWithSep(tree, " s/ ", 0, 0, sb);
				break;
			case SleighParser.OP_SREM:
				catChildrenWithSep(tree, " s% ", 0, 0, sb);
				break;

			case SleighParser.OP_FADD:
				catChildrenWithSep(tree, " f+ ", 0, 0, sb);
				break;
			case SleighParser.OP_FSUB:
				catChildrenWithSep(tree, " f- ", 0, 0, sb);
				break;
			case SleighParser.OP_FMULT:
				catChildrenWithSep(tree, " f* ", 0, 0, sb);
				break;
			case SleighParser.OP_FDIV:
				catChildrenWithSep(tree, " f/ ", 0, 0, sb);
				break;

			case SleighParser.OP_LEFT:
				catChildrenWithSep(tree, " << ", 0, 0, sb);
				break;
			case SleighParser.OP_RIGHT:
				catChildrenWithSep(tree, " >> ", 0, 0, sb);
				break;
			case SleighParser.OP_SRIGHT:
				catChildrenWithSep(tree, " s>> ", 0, 0, sb);
				break;

			case SleighParser.OP_AND:
				catChildrenWithSep(tree, " & ", 0, 0, sb);
				break;
			case SleighParser.OP_OR:
				catChildrenWithSep(tree, " | ", 0, 0, sb);
				break;
			case SleighParser.OP_XOR:
				catChildrenWithSep(tree, " ^ ", 0, 0, sb);
				break;
			case SleighParser.OP_BOOL_AND:
				catChildrenWithSep(tree, " && ", 0, 0, sb);
				break;
			case SleighParser.OP_BOOL_OR:
				catChildrenWithSep(tree, " || ", 0, 0, sb);
				break;
			case SleighParser.OP_BOOL_XOR:
				catChildrenWithSep(tree, " ^^ ", 0, 0, sb);
				break;

			case SleighParser.OP_EQUAL:
				catChildrenWithSep(tree, " == ", 0, 0, sb);
				break;
			case SleighParser.OP_NOTEQUAL:
				catChildrenWithSep(tree, " != ", 0, 0, sb);
				break;
			case SleighParser.OP_FEQUAL:
				catChildrenWithSep(tree, " f== ", 0, 0, sb);
				break;
			case SleighParser.OP_FNOTEQUAL:
				catChildrenWithSep(tree, " f!= ", 0, 0, sb);
				break;

			case SleighParser.OP_LESS:
				catChildrenWithSep(tree, " < ", 0, 0, sb);
				break;
			case SleighParser.OP_LESSEQUAL:
				catChildrenWithSep(tree, " <= ", 0, 0, sb);
				break;
			case SleighParser.OP_GREATEQUAL:
				catChildrenWithSep(tree, " >= ", 0, 0, sb);
				break;
			case SleighParser.OP_GREAT:
				catChildrenWithSep(tree, " > ", 0, 0, sb);
				break;

			case SleighParser.OP_SLESS:
				catChildrenWithSep(tree, " s< ", 0, 0, sb);
				break;
			case SleighParser.OP_SLESSEQUAL:
				catChildrenWithSep(tree, " s<= ", 0, 0, sb);
				break;
			case SleighParser.OP_SGREATEQUAL:
				catChildrenWithSep(tree, " s>= ", 0, 0, sb);
				break;
			case SleighParser.OP_SGREAT:
				catChildrenWithSep(tree, " s> ", 0, 0, sb);
				break;

			case SleighParser.OP_FLESS:
				catChildrenWithSep(tree, " f< ", 0, 0, sb);
				break;
			case SleighParser.OP_FLESSEQUAL:
				catChildrenWithSep(tree, " f<= ", 0, 0, sb);
				break;
			case SleighParser.OP_FGREATEQUAL:
				catChildrenWithSep(tree, " f>= ", 0, 0, sb);
				break;
			case SleighParser.OP_FGREAT:
				catChildrenWithSep(tree, " f> ", 0, 0, sb);
				break;

			case SleighParser.OP_DEREFERENCE:
				if (tree.getChildCount() == 3) {
					sb.append("*[");
					generateSleighExpression(tree.getChild(0), sb);
					sb.append("]:");
					generateSleighExpression(tree.getChild(1), sb);
					sb.append(" ");
					generateSleighExpression(tree.getChild(2), sb);
				}
				else if (tree.getChildCount() == 2) {
					Tree child0 = tree.getChild(0);
					switch (child0.getType()) {
						case SleighParser.OP_IDENTIFIER:
							sb.append("*[");
							generateSleighExpression(child0, sb);
							sb.append("] ");
							generateSleighExpression(tree.getChild(1), sb);
							break;
						case SleighParser.OP_BIN_CONSTANT:
						case SleighParser.OP_DEC_CONSTANT:
						case SleighParser.OP_HEX_CONSTANT:
							sb.append("*:");
							generateSleighExpression(child0, sb);
							sb.append(" ");
							generateSleighExpression(tree.getChild(1), sb);
							break;
						default:
							throw new AssertionError(
								"OP_DEREFERENCE with 2 children where child[0] is " +
									SleighParser.tokenNames[child0.getType()]);
					}
				}
				else if (tree.getChildCount() == 1) {
					sb.append("*");
					generateSleighExpression(tree.getChild(0), sb);
				}
				else {
					throw new AssertionError(
						"OP_DEREFERENCE with " + tree.getChildCount() + " children");
				}
				break;
			case SleighParser.OP_ADDRESS_OF:
				if (tree.getChildCount() == 2) {
					sb.append("&");
					generateSleighExpression(tree.getChild(0), sb);
					sb.append(" ");
					generateSleighExpression(tree.getChild(1), sb);
				}
				else if (tree.getChildCount() == 1) {
					sb.append("&");
					generateSleighExpression(tree.getChild(0), sb);
				}
				else {
					throw new AssertionError(
						"OP_ADDRESS_OF with " + tree.getChildCount() + " children");
				}
				break;
			case SleighParser.OP_SIZING_SIZE:
				sb.append(":");
				generateSleighExpression(tree.getChild(0), sb);
				break;
			case SleighParser.OP_APPLY:
				generateSleighExpression(tree.getChild(0), sb);
				sb.append("(");
				catChildrenWithSep(tree, ", ", 1, 0, sb);
				sb.append(")");
				break;
			case SleighParser.OP_TRUNCATION_SIZE:
				generateSleighExpression(tree.getChild(0), sb);
				sb.append(":");
				generateSleighExpression(tree.getChild(1), sb);
				break;
			case SleighParser.OP_BITRANGE:
				generateSleighExpression(tree.getChild(0), sb);
				sb.append("[");
				generateSleighExpression(tree.getChild(1), sb);
				sb.append(",");
				generateSleighExpression(tree.getChild(2), sb);
				sb.append("]");
				break;
			case SleighParser.OP_BITRANGE2:
				generateSleighExpression(tree.getChild(0), sb);
				sb.append(":");
				generateSleighExpression(tree.getChild(1), sb);
				break;
			case SleighParser.OP_ARGUMENTS:
				catChildrenWithSep(tree, ", ", 0, 0, sb);
				break;
			case SleighParser.OP_PARENTHESIZED:
				sb.append("(");
				generateSleighExpression(tree.getChild(0), sb);
				sb.append(")");
				break;
			default:
				throw new AssertionError("type = " + SleighParser.tokenNames[tree.getType()]);
		}
	}

	/**
	 * Generate source for the given Sleigh parse tree
	 * 
	 * <p>
	 * Currently, only nodes that could appear in a Sleigh expression are supported.
	 * 
	 * @param tree the expression tree
	 * @return the generated string
	 */
	public static String generateSleighExpression(Tree tree) {
		StringBuilder sb = new StringBuilder();
		generateSleighExpression(tree, sb);
		return sb.toString();
	}

	/**
	 * Remove parenthesis from the root of the given tree
	 * 
	 * <p>
	 * If the root is parenthesis, this simply gets the child. This is applied recursively until a
	 * non-parenthesis child is encountered.
	 * 
	 * @param tree the result of parsing a Sleigh expression
	 * @return the same or sub-tree
	 */
	public static Tree removeParenthesisTree(Tree tree) {
		if (tree.getType() == SleighParser.OP_PARENTHESIZED) {
			return removeParenthesisTree(tree.getChild(0));
		}
		return tree;
	}

	/**
	 * Apply the boolean "not" operator to a Sleigh expression
	 * 
	 * <p>
	 * This will attempt to invert the expression when possible, e.g., by changing a top-level
	 * "equals" to "not equals." If that is not possible, the this adds parenthesis and applies the
	 * actual Sleigh boolean "not" operator.
	 * 
	 * @param boolExpr the result of parsing a Sleigh expression
	 * @return the tree for the inverted expression
	 */
	public static Tree notTree(Tree boolExpr) {
		boolExpr = removeParenthesisTree(boolExpr);
		switch (boolExpr.getType()) {
			case SleighParser.OP_EQUAL:
				return makeTree(SleighParser.OP_NOTEQUAL, "!=", getChildren(boolExpr));
			case SleighParser.OP_NOTEQUAL:
				return makeTree(SleighParser.OP_EQUAL, "==", getChildren(boolExpr));
			case SleighParser.OP_FEQUAL:
				return makeTree(SleighParser.OP_FNOTEQUAL, "f!=", getChildren(boolExpr));
			case SleighParser.OP_FNOTEQUAL:
				return makeTree(SleighParser.OP_FEQUAL, "f==", getChildren(boolExpr));

			case SleighParser.OP_LESS:
				return makeTree(SleighParser.OP_GREATEQUAL, ">=", getChildren(boolExpr));
			case SleighParser.OP_LESSEQUAL:
				return makeTree(SleighParser.OP_GREAT, ">", getChildren(boolExpr));
			case SleighParser.OP_GREATEQUAL:
				return makeTree(SleighParser.OP_LESS, "<", getChildren(boolExpr));
			case SleighParser.OP_GREAT:
				return makeTree(SleighParser.OP_LESSEQUAL, "<=", getChildren(boolExpr));

			case SleighParser.OP_SLESS:
				return makeTree(SleighParser.OP_SGREATEQUAL, "s>=", getChildren(boolExpr));
			case SleighParser.OP_SLESSEQUAL:
				return makeTree(SleighParser.OP_SGREAT, "s>", getChildren(boolExpr));
			case SleighParser.OP_SGREATEQUAL:
				return makeTree(SleighParser.OP_SLESS, "s<", getChildren(boolExpr));
			case SleighParser.OP_SGREAT:
				return makeTree(SleighParser.OP_SLESSEQUAL, "s<=", getChildren(boolExpr));

			case SleighParser.OP_FLESS:
				return makeTree(SleighParser.OP_FGREATEQUAL, "f>=", getChildren(boolExpr));
			case SleighParser.OP_FLESSEQUAL:
				return makeTree(SleighParser.OP_FGREAT, "f>", getChildren(boolExpr));
			case SleighParser.OP_FGREATEQUAL:
				return makeTree(SleighParser.OP_FLESS, "f<", getChildren(boolExpr));
			case SleighParser.OP_FGREAT:
				return makeTree(SleighParser.OP_FLESSEQUAL, "f<=", getChildren(boolExpr));

			case SleighParser.OP_NOT:
				return removeParenthesisTree(boolExpr.getChild(0));
			default:
				return makeTree(SleighParser.OP_NOT, "!", List.of(
					makeTree(SleighParser.OP_PARENTHESIZED, "(...)", List.of(
						boolExpr))));
		}
	}

	/**
	 * Generate Sleigh source for a breakpoint predicated on the given condition
	 * 
	 * @param condition a Sleigh expression
	 * @return the Sleigh source
	 */
	public static String sleighForConditionalBreak(String condition) {
		if (CONDITION_ALWAYS.equals(condition)) {
			return UNCONDITIONAL_BREAK;
		}
		Tree tree = parseSleighExpression(condition);
		String negCond = generateSleighExpression(notTree(tree));
		return String.format("""
				if %s goto <L1>;
				  emu_swi();
				<L1>
				emu_exec_decoded();
				""", negCond);
	}
}
