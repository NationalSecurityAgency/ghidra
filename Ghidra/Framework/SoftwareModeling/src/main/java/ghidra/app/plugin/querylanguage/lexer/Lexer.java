/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.lexer;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.app.plugin.querylanguage.lexer.ast.AnyBytesNode;
import ghidra.app.plugin.querylanguage.lexer.ast.ByteNode;
import ghidra.app.plugin.querylanguage.lexer.ast.InstructionComponentNode;
import ghidra.app.plugin.querylanguage.lexer.ast.InstructionNode;
import ghidra.app.plugin.querylanguage.lexer.ast.IntraInstructionNode;
import ghidra.app.plugin.querylanguage.lexer.ast.LabelNode;
import ghidra.app.plugin.querylanguage.lexer.ast.LineSeparatorNode;
import ghidra.app.plugin.querylanguage.lexer.ast.MaskedByteNode;
import ghidra.app.plugin.querylanguage.lexer.ast.MetaNode;
import ghidra.app.plugin.querylanguage.lexer.ast.NotEndNode;
import ghidra.app.plugin.querylanguage.lexer.ast.NotStartNode;
import ghidra.app.plugin.querylanguage.lexer.ast.OpcodeNode;
import ghidra.app.plugin.querylanguage.lexer.ast.OperandNode;
import ghidra.app.plugin.querylanguage.lexer.ast.OrEndNode;
import ghidra.app.plugin.querylanguage.lexer.ast.OrMiddleNode;
import ghidra.app.plugin.querylanguage.lexer.ast.OrStartNode;
import ghidra.app.plugin.querylanguage.lexer.ast.ParseTreeNode;
import ghidra.app.plugin.querylanguage.lexer.ast.UnprocessedTokenNode;
import ghidra.app.plugin.querylanguage.lexer.ast.WildcardNode;
import ghidra.app.plugin.querylanguage.tokenizer.Token;
import ghidra.app.plugin.querylanguage.tokenizer.TokenType;

public class Lexer {

	enum MetadataStates {
		BEFORE_META, IN_META, AFTER_META
	}

	private final LinkedList<Token> tokens;

	public Lexer(LinkedList<Token> tokens) {
		this.tokens = tokens;
	}

	public ParseTree lex() {

		/*
		 * The lexer uses multiple phases.
		 *
		 * -----------------------------------------------------------------------------
		 *
		 * In the first set of phases, it takes our tokens and move them into a
		 * normalized format with general nodes.
		 *
		 * First, it converts the tokens to a Java stream for processing. Second, it
		 * extracts only the data that has semantics by pruning comments and commas.
		 * Third, it converts all data to simple wrapper nodes that implement the
		 * ParseTreeNode interface.
		 *
		 * -----------------------------------------------------------------------------
		 *
		 * In the second set of phases, it begins to specialize these nodes.
		 *
		 * Respectively, phases four through nine specialize: Line separators,
		 * negations, anybytes, literal instructions, wildcards, and labels.
		 *
		 * -----------------------------------------------------------------------------
		 *
		 * In the third set of phases, we coalesce and groups nodes together.
		 *
		 * For now, only line separators and newlines get coalesced. (In that order.)
		 *
		 * -----------------------------------------------------------------------------
		 *
		 * Fourth, we create a parse tree.
		 */

		// Initialize our parse tree.

		// Do the first set of phases: normalizing to a stream of the
		// UnprocessedTokenNodes that have semantics
		final var stream = tokens.stream();
		final var coalescedMetadata = coalesceMetadata(stream);
		final var semanticalData = extractSemanticalData(coalescedMetadata);
		final var asSimpleNodes = convertToNodes(semanticalData);

		// Do the second set of phases: specializing nodes.
		final var withLineSeparators = specializeLineSeparators(asSimpleNodes);
		final var withNegations = specializeNegations(withLineSeparators);
		final var withMetadata = specializeMeta(withNegations);
		final var withAnyBytes = specializeAnyBytes(withMetadata);
		final var withBytes = specializeBytes(withAnyBytes);
		final var withLabels = specializeLabels(withBytes);
		final var withOrs = specializeOrs(withLabels);
		final var withLiteralInstructions = specializeLiteralInstructionComponents(withOrs);
		final var withWildcards = specializeWildcards(withLiteralInstructions);

		// Do the third set of phases: coalescing nodes.
		final var asList = withWildcards.collect(Collectors.toList());
		final var withLineSeparatorsCoalesced = coalesceLineSeparators(asList);
		final var withInstructionsCoalesced = coalesceInstructions(withLineSeparatorsCoalesced);

		// Now, we move on to the fourth and final set of phases, which happens in
		// ParseTree.java
		return new ParseTree(withInstructionsCoalesced);
	}

	private Stream<Token> coalesceMetadata(Stream<Token> stream) {
		MetadataStates state = MetadataStates.BEFORE_META;
		final var newNodes = new ArrayList<Token>();

		StringBuilder meta = new StringBuilder();

		final var asList = stream.collect(Collectors.toCollection(ArrayList::new));

		for (final var token : asList) {
			boolean is_start = token.data().matches("`META`");
			boolean is_end = token.data().matches("`(?:META_END|END_META)`");
			if ((token.type() == TokenType.PICKLED_CANARY_COMMAND) && is_start) {
				if (state == MetadataStates.BEFORE_META) {
					state = MetadataStates.IN_META;
				} else {
					throw new RuntimeException("Cannot have more than one `META` tag");
				}
			} else if ((token.type() == TokenType.PICKLED_CANARY_COMMAND) && is_end) {
				if (state == MetadataStates.IN_META) {
					newNodes.add(new Token(TokenType.METADATA, meta.toString(), token.line()));
					state = MetadataStates.AFTER_META;
				} else if (state == MetadataStates.BEFORE_META) {
					throw new RuntimeException(
							"Cannot have closing `META_END` tag here. No" + " opening `META` found previously");
				} else {
					throw new RuntimeException("Cannot have more than one `META_END` tag");
				}
			} else {
				if (state == MetadataStates.IN_META) {
					if (token.type() != TokenType.COMMENT) {
						String data = token.data();
						if (data.startsWith(";")) {
							continue;
						}
						meta.append(data);
					}
				} else if (token.type() == TokenType.METADATA) {
					throw new RuntimeException("Found data that was assumed to be metadata outside"
							+ " of the metadata block. This could be because a character not"
							+ " recognized as an instruction character was seen: " + token.data());
				} else {
					newNodes.add(token);
				}
			}
		}

		return newNodes.stream();
	}

	private List<ParseTreeNode> coalesceLineSeparators(final List<ParseTreeNode> nodes) {
		final var newNodes = new ArrayList<ParseTreeNode>();
		var inNewLine = false;

		for (final var node : nodes) {
			if (!(node instanceof LineSeparatorNode)) {
				inNewLine = false;
				newNodes.add(node);
				continue;
			}

			// "a \n\n\n b" is the same as "a \n\n\n b" to us
			if (inNewLine) {
				continue;
			}

			newNodes.add(node);
			inNewLine = true;
		}

		return newNodes;
	}

	private List<ParseTreeNode> coalesceInstructions(final List<ParseTreeNode> nodes) {
		final var newNodes = new ArrayList<ParseTreeNode>();
		var inInstruction = false;

		for (final var node : nodes) {
			if (!(node instanceof InstructionComponentNode)) {
				inInstruction = false;
				newNodes.add(node);
				continue;
			}

			final var nodeButSpecialized = (InstructionComponentNode) node;

			if (inInstruction) {
				final var instructionNode = newNodes.get(newNodes.size() - 1);
				assert (instructionNode instanceof InstructionNode);
				((InstructionNode) instructionNode).put(nodeButSpecialized);
				continue;
			}

			newNodes.add(new InstructionNode(nodeButSpecialized));
			inInstruction = true;
		}

		return newNodes;
	}

	private Stream<ParseTreeNode> specializeLineSeparators(final Stream<ParseTreeNode> nodes) {
		return nodes.map(node -> {
			if (!(node instanceof UnprocessedTokenNode)) {
				return node;
			}

			final var nodeButSpecialized = (UnprocessedTokenNode) node;

			if (nodeButSpecialized.getTokenType() == TokenType.WHITESPACE
					&& nodeButSpecialized.getTokenData().contains("\n")) {
				return new LineSeparatorNode();
			}

			return node;
		});
	}

	private Stream<ParseTreeNode> specializeMeta(final Stream<ParseTreeNode> nodes) {
		return nodes.map(node -> {
			if (!(node instanceof UnprocessedTokenNode)) {
				return node;
			}

			final var nodeButSpecialized = (UnprocessedTokenNode) node;

			if (nodeButSpecialized.getTokenType() == TokenType.METADATA) {
				return new MetaNode(nodeButSpecialized.getTokenData());
			}

			return node;
		});
	}

	private Stream<ParseTreeNode> specializeNegations(final Stream<ParseTreeNode> nodes) {
		final var NEGATION_REGEX = "`NOT *\\{`";
		final var NEGATION_END_REGEX = "`\\} *(?:END_NOT|NOT_END)`";
		return nodes.map(node -> {
			if (node instanceof UnprocessedTokenNode) {

				final var nodeButSpecialized = (UnprocessedTokenNode) node;
				if (nodeButSpecialized.isCommand()) {
					String tokenData = nodeButSpecialized.getTokenData();
					if (tokenData.matches(NEGATION_REGEX)) {
						return new NotStartNode();
					} else if (tokenData.matches(NEGATION_END_REGEX)) {
						return new NotEndNode();
					}
				}
			}

			return node;
		});
	}

	private Stream<ParseTreeNode> specializeAnyBytes(final Stream<ParseTreeNode> nodes) {
		// TODO: try ^ at start
		final var ANYBYTES_REGEX = "`ANY_BYTES\\{(?<START>(0x)?[0-9a-fA-F]+), ?(?<END>(0x)?[0-9a-fA-F]+)(, ?(?<INTERVAL>(0x)?[0-9a-fA-F]+))?}`";
		// final var ANYBYTES_REGEX = "`ANY_BYTES\\{(?<START>.*), ?(?<END>.*)}`";

		return nodes.map(node -> {
			if (node instanceof UnprocessedTokenNode) {

				final var nodeButSpecialized = (UnprocessedTokenNode) node;
				if (nodeButSpecialized.isCommand()) {
					final var tokenData = nodeButSpecialized.getTokenData();
					final var tokenDataUpper = tokenData.toUpperCase();
					if (tokenData.matches(ANYBYTES_REGEX)) {
						final var compiledRegexQuery = Pattern.compile(ANYBYTES_REGEX);
						final var matcher = compiledRegexQuery.matcher(tokenData);

						matcher.matches();

						try {
							final var start = Integer.parseInt(matcher.group("START"));
							final var end = Integer.parseInt(matcher.group("END"));
							Integer interval = null;
							if (matcher.group("INTERVAL") != null) {
								interval = Integer.parseInt(matcher.group("INTERVAL"));
							}

							return new AnyBytesNode(start, end, interval, node.toString());
						} catch (NumberFormatException e) {
							throw new RuntimeException(String.format(
									"ANY_BYTES min and max must be integers between 0 and 2,147,483,647 inclusive: `ANY_BYTES{%s,%s}`",
									matcher.group("START"), matcher.group("END")));
						}
					} else if (tokenDataUpper.startsWith("`ANY_BYTES") && !tokenData.startsWith("`ANY_BYTES")
							|| tokenDataUpper.startsWith("`ANYBYTES") || tokenDataUpper.startsWith("`ANY_BYTE")
							|| tokenDataUpper.startsWith("`ANYBYTE")) {
						throw new RuntimeException(
								tokenData + " not a valid Pickled Canary command. Did you mean ANY_BYTES?");
					}
				}
			}

			return node;
		});
	}

	private Stream<ParseTreeNode> specializeOrs(final Stream<ParseTreeNode> nodes) {
		final var START_OR_REGEX = Pattern.compile("`(?:START_OR|OR_START) *\\{?`");
		final var OR_REGEX = Pattern.compile("`\\}? *OR *\\{?`");
		final var END_OR_REGEX = Pattern.compile("`\\}? *(?:END_OR|OR_END)`");

		var output = nodes.map(node -> {
			if (node instanceof UnprocessedTokenNode) {

				final var nodeButSpecialized = (UnprocessedTokenNode) node;
				if (nodeButSpecialized.isCommand()) {
					String tokenData = nodeButSpecialized.getTokenData();
					if (OR_REGEX.matcher(tokenData).matches()) {
						return new OrMiddleNode();
					} else if (START_OR_REGEX.matcher(tokenData).matches()) {
						return new OrStartNode();
					} else if (END_OR_REGEX.matcher(tokenData).matches()) {
						return new OrEndNode();
					} else {
						// throw new RuntimeException("Unrecognized OR command. Did you mean `OR`,"
						// + " `START_OR`, or `END_OR`?");
					}
				}
			}

			return node;
		});

		// You can't re-use / fork a stream...
		// so go to list and then back to two streams
		final var outputAsList = output.collect(Collectors.toCollection(ArrayList::new));

		long start_or_count = 0;
		long or_count = 0;
		long end_or_count = 0;

		for (final ParseTreeNode item : outputAsList) {
			if (item instanceof OrStartNode) {
				start_or_count += 1;
			} else if (item instanceof OrMiddleNode) {
				or_count += 1;
			} else if (item instanceof OrEndNode) {
				end_or_count += 1;
			}
		}

		if (start_or_count != end_or_count) {
			throw new RuntimeException("There are not an equal number of `START_OR` (" + start_or_count
					+ ") and `END_OR` (\"+end_or_count +\") tokens in your pattern");
		}
		if (or_count < end_or_count) {
			throw new RuntimeException("There are fewer `OR` (" + or_count + ") tokens than `START_OR` and `END_OR` ("
					+ end_or_count + ") tokens in your pattern");
		}

		return outputAsList.stream();
	}

	private Stream<ParseTreeNode> specializeBytes(final Stream<ParseTreeNode> nodes) {
		return nodes.flatMap(node -> {
			if (node instanceof UnprocessedTokenNode) {

				final var nodeButSpecialized = (UnprocessedTokenNode) node;
				if (nodeButSpecialized.isCommand()) {
					String tokenData = nodeButSpecialized.getTokenData();
					if (tokenData.startsWith("`=0x")) {
						return Stream.of(new ByteNode(
								Integer.parseInt(tokenData.substring(4, tokenData.length() - 1), 16), node.toString()));
					} else if (tokenData.length() <= 12 && tokenData.startsWith("`&0x") && tokenData.contains("=0x")) {
						int value_idx = tokenData.indexOf("=0x");
						int mask = Integer.parseInt(tokenData.substring(4, value_idx), 16);
						int value = Integer.parseInt(tokenData.substring(value_idx + 3, tokenData.length() - 1), 16);
						return Stream.of(new MaskedByteNode(mask, value));
					} else if (tokenData.startsWith("`\"")) {// this is where the String option is added
						// trimming out the `" from beginning/end
						String trimmedTokenData = tokenData.substring(2, tokenData.length() - 2);
						List<ByteNode> stringNodes = new ArrayList<>();
						for (int i = 0; i < trimmedTokenData.length(); i++) {
							stringNodes.add(new ByteNode(trimmedTokenData.charAt(i), node.toString()));
						}
						return stringNodes.stream();

					}
				}
			}

			return Stream.of(node);
		});
	}

	private Stream<ParseTreeNode> specializeLiteralInstructionComponents(final Stream<ParseTreeNode> nodes) {
		final var allWhitespacePattern = Pattern.compile("^[ \t]*$");
		final var asList = nodes.collect(Collectors.toCollection(ArrayList::new));

		if (asList.isEmpty()) {
			return Stream.empty();
		}

		final var firstNode = asList.get(0);

		// This will soon iterate over nodes 2...n of the n-tuple of nodes, which
		// requires the first node to be treated
		// as a special case.
		if (firstNode instanceof UnprocessedTokenNode) {

			final var nodeButSpecialized = ((UnprocessedTokenNode) firstNode);

			if (nodeButSpecialized.isInstructionComponent()) {
				final var opcode = nodeButSpecialized.getTokenData();
				asList.set(0, new OpcodeNode(opcode));
			}
		}

		for (int i = 1; i < asList.size(); i++) {
			var last = asList.get(i - 1);
			var current = asList.get(i);

			// If this node was already processed, then we can skip it.
			// Implies that current is an UnprocessedTokenNode in all later lines. (A)
			if (!(current instanceof UnprocessedTokenNode)) {
				continue;
			}

			final var currentButSpecialized = (UnprocessedTokenNode) current;

			// Since this must be an UnprocessedTokenNode token node by (A), we can safely
			// cast it...
			// ...and extract its text and type.
			final var currentText = currentButSpecialized.getTokenData();
			final var currentType = currentButSpecialized.getTokenType();

			// TODO: or PC command?
			final var isOpcodeOrOperand = currentType == TokenType.INSTRUCTION_COMPONENT;

			if (last instanceof InstructionComponentNode) {
				if (isOpcodeOrOperand) {
					asList.set(i, new OperandNode(currentText));
				} else {
					asList.set(i, new IntraInstructionNode(currentButSpecialized));
				}
			} else {

				// if the currentText is all whitespace...
				if (allWhitespacePattern.matcher(currentText).matches()) {
					// Loop through the next tokens to see if everything is whitespace until a
					// LineSeparatorNode
					int lookahead_index = i;
					boolean allWhitespaceSoFar = true;
					for (; lookahead_index < asList.size(); lookahead_index++) {
						ParseTreeNode next = asList.get(lookahead_index);
						if (next instanceof LineSeparatorNode) {
							break;
						} else if (!allWhitespacePattern.matcher(next.getInstructionText()).matches()) {
							allWhitespaceSoFar = false;
							break;
						}
					}
					// At this point we've looked ahead until:
					// * We've run out of tokens (e.g. it's whitespace until the end of the file)
					// * We ran into a LineSeparatorNode
					// * We ran into something that's not whitespace
					// At this point lookahead_index is the index of our stopping case (one of the
					// above bullets)
					// If we've only had whitespace to that point, delete the nodes between where we
					// started looking and where we stopped for some reason.
					if (allWhitespaceSoFar) {
						// Remove "i" each time because as we delete the formerly-higher indexes
						// will "drop" down into this index
						if (lookahead_index > i) {
							asList.subList(i, lookahead_index).clear();
						}
						// If we deleted nodes, the "next" node we need to process is now at the
						// same index our deleted node was at, so decrement i to look at it (i will
						// be incremented back to its current value by the for loop)
						i--;
						// Continue back to the loop without adding an OpcodeNode for the
						// just-deleted node (that'd be silly)
						continue;
					}

				} else if (!(last instanceof LineSeparatorNode)) {
					throw new RuntimeException("Expected instruction to start on a newline. Got text \""
							+ current.getInstructionText() + "\" after \"" + last.getInstructionText() + "\"");
				}
				asList.set(i, new OpcodeNode(currentText));
			}
		}

		return asList.stream();
	}

	private Stream<ParseTreeNode> specializeWildcards(final Stream<ParseTreeNode> nodes) {
		final var asList = nodes.collect(Collectors.toList());
		int wildcardInstanceId = 0;

		int operandIdx = asList.size() > 0
				&& (asList.get(0) instanceof OpcodeNode || asList.get(0) instanceof OperandNode) ? -1 : -2;
		for (int i = 1; i < asList.size(); i++) {
			var last = asList.get(i - 1);
			var current = asList.get(i);

			if (current instanceof LineSeparatorNode) {
				operandIdx = -2;
			} else if (current instanceof OpcodeNode || current instanceof OperandNode) {
				operandIdx++;
			}

			// We have to be somewhere in an instruction to be a wildcard.
			if (!(current instanceof IntraInstructionNode)) {
				continue;
			}

			/*
			 * We don't support wildcarded opcodes yet, so do nothing if this looks like an
			 * opcode. This line takes advantage of the fact that if the last node was part
			 * of an instruction, then the current node cannot be the start of a new
			 * instruction; mov a, b mov c, d isn't valid assembly.
			 */
			if (!(last instanceof InstructionComponentNode)) {
				continue;
			}

			if (((IntraInstructionNode) current).getType() == TokenType.PICKLED_CANARY_COMMAND) {
				asList.set(i, new WildcardNode(current.toString(), ++operandIdx, wildcardInstanceId++));
			}
		}

		return asList.stream();
	}

	private Stream<ParseTreeNode> specializeLabels(final Stream<ParseTreeNode> nodes) {
		final var LABEL_REGEX = "`(.+):`$";

		return nodes.map(node -> {
			if (node instanceof UnprocessedTokenNode) {

				final var nodeButSpecialized = (UnprocessedTokenNode) node;

				if (nodeButSpecialized.isCommand() && nodeButSpecialized.getTokenData().matches(LABEL_REGEX)) {
					final var nodeText = nodeButSpecialized.getTokenData();
					final var compiledRegexQuery = Pattern.compile(LABEL_REGEX);
					final var matcher = compiledRegexQuery.matcher(nodeText);
					final var matches = matcher.matches();
					assert (matches);
					final var labelName = matcher.group(1);

					return new LabelNode(labelName);
				}
			}

			return node;
		});
	}

	private Stream<ParseTreeNode> convertToNodes(Stream<Token> stream) {
		return stream.map(UnprocessedTokenNode::new);
	}

	private Stream<Token> extractSemanticalData(Stream<Token> stream) {
		return stream.filter(token -> token.type() != TokenType.COMMENT);
	}
}
