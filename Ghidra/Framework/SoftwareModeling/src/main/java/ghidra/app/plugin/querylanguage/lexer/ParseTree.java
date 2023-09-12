/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.lexer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.app.plugin.querylanguage.exceptions.ErrorSourceData;
import ghidra.app.plugin.querylanguage.exceptions.SyntaxErrorException;
import ghidra.app.plugin.querylanguage.lexer.ast.InstructionNode;
import ghidra.app.plugin.querylanguage.lexer.ast.LabelNode;
import ghidra.app.plugin.querylanguage.lexer.ast.ParseTreeNode;
import ghidra.app.plugin.querylanguage.lexer.ast.UnprocessedTokenNode;
import ghidra.app.plugin.querylanguage.lexer.ast.WildcardNode;

public class ParseTree {

	final Map<String, LabelNode> labels;
	final Map<WildcardNode, Integer> wildcardNodeIntegerMap;
	final Map<Integer, WildcardNode> integerWildcardNodeMap = new HashMap<>();
	final List<ParseTreeNode> treeNodes;

	public ParseTree(final List<ParseTreeNode> treeNodes) {
		this.labels = getLabelDefinitions(treeNodes);
		this.wildcardNodeIntegerMap = getWildcardDefinitions(treeNodes);
		this.treeNodes = treeNodes;

		validate(treeNodes);
	}

	public Stream<ParseTreeNode> stream() {
		return treeNodes.stream();
	}

	private void validate(final List<ParseTreeNode> nodes) {
		nodes.stream()
			.filter(UnprocessedTokenNode.class::isInstance)
			.map(UnprocessedTokenNode.class::cast)
			.findAny().ifPresent(node -> {
				throw new SyntaxErrorException("Failed to process node in parse tree.",
					new ErrorSourceData(node.getToken().line(), node.getToken().data()));
			});

//		 TODO: check wildcard sanity
	}

	private Map<String, LabelNode> getLabelDefinitions(final List<ParseTreeNode> nodes) {
		return nodes.stream()
				.filter(LabelNode.class::isInstance)
				.map(LabelNode.class::cast)
				.collect(Collectors.toMap(LabelNode::name, Function.identity()));
	}

	// Should only be called once.
	private Map<WildcardNode, Integer> getWildcardDefinitions(final List<ParseTreeNode> nodes) {
		if (wildcardNodeIntegerMap != null) {
			throw new RuntimeException("Wildcard definitions already exist.");
		}

		final HashSet<String> definedWildcardNames = new HashSet<>();
		final int[] id = { 0 };
		final var references = new ArrayList<WildcardNode>();

		final var map = nodes.stream()
				.filter(InstructionNode.class::isInstance)
				.map(InstructionNode.class::cast) // to InstructionNodes
				.map(InstructionNode::getInstructionComponents)
				.flatMap(List::stream)
				.filter(WildcardNode.class::isInstance)
				.map(WildcardNode.class::cast) // to WildcardNodes
				.peek(node -> {
					String nodeName = node.getName();
					if (definedWildcardNames.contains(nodeName)) {
						if (node.hasManuallySetAnyContext()) {
							throw new RuntimeException("Variable \"" + node.getName() + "\" specifies"
									+ " FILTER or subsequent fields after first use.\n\nOnly first wildcard"
									+ " with a given name may contain a FILTER (or subsequent fields)."
									+ " Later wildcards with the same name use the same FILTER (and"
									+ " subsequent fields) declared in that first wildcard.");
						}
						if (!node.isCatchAll() && !labels.containsKey(nodeName)) {
							references.add(node);
						}
					} else {
						if (!node.isCatchAll()) {
							definedWildcardNames.add(nodeName);
						}
					}
				}).peek(node -> node.setId(id[0]++))
				.collect(Collectors.toMap(Function.identity(), WildcardNode::getId, (x, y) -> {
					return x;
				}));

		for (var node : map.keySet()) {
			integerWildcardNodeMap.put(map.get(node), node);
		}

		references.forEach(node -> node.setId(map.get(node)));

		// ALL of this function besides this block was used in the pre-suboperand days.
		// I don't think it will be used any more after.
		// This copies the initiator into repeated wildcards.
		// We could implement some sort of reference system so other fields are also
		// accessible in the future, but this is currently the only field that we really
		// use.
		HashMap<String, WildcardNode> firstNodes = new HashMap<>();
		for (WildcardNode n : nodes.stream()
				.filter(InstructionNode.class::isInstance)
				.map(InstructionNode.class::cast) // to InstructionNodes
				.map(InstructionNode::getInstructionComponents)
				.flatMap(List::stream)
				.filter(WildcardNode.class::isInstance)
				.map(WildcardNode.class::cast)
				.collect(Collectors.toList())) {
			if (!n.isCatchAll()) {
				WildcardNode firstOfName = firstNodes.get(n.getName());
				if (firstOfName == null) {
					firstNodes.put(n.getName(), n);
				} else {
					if (n.hasManuallySetAnyContext()) {
						throw new RuntimeException("Variable \"" + n.getName() + "\" specifies"
								+ " FILTER or subsequent fields after first use.\n\nOnly first wildcard"
								+ " with a given name may contain a FILTER (or subsequent fields)."
								+ " Later wildcards with the same name use the same FILTER (and"
								+ " subsequent fields) declared in that first wildcard.");
					}
					Optional<String> otherInitiator = firstOfName.getInitiator();
					if (otherInitiator.isPresent()) {
						n.setInitiator(otherInitiator.get());
					}
				}
			}
		}

		return map;
	}
}
