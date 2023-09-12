/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.lexer.ast;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.plugin.querylanguage.lexer.api.VisitableParseTreeNode;
import ghidra.app.plugin.querylanguage.lexer.api.VisitableParseTreeNodeVisitor;
import ghidra.app.plugin.querylanguage.lexer.api.VisitableResolvedContentNode;
import ghidra.app.plugin.querylanguage.lexer.api.VisitableResolvedContentNodeVisitor;

import ghidra.program.model.address.Address;

public class InstructionNode implements VisitableResolvedContentNode, VisitableParseTreeNode {

	final List<InstructionComponentNode> nodes;

	String stringValue = "";
	boolean stringValueIsUpToDate = false;

	// Indexes here correspond to character indexes into stringValue and map
	// to the source wildcard node from which that character comes from (or null) if
	// the character in stringValue does not come from a wildcard node.
	final Map<Integer, WildcardNode> wildcardMap = new HashMap<>();

	public InstructionNode(final InstructionComponentNode nodeButSpecialized) {
		this.nodes = new ArrayList<>(List.of(nodeButSpecialized));
	}

	public InstructionNode(final List<InstructionComponentNode> nodesButSpecialized) {
		this.nodes = nodesButSpecialized;
	}

	public void put(final InstructionComponentNode node) {
		nodes.add(node);
	}

	public String getOpcode() {

		assert (!nodes.isEmpty());
		return nodes.get(0).toString();
	}

	public List<InstructionComponentNode> getInstructionComponents() {
		return Collections.unmodifiableList(nodes);
	}

	@Override
	public void accept(VisitableParseTreeNodeVisitor visitor) {
		visitor.visit(this);
	}

	@Override
	public String getInstructionText() {
		return toString();
	}

	@Override
	public String toString() {
		if (stringValueIsUpToDate) {
			return stringValue;
		}

		populateStringAndWildcardMap();

		return toString();
	}

	// Returns a map where indexes correspond to character indexes into the return
	// value of toString() and map to the source wildcard node from which that
	// character comes from (or null) if the character in toString() does not come
	// from a wildcard node.
	public Map<Integer, WildcardNode> getWildcardMap() {
		if (stringValueIsUpToDate) {
			return wildcardMap;
		}

		populateStringAndWildcardMap();

		return getWildcardMap();
	}

	private void populateStringAndWildcardMap() {
		if (stringValueIsUpToDate) {
			return;
		}
		for (InstructionComponentNode node : nodes) {
			String nodeStr = node.toString();
			// If we're looking at a wildcard node, add entries to our wildcardMap for each
			// character we're about to append to our stringValue
			if (node instanceof WildcardNode) {
				int nodeStrLen = nodeStr.length();
				int baseStrLen = stringValue.length();
				for (int nodeStrIdx = 0; nodeStrIdx < nodeStrLen; nodeStrIdx++) {
					wildcardMap.put(baseStrLen + nodeStrIdx, (WildcardNode) node);
				}
			}
			stringValue += nodeStr;
		}
		stringValueIsUpToDate = true;
	}

	/*
	 * We can do a better job of ensuring that we're guessing good values for
	 * wildcards if we know the address of the instruction that Ghidra is going to
	 * try to compile our instruction at, so here we stash away that address into
	 * the wildcards for later use
	 */
	public void populateAddressIntoWildcards(Address addr) {
		for (InstructionComponentNode x : this.nodes) {
			if (x instanceof WildcardNode) {
				((WildcardNode) x).setAnticipatedAddress(addr);
			}
		}
	}

	@Override
	public void accept(VisitableResolvedContentNodeVisitor visitor) {
		visitor.visit(this);
	}
}
