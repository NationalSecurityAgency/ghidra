/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.lexer.ast;

import java.util.Objects;

import ghidra.app.plugin.querylanguage.lexer.api.VisitableParseTreeNode;
import ghidra.app.plugin.querylanguage.lexer.api.VisitableParseTreeNodeVisitor;
import ghidra.app.plugin.querylanguage.lexer.api.VisitableResolvedContentNode;
import ghidra.app.plugin.querylanguage.lexer.api.VisitableResolvedContentNodeVisitor;

public class LabelNode implements VisitableResolvedContentNode, VisitableParseTreeNode {

	private final String name;

	public LabelNode(String name) {
		this.name = name;
	}

	public String name() {
		return name;
	}

	@Override
	public String getInstructionText() {
		return name + ":";
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		if (obj == null || obj.getClass() != this.getClass()) {
			return false;
		}
		var that = (LabelNode) obj;
		return Objects.equals(this.name, that.name);
	}

	@Override
	public int hashCode() {
		return Objects.hash(name);
	}

	@Override
	public String toString() {
		return "LabelNode[name=" + name + ']';
	}

	@Override
	public void accept(VisitableParseTreeNodeVisitor visitor) {
		visitor.visit(this);
	}

	@Override
	public void accept(VisitableResolvedContentNodeVisitor visitor) {
		visitor.visit(this);
	}
}
