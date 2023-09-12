/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.lexer.ast;

import ghidra.app.plugin.querylanguage.lexer.api.VisitableParseTreeNode;
import ghidra.app.plugin.querylanguage.lexer.api.VisitableParseTreeNodeVisitor;
import ghidra.app.plugin.querylanguage.lexer.api.VisitableResolvedContentNode;
import ghidra.app.plugin.querylanguage.lexer.api.VisitableResolvedContentNodeVisitor;

public class OrMiddleNode implements VisitableResolvedContentNode, VisitableParseTreeNode {

	@Override
	public void accept(VisitableParseTreeNodeVisitor visitor) {
		visitor.visit(this);
	}

	@Override
	public void accept(VisitableResolvedContentNodeVisitor visitor) {
		visitor.visit(this);
	}

	@Override
	public String getInstructionText() {
		return "OR";
	}
}
