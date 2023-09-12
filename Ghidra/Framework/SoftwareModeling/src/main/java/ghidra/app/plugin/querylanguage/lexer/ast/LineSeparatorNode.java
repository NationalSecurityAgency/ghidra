/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.lexer.ast;

import ghidra.app.plugin.querylanguage.lexer.api.VisitableParseTreeNode;
import ghidra.app.plugin.querylanguage.lexer.api.VisitableParseTreeNodeVisitor;

public class LineSeparatorNode implements VisitableParseTreeNode {

	@Override
	public void accept(VisitableParseTreeNodeVisitor visitor) {
		visitor.visit(this);
	}

	@Override
	public String getInstructionText() {
		return "\n";
	}

	@Override
	public String toString() {
		return "\n";
	}
}
