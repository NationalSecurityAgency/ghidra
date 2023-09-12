/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.lexer.api;

import ghidra.app.plugin.querylanguage.lexer.ast.ParseTreeNode;

public interface VisitableParseTreeNode extends ParseTreeNode {
	void accept(VisitableParseTreeNodeVisitor visitor);
}
