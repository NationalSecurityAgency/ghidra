/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.lexer.api;

import ghidra.app.plugin.querylanguage.lexer.ast.AnyBytesNode;
import ghidra.app.plugin.querylanguage.lexer.ast.ByteNode;
import ghidra.app.plugin.querylanguage.lexer.ast.InstructionNode;
import ghidra.app.plugin.querylanguage.lexer.ast.LabelNode;
import ghidra.app.plugin.querylanguage.lexer.ast.LineSeparatorNode;
import ghidra.app.plugin.querylanguage.lexer.ast.MaskedByteNode;
import ghidra.app.plugin.querylanguage.lexer.ast.MetaNode;
import ghidra.app.plugin.querylanguage.lexer.ast.NotEndNode;
import ghidra.app.plugin.querylanguage.lexer.ast.NotStartNode;
import ghidra.app.plugin.querylanguage.lexer.ast.OrEndNode;
import ghidra.app.plugin.querylanguage.lexer.ast.OrMiddleNode;
import ghidra.app.plugin.querylanguage.lexer.ast.OrStartNode;

public interface VisitableParseTreeNodeVisitor {

	void visit(AnyBytesNode anyBytesNode);

	void visit(InstructionNode instructionResolutionList);

	void visit(LineSeparatorNode instructionResolutionList);

	void visit(OrStartNode orStartNode);

	void visit(OrMiddleNode orMiddleNode);

	void visit(OrEndNode orEndNode);

	void visit(ByteNode byteNode);

	void visit(MaskedByteNode byteNode);

	void visit(NotStartNode notStartNode);

	void visit(NotEndNode notEndNode);

	void visit(MetaNode metaNode);

	void visit(LabelNode labelNode);
}
