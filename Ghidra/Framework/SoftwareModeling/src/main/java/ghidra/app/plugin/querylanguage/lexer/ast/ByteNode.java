/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.lexer.ast;

import ghidra.app.plugin.querylanguage.lexer.api.VisitableParseTreeNode;
import ghidra.app.plugin.querylanguage.lexer.api.VisitableParseTreeNodeVisitor;
import ghidra.app.plugin.querylanguage.lexer.api.VisitableResolvedContentNode;
import ghidra.app.plugin.querylanguage.lexer.api.VisitableResolvedContentNodeVisitor;

public class ByteNode implements VisitableResolvedContentNode, VisitableParseTreeNode {

	private final int value;
	private final String note;

	public ByteNode(int value, String note) {
		if (value < 0 || value > 255) {
			throw new RuntimeException("Byte must be between 0-255 (inclusive) but received " + value);
		}
		this.value = value;
		this.note = note;
	}

	public int value() {
		return this.value;
	}

	@Override
	public String getInstructionText() {
		return String.format("=0x%02x", this.value);
	}

	@Override
	public String toString() {
		return String.format("ByteNode Value: %02x From: %s", this.value, this.note);
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
