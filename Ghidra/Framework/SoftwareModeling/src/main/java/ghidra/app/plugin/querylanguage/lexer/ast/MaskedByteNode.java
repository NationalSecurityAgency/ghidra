/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.lexer.ast;

import ghidra.app.plugin.querylanguage.lexer.api.VisitableParseTreeNode;
import ghidra.app.plugin.querylanguage.lexer.api.VisitableParseTreeNodeVisitor;
import ghidra.app.plugin.querylanguage.lexer.api.VisitableResolvedContentNode;
import ghidra.app.plugin.querylanguage.lexer.api.VisitableResolvedContentNodeVisitor;

public class MaskedByteNode implements VisitableResolvedContentNode, VisitableParseTreeNode {

	private final int mask;
	private final int value;

	public MaskedByteNode(int mask, int value) {
		if (mask < 0 || mask > 255) {
			throw new RuntimeException("Byte must be between 0-255 (inclusive) but received " + mask);
		}
		if (value < 0 || value > 255) {
			throw new RuntimeException("Byte must be between 0-255 (inclusive) but received " + value);
		}
		this.mask = mask;
		this.value = value;
	}

	public int value() {
		return this.value;
	}

	public int mask() {
		return this.mask;
	}

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
		return String.format("&0x%02x=0x%02x", this.mask, this.value);
	}
}
