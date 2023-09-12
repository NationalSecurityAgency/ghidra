/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.lexer.ast;

import ghidra.app.plugin.querylanguage.lexer.api.VisitableParseTreeNode;
import ghidra.app.plugin.querylanguage.lexer.api.VisitableParseTreeNodeVisitor;
import ghidra.app.plugin.querylanguage.lexer.api.VisitableResolvedContentNode;
import ghidra.app.plugin.querylanguage.lexer.api.VisitableResolvedContentNodeVisitor;

public class AnyBytesNode implements VisitableResolvedContentNode, VisitableParseTreeNode {

	private final int start;
	private final int end;
	private final int interval;
	private final String note;

	public AnyBytesNode(final int start, final int end, final Integer interval, final String note) {
		this.start = start;
		this.end = end;
		if (interval == null) {
			this.interval = 1;
		} else {
			this.interval = interval;
		}

		this.note = note;
	}

	public int getStart() {
		return start;
	}

	public int getEnd() {
		return end;
	}

	public int getInterval() {
		return interval;
	}

	@Override
	public String getInstructionText() {
		return String.format("ANY_BYTES{%d,%d,%d}", start, end, interval);
	}

	@Override
	public String toString() {
		return String.format("AnyBytesNode Start: %s End: %s Interval: %s From: %s", this.start, this.end,
				this.interval, this.note);
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
