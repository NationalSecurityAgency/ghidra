/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.lexer.ast;

import ghidra.app.plugin.querylanguage.tokenizer.TokenType;

/**
 * Generally used to capture e.g. commas, spaces, wildcards, etc., that carry
 * important syntactical implications.
 */
public class IntraInstructionNode extends InstructionComponentNode {

	private final TokenType type;
	private final UnprocessedTokenNode intraNodeComponent;

	public IntraInstructionNode(final UnprocessedTokenNode intraNodeComponent) {
		super(intraNodeComponent.getTokenData());
		this.type = intraNodeComponent.getTokenType();
		this.intraNodeComponent = intraNodeComponent;
	}

	public TokenType getType() {
		return type;
	}

	@Override
	public String getInstructionText() {
		return intraNodeComponent.getInstructionText();
	}
}
