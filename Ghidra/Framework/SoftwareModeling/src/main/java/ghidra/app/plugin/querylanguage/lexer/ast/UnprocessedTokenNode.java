/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.lexer.ast;

import ghidra.app.plugin.querylanguage.tokenizer.Token;
import ghidra.app.plugin.querylanguage.tokenizer.TokenType;

public class UnprocessedTokenNode implements ParseTreeNode {

	private final Token token;

	public UnprocessedTokenNode(final Token token) {
		this.token = token;
	}

	public Token getToken() {
		return token;
	}

	public TokenType getTokenType() {
		return token.type();
	}

	public String getTokenData() {
		return token.data();
	}

	public boolean isCommand() {
		return getTokenType() == TokenType.PICKLED_CANARY_COMMAND;
	}

	public boolean isInstructionComponent() {
		return getTokenType() == TokenType.INSTRUCTION_COMPONENT;
	}

	@Override
	public String getInstructionText() {
		return token.data();
	}

	@Override
	public String toString() {
		return String.format("Token from line #%s: Token type: %s data: %s", token.line().number(), token.type(),
				token.data());
	}
}
