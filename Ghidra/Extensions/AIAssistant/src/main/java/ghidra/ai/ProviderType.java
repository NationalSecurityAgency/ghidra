/* ###
 * IP: HexToCode_License
 *
 * HexToCode
 * Copyright (c) 2026 Shmuel Sinay <g47ben@gmail.com>. All rights reserved.
 *
 * Licensed under the HexToCode Restricted License; see the LICENSE file at the
 * root of this distribution. You may not use, copy, modify or distribute this
 * file except as that license allows.
 */
package ghidra.ai;

/**
 * The AI services the assistant can talk to.
 */
enum ProviderType {
	CLAUDE("Anthropic Claude"),
	GEMINI("Google AI Studio (Gemini)"),
	OPENAI_COMPATIBLE("OpenAI / שרת תואם OpenAI");

	private final String displayName;

	ProviderType(String displayName) {
		this.displayName = displayName;
	}

	@Override
	public String toString() {
		return displayName;
	}
}
