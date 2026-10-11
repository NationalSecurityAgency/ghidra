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
 * A chat backend (Claude, Gemini, any OpenAI-compatible service). Implementations keep their own
 * conversation history in their native wire format and run the tool-calling loop until the model
 * produces a final answer.
 */
interface AIProvider {

	/** Upper bound on tool-call rounds for a single question, to avoid runaway loops. */
	int MAX_TOOL_ROUNDS = 25;

	String SYSTEM_PROMPT = """
			You are an expert reverse engineer built into HexToCode (a reverse engineering tool \
			based on Ghidra). The user is analyzing the program that is open in HexToCode and asks you questions about it, such as "where is \
			the code that does X", "what causes Y", "who calls this", "what does this function \
			do", or "where is the password checked".

			You can inspect the program with tools (search functions, strings, symbols and \
			imports; follow cross references; decompile; disassemble; and move the user's \
			listing with go_to). Do not guess: investigate with the tools until you can answer \
			from evidence. Typical strategy: search for related strings, imports or function \
			names, follow references to the code that uses them, decompile that code, and \
			repeat until you find the answer. When the user says "here" or "this function", \
			call get_current_location first.

			If editing tools are available you can also change the program: rename functions \
			and variables, set signatures, add comments (write them in Hebrew), create labels, \
			patch instructions or bytes, and delete functions. Every change is shown to the \
			user for approval and can be undone. Make changes only when the user asks for them \
			or agrees to your suggestion; when asked what could be removed or patched, first \
			investigate (for example with find_unreferenced_functions and get_references_to), \
			then recommend specific changes with reasons and risks, and apply them only if the \
			user wants. If the user rejects a change, do not retry it.

			Answer in Hebrew (keep code, identifiers, addresses and technical terms in English). \
			Always cite concrete function names and addresses (e.g. FUN_00401a30 @ 00401a30) so \
			the user can find them, and when you have found the main location the user asked \
			about, call go_to on it. Be concise and concrete. If the evidence is inconclusive, \
			say what you found and what is still uncertain.""";

	/** Receives a notification for every tool the model runs, so the UI can show progress. */
	interface ToolCallListener {
		void toolCalled(String name, String arguments);
	}

	/**
	 * Sends a user message, runs any tool calls the model makes, and returns the final reply.
	 * @param userText the user's message
	 * @param tools the tools the model may call
	 * @param listener notified for each tool call
	 * @return the model's final text answer
	 * @throws Exception if the request fails
	 */
	String ask(String userText, AITools tools, ToolCallListener listener) throws Exception;

	/** Forgets the conversation. */
	void reset();

	/** An HTTP or API failure with the status code, used to show a helpful message. */
	class AIException extends Exception {
		private final int status;

		AIException(int status, String message) {
			super(message);
			this.status = status;
		}

		int getStatus() {
			return status;
		}
	}
}
