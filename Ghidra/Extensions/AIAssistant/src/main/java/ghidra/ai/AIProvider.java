/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
			You are an expert reverse engineer built into Ghidra. The user is analyzing the \
			program that is open in Ghidra and asks you questions about it, such as "where is \
			the code that does X", "what causes Y", "who calls this", "what does this function \
			do", or "where is the password checked".

			You can inspect the program with tools (search functions, strings, symbols and \
			imports; follow cross references; decompile; disassemble; and move the user's \
			listing with go_to). Do not guess: investigate with the tools until you can answer \
			from evidence. Typical strategy: search for related strings, imports or function \
			names, follow references to the code that uses them, decompile that code, and \
			repeat until you find the answer. When the user says "here" or "this function", \
			call get_current_location first.

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
