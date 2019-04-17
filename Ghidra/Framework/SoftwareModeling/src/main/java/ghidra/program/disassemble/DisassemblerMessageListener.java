/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.disassemble;

import ghidra.util.Msg;

/**
 * Interface for reporting disassembly messages
 */
public interface DisassemblerMessageListener {
	/**
	 * Ignores all messages from the disassembler.
	 */
    public final static DisassemblerMessageListener IGNORE = new DisassemblerMessageListener() {
        public void disassembleMessageReported(String msg) {//don't care...
        }
    };

    /**
     * Writes all messages from disassembler to the console.
     */
    public final static DisassemblerMessageListener CONSOLE = new DisassemblerMessageListener() {
		public void disassembleMessageReported(String msg) {
			Msg.debug(this, "DisassemblerMessageListener: "+msg);
		}
	};

	/**
	 * Method called to display disassembly progress messasges
	 * @param msg the message to display.
	 */
	void disassembleMessageReported(String msg); 
}
