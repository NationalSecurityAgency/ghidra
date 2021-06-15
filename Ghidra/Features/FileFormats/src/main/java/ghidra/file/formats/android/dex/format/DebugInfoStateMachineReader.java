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
package ghidra.file.formats.android.dex.format;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.LEB128;

class DebugInfoStateMachineReader {
	private static final int MAX_SIZE = 0x10000; // 64k

	static int computeLength( BinaryReader reader ) throws IOException {
		long start = reader.getPointerIndex();

		while (reader.getPointerIndex() - start < MAX_SIZE) {

			byte opcode = reader.readNextByte( );

            switch( opcode ) {
                case DebugStateMachineOpCodes.DBG_END_SEQUENCE: {
					return (int) (reader.getPointerIndex() - start);//done!
                }
                case DebugStateMachineOpCodes.DBG_ADVANCE_PC: {
					LEB128.readAsUInt32(reader);
                    break;
                }
                case DebugStateMachineOpCodes.DBG_ADVANCE_LINE: {
					LEB128.readAsUInt32(reader);
                    break;
                }
                case DebugStateMachineOpCodes.DBG_START_LOCAL: {
					int register = LEB128.readAsUInt32(reader);

            		//TODO uleb128p1
					int name = LEB128.readAsUInt32(reader);

            		//TODO uleb128p1
					int type = LEB128.readAsUInt32(reader);

                    break;
                }
                case DebugStateMachineOpCodes.DBG_START_LOCAL_EXTENDED: {
					int register = LEB128.readAsUInt32(reader);

            		//TODO uleb128p1
					int name = LEB128.readAsUInt32(reader);

            		//TODO uleb128p1
					int type = LEB128.readAsUInt32(reader);

            		//TODO uleb128p1
					int signature = LEB128.readAsUInt32(reader);

                    break;
                }
                case DebugStateMachineOpCodes.DBG_END_LOCAL: {
					int register = LEB128.readAsUInt32(reader);
                    break;
                }
                case DebugStateMachineOpCodes.DBG_RESTART_LOCAL: {
					int register = LEB128.readAsUInt32(reader);
                    break;
                }
                case DebugStateMachineOpCodes.DBG_SET_PROLOGUE_END: {
                    break;
                }
                case DebugStateMachineOpCodes.DBG_SET_EPILOGUE_BEGIN: {
                    break;
                }
                case DebugStateMachineOpCodes.DBG_SET_FILE: {
                	//TODO uleb128p1
					int name = LEB128.readAsUInt32(reader);
                    break;
                }
                default: {
                	break;
                }
            }
		}

		return 0;
	}
}
