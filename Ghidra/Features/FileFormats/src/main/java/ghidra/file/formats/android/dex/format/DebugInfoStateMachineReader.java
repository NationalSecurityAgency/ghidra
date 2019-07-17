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

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.android.dex.util.Leb128;

import java.io.IOException;

class DebugInfoStateMachineReader {

	static int computeLength( BinaryReader reader ) throws IOException {
		int length = 0;

		while ( true ) {

			if ( length > 0x10000 ) {//don't loop forever!
				return 0;
			}

			byte opcode = reader.readNextByte( );

			++length;

            switch( opcode ) {
                case DebugStateMachineOpCodes.DBG_END_SEQUENCE: {
                    return length;//done!
                }
                case DebugStateMachineOpCodes.DBG_ADVANCE_PC: {
            		int advance = Leb128.readUnsignedLeb128( reader.readByteArray( reader.getPointerIndex( ), 5 ) );
            		int advanceLength = Leb128.unsignedLeb128Size( advance );
            		reader.setPointerIndex( reader.getPointerIndex( ) + advanceLength );
            		length += advanceLength;
                    break;
                }
                case DebugStateMachineOpCodes.DBG_ADVANCE_LINE: {
            		int advance = Leb128.readSignedLeb128( reader.readByteArray( reader.getPointerIndex( ), 5 ) );
            		int advanceLength = Leb128.signedLeb128Size( advance );
            		reader.setPointerIndex( reader.getPointerIndex( ) + advanceLength );
            		length += advanceLength;
                    break;
                }
                case DebugStateMachineOpCodes.DBG_START_LOCAL: {
            		int register = Leb128.readUnsignedLeb128( reader.readByteArray( reader.getPointerIndex( ), 5 ) );
            		int registerLength = Leb128.unsignedLeb128Size( register );
            		reader.setPointerIndex( reader.getPointerIndex( ) + registerLength );
            		length += registerLength;

            		//TODO uleb128p1
            		int name = Leb128.readUnsignedLeb128( reader.readByteArray( reader.getPointerIndex( ), 5 ) );
            		int nameLength = Leb128.unsignedLeb128Size( name );
            		reader.setPointerIndex( reader.getPointerIndex( ) + nameLength );
            		length += nameLength;

            		//TODO uleb128p1
            		int type = Leb128.readUnsignedLeb128( reader.readByteArray( reader.getPointerIndex( ), 5 ) );
            		int typeLength = Leb128.unsignedLeb128Size( type );
            		reader.setPointerIndex( reader.getPointerIndex( ) + typeLength );
            		length += typeLength;

                    break;
                }
                case DebugStateMachineOpCodes.DBG_START_LOCAL_EXTENDED: {
            		int register = Leb128.readUnsignedLeb128( reader.readByteArray( reader.getPointerIndex( ), 5 ) );
            		int registerLength = Leb128.unsignedLeb128Size( register );
            		reader.setPointerIndex( reader.getPointerIndex( ) + registerLength );
            		length += registerLength;

            		//TODO uleb128p1
            		int name = Leb128.readUnsignedLeb128( reader.readByteArray( reader.getPointerIndex( ), 5 ) );
            		int nameLength = Leb128.unsignedLeb128Size( name );
            		reader.setPointerIndex( reader.getPointerIndex( ) + nameLength );
            		length += nameLength;

            		//TODO uleb128p1
            		int type = Leb128.readUnsignedLeb128( reader.readByteArray( reader.getPointerIndex( ), 5 ) );
            		int typeLength = Leb128.unsignedLeb128Size( type );
            		reader.setPointerIndex( reader.getPointerIndex( ) + typeLength );
            		length += typeLength;

            		//TODO uleb128p1
            		int signature = Leb128.readUnsignedLeb128( reader.readByteArray( reader.getPointerIndex( ), 5 ) );
            		int signatureLength = Leb128.unsignedLeb128Size( signature );
            		reader.setPointerIndex( reader.getPointerIndex( ) + signatureLength	 );
            		length += signatureLength;

                    break;
                }
                case DebugStateMachineOpCodes.DBG_END_LOCAL: {
                	int register = Leb128.readUnsignedLeb128( reader.readByteArray( reader.getPointerIndex( ), 5 ) );
            		int registerLength = Leb128.unsignedLeb128Size( register );
            		reader.setPointerIndex( reader.getPointerIndex( ) + registerLength );
            		length += registerLength;
                    break;
                }
                case DebugStateMachineOpCodes.DBG_RESTART_LOCAL: {
                	int register = Leb128.readUnsignedLeb128( reader.readByteArray( reader.getPointerIndex( ), 5 ) );
            		int registerLength = Leb128.unsignedLeb128Size( register );
            		reader.setPointerIndex( reader.getPointerIndex( ) + registerLength );
            		length += registerLength;
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
                	int name = Leb128.readUnsignedLeb128( reader.readByteArray( reader.getPointerIndex( ), 5 ) );
            		int nameLength = Leb128.unsignedLeb128Size( name );
            		reader.setPointerIndex( reader.getPointerIndex( ) + nameLength );
            		length += nameLength;
                    break;
                }
                default: {
                	break;
                }
            }
		}
	}
}
