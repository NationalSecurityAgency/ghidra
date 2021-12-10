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

/**
 * Debug info opcodes and constants
 *
 */
public final class DebugInfoOpcodes {

	public final static byte DBG_END_SEQUENCE = 0x00;
	public final static byte DBG_ADVANCE_PC = 0x01;
	public final static byte DBG_ADVANCE_LINE = 0x02;
	public final static byte DBG_START_LOCAL = 0x03;
	public final static byte DBG_START_LOCAL_EXTENDED = 0x04;
	public final static byte DBG_END_LOCAL = 0x05;
	public final static byte DBG_RESTART_LOCAL = 0x06;
	public final static byte DBG_SET_PROLOGUE_END = 0x07;
	public final static byte DBG_SET_EPILOGUE_BEGIN = 0x08;
	public final static byte DBG_SET_FILE = 0x09;
	public final static byte DBG_FIRST_SPECIAL = 0x0a;
	public final static byte DBG_LINE_BASE = -4;
	public final static byte DBG_LINE_RANGE = 15;

}
