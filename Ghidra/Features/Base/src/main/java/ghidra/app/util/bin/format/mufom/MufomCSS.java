/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License; Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing; software
 * distributed under the License is distributed on an "AS IS" BASIS;
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND; either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.mufom;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

/*
 * 9.2 CCS (checksum with sum) Command
 */
public class MufomCSS extends MufomRecord {
	public static final String NAME = "CSS";
	public static final int record_type = MufomType.MUFOM_CMD_CSS;
	public static final int record_subtype = -1;
	public long record_start = -1;

	public MufomCSS(BinaryReader reader) throws IOException {
		record_start = reader.getPointerIndex();
		read_record_type(reader, record_type, record_subtype, NAME);
		Msg.info(this, "unimplemented " + NAME);
		throw new IOException();
	}
}
