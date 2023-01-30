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
 * 8.1 MB (module begin) Command
 *
 * MB-command → “MB” target-machine-configuration (“,” module-name)? “.”
 * target-machine-configuration → identifier
 * module-name → char-string
 *
 * {$E0}{Id1}{Id2}
 */
public class MufomMB extends MufomRecord {
	public static final String NAME = "MB";
	public static final int record_type = MufomType.MUFOM_CMD_MB;
	public static final int record_subtype = -1;
	public long record_start = -1;
	public String target_machine_configuration = null;
	public String module_name = null;

	public void print() {
		String msg = NAME + ": " + target_machine_configuration + " " + module_name;
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}
	public MufomMB(BinaryReader reader) throws IOException {
		record_start = reader.getPointerIndex();
		read_record_type(reader, record_type, record_subtype, NAME);
		target_machine_configuration = read_id(reader);
		module_name = read_opt_id(reader);
		print();
	}
}
