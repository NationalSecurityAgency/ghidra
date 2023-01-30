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
import java.util.Calendar;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

/*
 * An assembler debugging information block.
 */
public class MufomBB10 extends MufomRecord {
	public String source_filename = null;
	public long tool_type = -1;
	public String version = null;
	public Calendar date;

	private void print() {
		String msg = "";
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomBB10(BinaryReader reader) throws IOException {
		Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER MufomBB10");
		source_filename = read_id(reader);
		String zero = read_id(reader);
		if (zero.length() != 0) {
			Msg.info(this, "Bad zero");
			throw new IOException();
		}
		tool_type = read_int(reader);
		if (210 == tool_type) {

		} else if (209 == tool_type) {

		} else {
			Msg.info(this, "bad tool " + tool_type);
			throw new IOException();
		}
		version = read_id(reader);

		int year = (int) read_int(reader);
		int month = (int) read_int(reader);
		int day = (int) read_int(reader);
		int hour = (int) read_int(reader);
		int minute = (int) read_int(reader);
		int second = (int) read_int(reader);
		date.set(year, month, day, hour, minute, second);
		print();
	}
}
