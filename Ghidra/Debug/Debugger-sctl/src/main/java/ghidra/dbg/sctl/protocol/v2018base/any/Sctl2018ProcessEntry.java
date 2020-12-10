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
package ghidra.dbg.sctl.protocol.v2018base.any;

import java.util.ArrayList;
import java.util.List;

import ghidra.comm.packet.annot.CountedByField;
import ghidra.comm.packet.annot.RepeatedField;
import ghidra.comm.packet.fields.PacketField;
import ghidra.dbg.sctl.protocol.common.AbstractSctlProcessEntry;
import ghidra.dbg.sctl.protocol.common.SctlString;

/**
 * The format for each process of {@code bytes[]} of SCTL's {@code Rps} reply for Linux dialects
 */
public class Sctl2018ProcessEntry extends AbstractSctlProcessEntry {
	@PacketField
	public long pid;

	@PacketField
	public SctlString cmd;

	@PacketField
	public long nt;

	@PacketField
	@RepeatedField
	@CountedByField("nt")
	public List<Sctl2018ThreadEntry> threads = new ArrayList<>();

	@Override
	public long getProcessID() {
		return pid;
	}

	@Override
	public void setProcessID(long pid) {
		this.pid = pid;
	}

	@Override
	public String getCommand() {
		return cmd.str;
	}

	@Override
	public void setCommand(String cmd) {
		this.cmd = new SctlString(cmd);
	}

	@Override
	public List<Sctl2018ThreadEntry> getThreads() {
		return threads;
	}

	@Override
	public Sctl2018ThreadEntry addThread() {
		Sctl2018ThreadEntry t = new Sctl2018ThreadEntry();
		threads.add(t);
		return t;
	}
}
