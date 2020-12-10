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
import ghidra.dbg.sctl.protocol.common.AbstractSctlProcessList;

/**
 * The format for {@code bytes[]} of SCTL's {@code Rps} reply for Linux dialects
 */
public class Sctl2018ProcessList extends AbstractSctlProcessList {
	@PacketField
	public long ntarg;

	@PacketField
	@RepeatedField
	@CountedByField("ntarg")
	public List<Sctl2018ProcessEntry> processes = new ArrayList<>();

	@Override
	public List<Sctl2018ProcessEntry> getProcesses() {
		return processes;
	}

	@Override
	public Sctl2018ProcessEntry addProcess() {
		Sctl2018ProcessEntry proc = new Sctl2018ProcessEntry();
		processes.add(proc);
		return proc;
	}
}
