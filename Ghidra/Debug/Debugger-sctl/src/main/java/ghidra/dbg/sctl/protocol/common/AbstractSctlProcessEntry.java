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
package ghidra.dbg.sctl.protocol.common;

import java.util.List;

import ghidra.comm.packet.Packet;

/**
 * An attachable target process entry
 * 
 * This is a dialect-defined format.
 */
public abstract class AbstractSctlProcessEntry extends Packet {
	/**
	 * Get the process ID
	 * 
	 * @return the process ID
	 */
	public abstract long getProcessID();

	/**
	 * Set the process ID
	 * 
	 * @param pid the process ID
	 */
	public abstract void setProcessID(long pid);

	/**
	 * Get the command that launched the process
	 * 
	 * Alternatively, this may be any textual description of the process
	 * 
	 * @return the command
	 */
	public abstract String getCommand();

	/**
	 * Set the command that launched the process
	 * 
	 * Alternatively, this may be any textual description of the process
	 * 
	 * @param cmd the command
	 */
	public abstract void setCommand(String cmd);

	/**
	 * Get the threads in the process
	 * 
	 * @return a list of thread entries
	 */
	public abstract List<? extends AbstractSctlThreadEntry> getThreads();

	/**
	 * Add a thread to the thread list
	 * 
	 * @return the new, empty thread entry
	 */
	public abstract AbstractSctlThreadEntry addThread();
}
