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
package ghidra.app.plugin.processors.generic;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.ProcessorContext;
import ghidra.program.model.mem.MemBuffer;

/**
 * 
 *
 * To change this generated comment edit the template variable "typecomment":
 * {@literal Window>Preferences>Java>Templates.}
 * To enable and disable the creation of type comments go to
 * {@literal Window>Preferences>Java>Code Generation.}
 */
public class Position {

	private MemBuffer buf;
	private Address startAddr;
	private Address nextAddr;
	ProcessorContext context;

	public Position(MemBuffer b, Address start, Address next, ProcessorContext c) {
		buf = b;
		startAddr = start;
		nextAddr = next;
		context = c;
	}

	public MemBuffer buffer() {return buf;}
	public Address startAddr() {return startAddr;}
	public Address nextAddr() {return nextAddr;}
	public ProcessorContext context() {return context;}

}
