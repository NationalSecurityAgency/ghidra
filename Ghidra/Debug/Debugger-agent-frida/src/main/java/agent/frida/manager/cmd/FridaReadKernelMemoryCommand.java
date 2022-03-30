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
package agent.frida.manager.cmd;

import java.nio.ByteBuffer;

import com.google.common.collect.Range;
import com.google.common.collect.RangeSet;
import com.google.common.collect.TreeRangeSet;
//import com.sun.jna.Pointer;
//import com.sun.jna.ptr.PointerByReference;
import com.google.gson.JsonElement;

import agent.frida.manager.impl.FridaManagerImpl;
import ghidra.program.model.address.Address;
import ghidra.util.NumericUtilities;

public class FridaReadKernelMemoryCommand extends AbstractFridaCommand<RangeSet<Long>> {

	private final Address addr;
	private final ByteBuffer buf;
	private final int len;

	public FridaReadKernelMemoryCommand(FridaManagerImpl manager, Address addr, ByteBuffer buf, int len) {
		super(manager);
		this.addr = addr;
		this.buf = buf;
		this.len = len;
	}

	@Override
	public RangeSet<Long> complete(FridaPendingCommand<?> pending) {
		RangeSet<Long> rangeSet = TreeRangeSet.create();
		rangeSet.add(Range.closedOpen(addr.getOffset(), addr.getOffset() + len));
		return rangeSet;
	}

	
	@Override
	public void invoke() {
		manager.loadScript(this, "read_memory",      
			"var buf = Kernel.readByteArray(ptr(0x"+addr+")"+len+"); result = hexdump(buf, {header:false});");
	}
	
	@Override
	public void parseSpecifics(JsonElement element) {
		String payload = element.getAsString();
		String[] lines = payload.split("\n");
		int n = 0;
		for (String l : lines) {
			String[] split = l.split("  ");
			byte[] bytes = NumericUtilities.convertStringToBytes(split[1]);
			for (int i = 0; i < 16; i++) {
				buf.put(n+i, bytes[i]);
			}
			n += 16;
		}
	}

}
