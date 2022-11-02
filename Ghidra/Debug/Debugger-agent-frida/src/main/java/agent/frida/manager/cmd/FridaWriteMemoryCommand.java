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

import agent.frida.manager.impl.FridaManagerImpl;
import ghidra.program.model.address.Address;

public class FridaWriteMemoryCommand extends AbstractFridaCommand<Void> {

	private final Address addr;
	private final ByteBuffer buf;
	private final int len;

	public FridaWriteMemoryCommand(FridaManagerImpl manager, Address addr, ByteBuffer buf, int len) {
		super(manager);
		this.addr = addr;
		this.buf = buf.duplicate();
		this.len = len;
	}

	@Override
	public void invoke() {
		//TODO: This is completely untested and probably will not work
		String bufstr = buf.toString();
		manager.loadScript(this, "write_memory",      
				"var buf = []; " +
				"var str = '" + bufstr + "';" +
				"var len = " + len + ";" +
				"for (var i = 0; i < len; ++i) {" +
				"  var code = str.charCodeAt(i);" +
				"  buf = buf.concat([code]);" +
				"}" +
				"ptr(0x"+addr+").writeByteArray(buf);");
	}

}
