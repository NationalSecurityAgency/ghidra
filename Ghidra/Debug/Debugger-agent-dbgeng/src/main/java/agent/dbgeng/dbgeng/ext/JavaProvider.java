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
package agent.dbgeng.dbgeng.ext;

import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgeng.dbgeng.DebugClient;
import agent.dbgeng.impl.dbgeng.client.DebugClientInternal;
import agent.dbgeng.jna.dbgeng.client.WrapIDebugClient;
import agent.dbgeng.jna.javaprovider.JavaProviderNative;

/**
 * Wrapper for "javaprovider" plugin library
 * 
 * @deprecated In one (abandoned) use case, the SCTL server can be loaded as a
 *             "{@code engext.cpp}-style" plugin, presumably into any {@code dbgeng.dll}-powered
 *             debugger. This is accomplished by embedding the JVM into the plugin, and then calling
 *             an alternative entry point. This plugin also provides a utility function for invoking
 *             {@code CreateClient} on the client provided to the plugin by the host debugger.
 */
@Deprecated
public class JavaProvider {
	public static DebugClient createClient() {
		PointerByReference pClient = new PointerByReference();
		COMUtils.checkRC(JavaProviderNative.INSTANCE.createClient(pClient.getPointer()));
		WrapIDebugClient wrap = new WrapIDebugClient(pClient.getValue());

		try {
			return DebugClientInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}
}
