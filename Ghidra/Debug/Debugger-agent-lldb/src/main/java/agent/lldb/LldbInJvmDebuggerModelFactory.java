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
package agent.lldb;

import java.util.concurrent.CompletableFuture;

import agent.lldb.model.impl.LldbModelImpl;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.util.ConfigurableFactory.FactoryDescription;
import ghidra.util.classfinder.ExtensionPointProperties;

/**
 * Note this is in the testing source because it's not meant to be shipped in the release.... That
 * may change if it proves stable, though, no?
 */
@FactoryDescription( //
	brief = "IN-VM lldb local debugger", //
	htmlDetails = "Launch a lldb session in this same JVM" //
)
@ExtensionPointProperties(priority = 80)
public class LldbInJvmDebuggerModelFactory implements DebuggerModelFactory {

	// TODO remoteTransport option?

	@Override
	public CompletableFuture<? extends DebuggerObjectModel> build() {
		LldbModelImpl model = new LldbModelImpl();
		return model.startLLDB(new String[] {}).thenApply(__ -> model);
	}

	@Override
	public boolean isCompatible() {
		String osname = System.getProperty("os.name");
		return osname.contains("Mac OS X") || osname.contains("Linux") || osname.contains("Windows");
	}

}
