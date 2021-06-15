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
package agent.dbgmodel;

import java.util.concurrent.CompletableFuture;

import agent.dbgmodel.model.impl.DbgModel2Impl;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.util.ConfigurableFactory.FactoryDescription;

/**
 * Note this is in the testing source because it's not meant to be shipped in the release.... That
 * may change if it proves stable, though, no?
 */
@FactoryDescription( //
	brief = "IN-VM MS dbgmodel local debugger", //
	htmlDetails = "Launch a dbgmodel session in this same JVM" //
)
public class DbgModelInJvmDebuggerModelFactory implements DebuggerModelFactory {

	@Override
	public CompletableFuture<? extends DebuggerObjectModel> build() {
		DbgModel2Impl model = new DbgModel2Impl();
		return model.startDbgEng(new String[] {}).thenApply(__ -> model);
	}

	@Override
	public boolean isCompatible() {
		return System.getProperty("os.name").toLowerCase().contains("windows");
	}

}
