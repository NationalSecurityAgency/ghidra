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
package agent.gdb.manager;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.gdb.manager.impl.GdbMinimalSymbol;

public interface GdbModule {
	String getName();

	CompletableFuture<Long> computeBase();

	CompletableFuture<Long> computeMax();

	Long getKnownBase();

	Long getKnownMax();

	CompletableFuture<Map<String, GdbModuleSection>> listSections();

	Map<String, GdbModuleSection> getKnownSections();

	CompletableFuture<Map<String, GdbMinimalSymbol>> listMinimalSymbols();

}
