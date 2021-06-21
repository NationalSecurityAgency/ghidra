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
package agent.dbgmodel.model.impl;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.model.iface1.DbgModelTargetInterruptible;
import agent.dbgeng.model.iface2.DbgModelTargetObject;

public class DbgModel2TargetSystemMarkerImpl extends DbgModel2TargetObjectImpl
		implements DbgModelTargetInterruptible {

	// NB: this is an invisible marker whose only purpose if to enable an
	//  interrupt when connecting in kernel-mode to a running target
	public DbgModel2TargetSystemMarkerImpl(DbgModelTargetObject obj) {
		super(obj.getModel(), obj, "_system", "SystemMarker");
	}

	@Override
	public CompletableFuture<Void> requestAttributes(boolean refresh) {
		Map<String, Object> nmap = new HashMap<>();
		return addModelObjectAttributes(nmap);
	}

}
