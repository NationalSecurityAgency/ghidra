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
package agent.dbgeng.model.impl;

import java.util.List;
import java.util.Map;

import agent.dbgeng.manager.DbgEventFilter;
import agent.dbgeng.model.iface2.DbgModelTargetEvent;
import agent.dbgeng.model.iface2.DbgModelTargetEventContainer;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "Event",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Object.class) })
public class DbgModelTargetEventImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetEvent {
	protected static String indexFilter(DbgEventFilter filter) {
		return filter.getName();
	}

	protected static String keyFilter(DbgEventFilter filter) {
		return PathUtils.makeKey(indexFilter(filter));
	}

	private DbgEventFilter filter;

	public DbgModelTargetEventImpl(DbgModelTargetEventContainer events, DbgEventFilter filter) {
		super(events.getModel(), events, keyFilter(filter), "EventFilter");
		this.getModel().addModelObject(filter, this);
		this.filter = filter;

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getIndex(), //
			"Command", filter.getCmd(), //
			"Execute", filter.getExecutionOption(), //
			"Continue", filter.getContinueOption() //
		), "Initialized");
	}

	@Override
	public DbgEventFilter getFilter() {
		return filter;
	}

}
