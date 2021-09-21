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

import agent.dbgeng.manager.DbgExceptionFilter;
import agent.dbgeng.model.iface2.DbgModelTargetEventContainer;
import agent.dbgeng.model.iface2.DbgModelTargetException;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;

@TargetObjectSchemaInfo(
	name = "Module",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(
			name = "Symbols",
			type = DbgModelTargetSymbolContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(name = "BaseAddress", type = Address.class),
		@TargetAttributeType(name = "ImageName", type = String.class),
		@TargetAttributeType(name = "TimeStamp", type = Integer.class),
		@TargetAttributeType(name = "Len", type = String.class),
		@TargetAttributeType(type = Void.class) })
public class DbgModelTargetExceptionImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetException {
	protected static String indexFilter(DbgExceptionFilter filter) {
		return filter.getName();
	}

	protected static String keyFilter(DbgExceptionFilter filter) {
		return PathUtils.makeKey(indexFilter(filter));
	}

	private DbgExceptionFilter filter;

	public DbgModelTargetExceptionImpl(DbgModelTargetEventContainer events,
			DbgExceptionFilter filter) {
		super(events.getModel(), events, keyFilter(filter), "ExceptionFilter");
		this.getModel().addModelObject(filter, this);
		this.filter = filter;

		/*
		changeAttributes(List.of(), List.of( //
			symbols //
		//  sections.getName(), sections, //
		), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getIndex(), //
			SHORT_DISPLAY_ATTRIBUTE_NAME, module.getName(), //
			MODULE_NAME_ATTRIBUTE_NAME, module.getImageName(), //
			"BaseAddress", space.getAddress(module.getKnownBase()), //
			"ImageName", module.getImageName(), //
			"TimeStamp", module.getTimeStamp(), //
			"Len", Integer.toHexString(module.getSize()) //
		), "Initialized");
		*/
	}

	@Override
	public DbgExceptionFilter getFilter() {
		return filter;
	}

}
