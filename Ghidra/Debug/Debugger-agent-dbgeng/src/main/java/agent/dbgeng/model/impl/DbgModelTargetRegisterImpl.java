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

import agent.dbgeng.manager.impl.DbgRegister;
import agent.dbgeng.model.iface2.DbgModelTargetRegister;
import agent.dbgeng.model.iface2.DbgModelTargetRegisterContainerAndBank;
import ghidra.dbg.target.TargetRegister;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(name = "RegisterDescriptor", elements = {
	@TargetElementType(type = Void.class) }, attributes = {
		@TargetAttributeType(name = TargetRegister.CONTAINER_ATTRIBUTE_NAME, type = DbgModelTargetRegisterContainerImpl.class),
		@TargetAttributeType(type = Void.class) })
public class DbgModelTargetRegisterImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetRegister {

	protected static String indexRegister(DbgRegister register) {
		String name = register.getName();
		if ("".equals(name)) {
			return "UNNAMED," + register.getNumber();
		}
		return name;
	}

	protected static String keyRegister(DbgRegister register) {
		return PathUtils.makeKey(indexRegister(register));
	}

	protected final DbgModelTargetRegisterContainerAndBank registers;
	protected final DbgRegister register;

	protected final int bitLength;

	public DbgModelTargetRegisterImpl(DbgModelTargetRegisterContainerAndBank registers,
			DbgRegister register) {
		super(registers.getModel(), registers, keyRegister(register), "Register");
		this.getModel().addModelObject(register, this);
		this.registers = registers;
		this.register = register;

		this.bitLength = register.getSize() * 8;

		changeAttributes(List.of(), List.of(), Map.of( //
			CONTAINER_ATTRIBUTE_NAME, registers, //
			LENGTH_ATTRIBUTE_NAME, bitLength, //
			DISPLAY_ATTRIBUTE_NAME, "[" + register.getName() + "]" //
		), "Initialized");
	}

	@Override
	public int getBitLength() {
		return bitLength;
	}

	@Override
	public DbgRegister getRegister() {
		return register;
	}
}
