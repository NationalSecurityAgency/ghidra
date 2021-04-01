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
package agent.dbgeng.model.iface2;

import java.math.BigInteger;

import agent.dbgeng.manager.impl.DbgRegister;
import ghidra.dbg.target.TargetRegister;
import ghidra.dbg.util.ConversionUtils;

public interface DbgModelTargetRegister extends DbgModelTargetObject, TargetRegister {

	@Override
	public int getBitLength();

	public DbgRegister getRegister();

	public default byte[] getBytes() {
		String val = (String) getCachedAttributes().get(VALUE_ATTRIBUTE_NAME);
		BigInteger value = new BigInteger(val, 16);
		return ConversionUtils.bigIntegerToBytes(16, value);
	}

}
