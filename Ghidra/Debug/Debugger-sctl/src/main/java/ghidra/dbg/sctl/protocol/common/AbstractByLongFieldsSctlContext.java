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
package ghidra.dbg.sctl.protocol.common;

import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

public abstract class AbstractByLongFieldsSctlContext extends AbstractSctlContext {

	@Override
	public Map<String, byte[]> toMap() {
		Map<String, byte[]> result = new LinkedHashMap<>();
		ByteBuffer buf = ByteBuffer.allocate(Long.BYTES);
		buf.order(ByteOrder.BIG_ENDIAN);
		for (Field fld : getClass().getFields()) {
			try {
				buf.putLong(0, fld.getLong(this));
			}
			catch (IllegalArgumentException | IllegalAccessException e) {
				throw new AssertionError(e);
			}
			result.put(fld.getName(), Arrays.copyOf(buf.array(), Long.BYTES));
		}
		return result;
	}

	@Override
	public Set<String> getRegisterNames() {
		Set<String> result = new LinkedHashSet<>();
		for (Field fld : getClass().getFields()) {
			result.add(fld.getName());
		}
		return result;
	}

	@Override
	public void updateFromMap(Map<String, byte[]> values) {
		try {
			Class<?> cls = getClass();
			ByteBuffer buf = ByteBuffer.allocate(Long.BYTES);
			buf.order(ByteOrder.BIG_ENDIAN);
			for (Map.Entry<String, byte[]> ent : values.entrySet()) {
				buf.putLong(0, 0);
				buf.position(0);
				byte[] val = ent.getValue();
				buf.put(val, Long.BYTES - val.length, val.length);
				Field fld = cls.getField(ent.getKey());
				fld.setLong(this, buf.getLong(0));
			}
		}
		catch (NoSuchFieldException | SecurityException | IllegalArgumentException
				| IllegalAccessException e) {
			throw new AssertionError(e);
		}
	}

	@Override
	public void update(String name, byte[] value) {
		try {
			Class<?> cls = getClass();
			ByteBuffer buf = ByteBuffer.allocate(Long.BYTES);
			buf.order(ByteOrder.BIG_ENDIAN);
			buf.put(value, Long.BYTES - value.length, value.length);
			Field fld = cls.getField(name);
			fld.setLong(this, buf.getLong(0));
		}
		catch (NoSuchFieldException | IllegalArgumentException | IllegalAccessException e) {
			throw new AssertionError(e);
		}
	}
}
