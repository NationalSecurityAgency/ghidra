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
package ghidra.comm.packet.fields;

import java.lang.reflect.Field;

import ghidra.comm.packet.Packet;

/**
 * An abstract implementation of {@link FieldCodec} associated with a registered packet type and
 * field
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 * @param <T> the type linking this codec to the next codec down the chain, or to the annotated
 *            field
 */
public abstract class AbstractFieldCodec<ENCBUF, DECBUF, T>
		implements FieldCodec<ENCBUF, DECBUF, T> {

	/**
	 * Assuming val has an integral value, get it
	 * 
	 * @param val an object of type {@link Byte}, {@link Short}, {@link Integer}, or {@link Long}
	 * @return the value as a {@code long}
	 */
	public static long getIntegralValue(Object val) {
		if (val instanceof Byte) {
			return (Byte) val;
		}
		else if (val instanceof Short) {
			return (Short) val;
		}
		else if (val instanceof Integer) {
			return (Integer) val;
		}
		else if (val instanceof Long) {
			return (Long) val;
		}
		throw new IllegalArgumentException(val + " is not an integral type");
	}

	/**
	 * Convert a long to {@link Byte}, {@link Short}, {@link Integer}, or {@link Long}
	 * 
	 * @param type the desired type
	 * @param val the value
	 * @return the value as the desired type, if possible
	 */
	@SuppressWarnings("unchecked")
	public static <T> T getIntegralOfType(Class<T> type, long val) {
		if (type == byte.class || Byte.class.isAssignableFrom(type)) {
			return (T) Byte.valueOf((byte) val);
		}
		else if (type == short.class || Short.class.isAssignableFrom(type)) {
			return (T) Short.valueOf((short) val);
		}
		else if (type == int.class || Integer.class.isAssignableFrom(type)) {
			return (T) Integer.valueOf((int) val);
		}
		else if (type == long.class || Long.class.isAssignableFrom(type)) {
			return (T) Long.valueOf(val);
		}
		throw new IllegalArgumentException(type + " is not an integral type");
	}

	/**
	 * Check if a type is {@link Byte}, {@link Short}, {@link Integer}, or {@link Long}
	 * 
	 * @param type the type
	 * @return true, if the type represents an integral value
	 */
	public static boolean isIntegralType(Class<?> type) {
		if (type == byte.class || Byte.class.isAssignableFrom(type)) {
			return true;
		}
		else if (type == short.class || Short.class.isAssignableFrom(type)) {
			return true;
		}
		else if (type == int.class || Integer.class.isAssignableFrom(type)) {
			return true;
		}
		else if (type == long.class || Long.class.isAssignableFrom(type)) {
			return true;
		}
		return false;
	}

	protected final Class<? extends Packet> pktType;
	protected final Field field;

	/**
	 * Construct a new {@code AbstractFieldCodec}
	 * 
	 * @param pktType the packet type with which this field codec is registered
	 * @param field the field in whose chain this field codec resides
	 */
	public AbstractFieldCodec(Class<? extends Packet> pktType, Field field) {
		this.pktType = pktType;
		this.field = field;
	}
}
