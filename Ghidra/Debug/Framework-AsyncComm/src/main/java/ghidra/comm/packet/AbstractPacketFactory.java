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
package ghidra.comm.packet;

import java.lang.reflect.*;
import java.util.*;

/**
 * A partial implementation of {@link PacketFactory}
 * 
 * This implementation provides reasonable defaults for arrays, lists, and sets. It also provides an
 * easy mechanism {@link #useFor(Class, Class)} to substitute a given class or interface for one of
 * its concrete subclasses or implementations.
 */
public abstract class AbstractPacketFactory implements PacketFactory {
	private Map<Class<?>, Class<?>> substs = new HashMap<>();

	/**
	 * Construct a new packet factory
	 * 
	 * This applies the default substitutions: {@link ArrayList} for {@link List}, and
	 * {@link LinkedHashSet} for {@link Set}.
	 */
	public AbstractPacketFactory() {
		useFor(List.class, ArrayList.class);
		useFor(Set.class, LinkedHashSet.class);
	}

	/**
	 * Specify an additional substitution for collections and packets
	 * 
	 * When requested to construct a new collection or packet, the factory will check its map of
	 * substitutions. If one is present, the substituted class is constructed instead. If one is not
	 * present, then the factory attempts to construct the requested class, which may result in an
	 * {@link InstantiationException}.
	 * 
	 * @param abs the class, usually abstract, or interface to substitute out
	 * @param impl the concrete implementation to substitute in
	 */
	protected <T> void useFor(Class<T> abs, Class<? extends T> impl) {
		if (Modifier.isAbstract(impl.getModifiers())) {
			throw new IllegalArgumentException("Implementation class must not be abstract");
		}
		substs.put(abs, impl);
	}

	/**
	 * Check if a given class has been substituted
	 * 
	 * @param abs the class to check for substitutions
	 * @return the concrete substitution, if specified, or null
	 */
	@SuppressWarnings("unchecked")
	protected <T> Class<? extends T> getFor(Class<T> abs) {
		return (Class<? extends T>) substs.get(abs);
	}

	@Override
	public Object newArray(Class<?> componentType, int length) {
		return Array.newInstance(componentType, length);
	}

	@Override
	public <E, C extends Collection<E>> C newCollection(Class<C> colType, Class<E> elemType)
			throws InstantiationException, IllegalAccessException, IllegalArgumentException,
			InvocationTargetException, NoSuchMethodException, SecurityException {
		Class<? extends C> use = getFor(colType);
		if (use != null) {
			return use.getConstructor().newInstance();
		}
		return colType.getConstructor().newInstance();
	}

	@Override
	public <P extends Packet> P newPacket(Class<P> pktType)
			throws InstantiationException, IllegalAccessException, IllegalArgumentException,
			InvocationTargetException, NoSuchMethodException, SecurityException {
		Class<? extends P> use = getFor(pktType);
		if (use != null) {
			return use.getConstructor().newInstance();
		}
		return pktType.getConstructor().newInstance();
	}

	@SuppressWarnings("unchecked")
	@Override
	public void registerTypes(PacketCodec<?> codec) {
		for (Map.Entry<Class<?>, Class<?>> ent : substs.entrySet()) {
			Class<?> abs = ent.getKey();
			if (Packet.class.isAssignableFrom(abs)) {
				codec.registerPacketType((Class<? extends Packet>) abs);
			}
			Class<?> impl = ent.getValue();
			if (Packet.class.isAssignableFrom(impl)) {
				codec.registerPacketType((Class<? extends Packet>) impl);
			}
		}
	}
}
