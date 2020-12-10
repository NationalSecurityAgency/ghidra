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

import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

/**
 * A factory for instantiating abstract types found in packet fields
 * 
 * This permits a pluggable means of implementing multiple protocol versions and/or dialects while
 * locating most of the version-specific logic in one object. Generally each packet factory
 * implements the details of one version.
 * 
 * Whenever an abstract packet type, array, or collection is encountered during decode, the packet
 * factory is used to create an empty instance ready to be populated with the decoded data. Thus, if
 * a portion of a packet is known to vary from version to version, the main protocol need only
 * specify an abstract type. One factory then instantiates the format for one version, while another
 * factory can do the same for another version. The codec will take care of the specifics for
 * decoding each format, e.g:
 * 
 * Most implementations should extend {@link AbstractPacketFactory}, which provides reasonable
 * defaults for all but {@link #newPacket(Class)}.
 * 
 * <pre>
 * public class Person {
 * 	&#64;PacketField
 * 	&#64;NullTerminated
 * 	public String name;
 * 
 * 	&#64;PacketField
 * 	public AbstractAgeSpec ageSpec;
 * }
 * 
 * public abstract class AbstractAgeSpec {
 * }
 * 
 * public abstract class Age extends AbstractAgeSpec {
 * 	&#64;PacketField
 * 	public byte age; // in years
 * }
 * 
 * public abstract class Birthday extends AbstractAgeSpec {
 * 	&#64;PacketField
 * 	public short birthYear;
 * 
 * 	&#64;PacketField
 * 	public byte birthMonth;
 * 
 * 	&#64;PacketField
 * 	public byte birthDay;
 * }
 * 
 * public class Version1Factory extends AbstractPacketFactory {
 * 	&#64;Override
 * 	public <P extends Packet> P newPacket(Class<P> pktType) {
 * 		if (AbstractAgeSpec.class.equals(pktType)) {
 * 			return new Age();
 * 		}
 * 	}
 * 
 * 	public void registerTypes(PacketCodec<?, ?, ?> codec) {
 * 		codec.registerPacketType(Age.class);
 * 	}
 * }
 * 
 * public class Version2Factory extends AbstractPacketFactory {
 * 	&#64;Override
 * 	public <P extends Packet> P newPacket(Class<P> pktType) {
 * 		if (AbstractAgeSpec.class.equals(pktType)) {
 * 			return new Birthday();
 * 		}
 * 	}
 * 
 * 	public void registerTypes(PacketCodec<?, ?, ?> codec) {
 * 		codec.registerPacketType(Birthday.class);
 * 	}
 * }
 * </pre>
 * 
 * Now, the version can be selected statically or dynamically:
 * 
 * <pre>
 * PacketFactory version = negotiateVersion();
 * version.registerTypes(codec);
 * Person p = codec.decodePacket(Person.class, buf, version);
 * </pre>
 * 
 * Granted, there may still be specific logic to processing a birthday vs. an age, but a developer
 * can factor this into objects that already exist. It is possible, for example, to define abstract
 * methods in {@code AbstractAgeSpec} to obtain the person's age and/or birthday given the current
 * date. Or, it is possible to define a new abstract class extending {@code PacketFactory} and
 * define each version's implemented to extend it. The abstract class can then define methods that
 * each version must implement for the protocol to work in general.
 */
public interface PacketFactory {

	/**
	 * Instantiate an array
	 * 
	 * Implementors need rarely if ever override this method. The default simply calls
	 * {@link Array#newInstance(Class, int)}.
	 * 
	 * @param componentType the type of element in the array
	 * @param length the number of elements in the array
	 * @return the new array
	 */
	public Object newArray(Class<?> componentType, int length);

	/**
	 * Construct a new collection of a given type
	 * 
	 * This is mostly so that packets do not need to specify the exact type of collection. It is
	 * sufficient to declare, e.g., {@code @PacketField public List<Integer> intList} instead of
	 * {@code ArrayList<Integer>}.
	 * 
	 * The default uses {@link ArrayList} for {@link List} and {@link LinkedHashSet} for
	 * {@link Set}. Any other class is instantiated as requested, possibly throwing an
	 * {@link InstantiationException}.
	 * 
	 * @param colType the type of collection to instantiate
	 * @param elemType the type of element stored in the collection
	 * @return the new collection
	 * @throws InstantiationException if the requested type cannot be instantiated
	 * @throws IllegalAccessException if the requested type is not accessible
	 * @throws SecurityException
	 * @throws NoSuchMethodException
	 * @throws InvocationTargetException
	 * @throws IllegalArgumentException
	 */
	public <E, C extends Collection<E>> C newCollection(Class<C> colType, Class<E> elemType)
			throws InstantiationException, IllegalAccessException, IllegalArgumentException,
			InvocationTargetException, NoSuchMethodException, SecurityException;

	/**
	 * Construct a new blank packet of a given type
	 * 
	 * @param pktType the type of packet, usually abstract, to instantiate
	 * @return the new packet
	 * @throws InstantiationException if the requested type cannot be instantiated
	 * @throws IllegalAccessException if the requested type is not accessible
	 * @throws SecurityException
	 * @throws NoSuchMethodException
	 * @throws InvocationTargetException
	 * @throws IllegalArgumentException
	 */
	public <P extends Packet> P newPacket(Class<P> pktType)
			throws InstantiationException, IllegalAccessException, IllegalArgumentException,
			InvocationTargetException, NoSuchMethodException, SecurityException;

	/**
	 * Register the types used by this factory with the given codec
	 * 
	 * The developer must call this method before passing this factory to any decode method.
	 * Otherwise, the codec may attempt to decode a packet type that has not been registered. Using
	 * a {@link AbstractPacketMarshaller} may ease this burden. It has some conveniences for
	 * handling packet factories.
	 * 
	 * @param codec the codec with which to register the version-specific packet types
	 */
	public void registerTypes(PacketCodec<?> codec);
}
