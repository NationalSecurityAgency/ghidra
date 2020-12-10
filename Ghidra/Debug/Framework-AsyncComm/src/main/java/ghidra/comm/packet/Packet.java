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
import java.nio.ByteBuffer;
import java.util.*;

import org.apache.commons.lang3.StringUtils;

import com.google.common.collect.ImmutableMap;

import ghidra.comm.packet.annot.*;
import ghidra.comm.packet.binary.*;
import ghidra.comm.packet.err.*;
import ghidra.comm.packet.fields.PacketField;
import ghidra.comm.packet.string.*;
import ghidra.graph.*;
import ghidra.graph.algo.SorterException;
import ghidra.graph.algo.TopologicalSorter;

/**
 * A class with customizable serialization via {@link PacketField} annotations
 * 
 * The goal of the packet library is to ease serialization and de-serialization of network packets.
 * Instead of providing methods to serialize and de-serialize primitives, and requiring a developer
 * to apply these conversely, it instead provides annotations which are applied to the fields to
 * serialize and de-serialize. The developer can then provide pluggable methods for serializing and
 * de-serializing various types. Of course, the library provides default implementations which
 * suffice for most uses. Consider an example:
 * 
 * <pre>
 * public class Person extends Packet {
 * 	&#64;PacketField
 * 	&#64;NullTerminated
 * 	public String name;
 * 
 * 	&#64;PacketField
 * 	public byte age;
 * }
 * </pre>
 * 
 * Note that all fields to be encoded must be public, and there must be a default constructor. The
 * {@link PacketField} annotation indicates which fields are encoded. They are encoded in order of
 * declaration unless another annotation prescribes otherwise. Other annotations modify the encoding
 * and decoding methods applied. For example, the {@link NullTerminated} annotation modifies
 * encoding so that a null terminator is inserted after the encoded field. Conversely, it modifies
 * the decoding so that decoding the field consumes exactly the data preceding the next null
 * terminator, and then the annotation consumes the null terminator. Were this annotation not
 * applied, the {@code name} field would not be decoded correctly, as it would consume the data
 * encoded for {@code age} as well.
 * 
 * The packet then must be registered with a codec. The codec provides the methods for encoding and
 * decoding primitive types, arrays, lists, etc. A single packet type may be registered with
 * multiple codecs. To encode the packet as binary data in a {@link ByteBuffer}, use the provided
 * {@link ByteBufferPacketCodec}.
 * 
 * <pre>
 * ByteBufferPacketCodec codec = ByteBufferPacketCodec.getInstance();
 * codec.registerPacketType(Person.class);
 * </pre>
 * 
 * Now, the packet is easily encoded and decoded:
 * 
 * <pre>
 * Person alice = new Person();
 * alice.name = "Alice";
 * alice.age = 25;
 * 
 * // Encode
 * ByteBuffer buf = ByteBuffer.allocate(1024);
 * codec.encodePacket(buf, alice);
 * 
 * // Decode
 * buf.flip();
 * Person person = codec.decodePacket(buf);
 * 
 * System.out.println(person);
 * </pre>
 * 
 * Voila! There is also a {@link StringPacketCodec} that encodes and decodes packets as
 * {@link String}s. It follows the same scheme. Register the packet, then encode and decode. The
 * only notable difference is that its encode method has a different signature:
 * 
 * <pre>
 * String encoded = codec.encodepacket(alice);
 * </pre>
 * 
 * Technically, both codecs have both variants, but depending on the encoded type, one variant may
 * be more appropriate than another. Since {@link ByteBuffer}s are mutable by design, it's more
 * suitable to encode packets into an existing {@link ByteBuffer} than it is to ask the library to
 * instantiate a new one.
 * 
 * Packets can also be nested. The packet codec already provides the methods needed to encode and
 * decode any packet. Thus, fields that are packets are simply encoded and decoded in place:
 * 
 * <pre>
 * public class Person extends Packet {
 * 	&#64;PacketField
 * 	&#64;NullTerminated
 * 	public String name;
 * 
 * 	&#64;PacketField
 * 	public byte age;
 * 
 * 	&#64;PacketField
 * 	public Address homeAddress;
 * }
 * 
 * public class Address extends Packet {
 * 	&#64;PacketField
 * 	&#64;NullTerminated
 * 	public String houseNumber;
 * 
 * 	&#64;PacketField
 * 	&#64;NullTerminated
 * 	public String street;
 * 
 * 	&#64;PacketField
 * 	public int zipCode;
 * }
 * </pre>
 * 
 * Packet fields may also be declared {@code final}, which is useful for validation or packet type
 * selection. Final fields are encoded exactly the same was an non-final fields. When decoded, the
 * field value is checked against the final value. If they match, decoding continues. If not, a
 * {@link PacketFieldValueMismatchException} is thrown. If the final field is variable in size, that
 * size is used as a clue during decode. Thus, for example, the {@link NullTerminated} annotation
 * would not be required, since it would try to decode a {@link String} of the same size as the
 * final value. It would not need a null terminator to determine the size, though it may still be
 * applied if desired.
 * 
 * The more interesting cases are handled by the various annotations. Many are included, and a
 * developer may provide additional ones. Generally, it is better to provide new annotations than it
 * is to extend a codec, unless the encoding and decoding of primitives needs to be modified
 * globally.
 * 
 * Annotations for delimiting fields:
 * <ul>
 * <li>{@link CountedByField}</li>
 * <li>{@link SizedByField}</li>
 * <li>{@link SizedByMethods}</li>
 * <li>{@link NullTerminated}</li>
 * <li>{@link RegexTerminated}</li>
 * <li>{@link SequenceTerminated}</li>
 * </ul>
 * 
 * Annotations for collections and arrays:
 * <ul>
 * <li>{@link RepeatedField}</li>
 * <li>{@link CountedByField}</li>
 * <li>{@link RegexSeparated}</li>
 * </ul>
 * 
 * Annotations for conditionals and type selection:
 * <ul>
 * <li>{@link OptionalField}</li>
 * <li>{@link TypedByField}</li>
 * <li>{@link TypedByLookahead}</li>
 * </ul>
 * 
 * Annotations for modifying primitive encoding:
 * <ul>
 * <li>{@link EncodeChars}</li>
 * <li>{@link ReverseByteOrder}</li>
 * <li>{@link SizeRestricted}</li>
 * <li>{@link WithRadix}</li>
 * <li>{@link WithSign}</li>
 * </ul>
 * 
 * These annotations generally provide sufficient control for dealing with most common binary and
 * ASCII encoding schemes used in networking. For complex text processing, however, please consider
 * a formal parser, e.g., ANTLR.
 */
public abstract class Packet implements Comparable<Packet> {
	private static final Map<Class<? extends Packet>, List<Field>> fieldsByType = new HashMap<>();

	private Packet parent;

	void setParent(Packet parent) {
		this.parent = parent;
	}

	/**
	 * If this packet appeared as a packet field, obtain the packet containing it
	 * 
	 * @return the containing packet
	 */
	public Packet getParent() {
		return parent;
	}

	/**
	 * Begin specifying a map of keys to field types in a single line
	 * 
	 * @param key the type of keys -- generally values found in a keying field
	 * @param val the type of value -- generally a packet type selected by the keying field
	 * @return a builder for populating and obtaining the map
	 */
	public static <K, V> ImmutableMap.Builder<K, Class<? extends V>> typeMap(Class<K> key,
			Class<V> val) {
		return new ImmutableMap.Builder<>();
	}

	/*
	 * An edge in the graph used to order the packet fields
	 */
	static class Precedes implements GEdge<Field> {
		public final Field first;
		public final Field second;

		public Precedes(Field first, Field second) {
			this.first = first;
			this.second = second;
		}

		@Override
		public int hashCode() {
			return first.hashCode() * 31 + second.hashCode();
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof Precedes)) {
				return false;
			}
			Precedes that = (Precedes) obj;
			return this.first.equals(that.first) && this.second.equals(that.second);
		}

		@Override
		public Field getStart() {
			return first;
		}

		@Override
		public Field getEnd() {
			return second;
		}
	}

	/**
	 * Obtain a packet field by type and name, verifying that it is annotated
	 * 
	 * @param cls the packet type
	 * @param name the name of the field
	 * @return the located field
	 * @throws NoSuchFieldException if the field does not exist at all
	 * @throws SecurityException if the field cannot be accessed
	 * @throws PacketFieldDeclarationException if the field is not annotated with
	 *             {@link PacketField}
	 */
	public static Field getPacketField(Class<? extends Packet> cls, String name)
			throws NoSuchFieldException, SecurityException {
		Field f = cls.getField(name);
		PacketField annot = f.getAnnotation(PacketField.class);
		if (annot == null) {
			throw new PacketFieldDeclarationException(cls, f,
				"Field is not a @" + PacketField.class.getSimpleName());
		}
		return f;
	}

	private static void checkPacketFieldModifiers(Class<? extends Packet> cls) {
		for (Field f : cls.getDeclaredFields()) {
			// This is just to check for correct access
			// Let the cls.getFields() method get all the interesting fields
			PacketField annot = f.getAnnotation(PacketField.class);
			if (annot == null) {
				continue;
			}
			int mod = f.getModifiers();
			if (!Modifier.isPublic(mod)) {
				throw new InvalidFieldModifiersException(cls, f, annot, "Field must be public");
			}
			if (Modifier.isStatic(mod) && !Modifier.isFinal(mod)) {
				throw new InvalidFieldModifiersException(cls, f, annot,
					"Static field must also be final");
			}
		}
	}

	/**
	 * Obtain an ordered list of packet fields for the given packet type
	 * 
	 * The ordering is accomplished via a topological sort of the fields after their relationships
	 * are extracted. By default, a field declared after another is implied to be encoded after it.
	 * Fields of a sub type have not implied ordering with respect to fields of its super type(s).
	 * Thus, some {@link PacketField#before()} and/or {@link PacketField#after()} attributes must be
	 * given, usually by the sub type. If the topological sort cannot be resolved uniquely --
	 * meaning exactly one ordering is possible given all the before/after constraints -- a
	 * {@link FieldOrderingException} is thrown.
	 * 
	 * @param cls the packet type
	 * @return the list of fields
	 * @throws FieldOrderingException if the fields cannot be ordered uniquely
	 */
	public static List<Field> getFields(Class<? extends Packet> cls) throws FieldOrderingException {
		List<Field> fields = fieldsByType.get(cls);
		if (fields != null) {
			return fields;
		}

		checkPacketFieldModifiers(cls);

		// Derive the field ordering relationships and add them to a graph
		GDirectedGraph<Field, Precedes> precedes = GraphFactory.createDirectedGraph();
		Map<String, Field> byName = new HashMap<>();
		Field lastF = null;
		String[] lastBefore = new String[0];
		for (Field f : cls.getFields()) {
			// TODO: I'm making assumptions about the order of fields returned.
			// According to the docs, I shouldn't....
			if (lastF != null && lastF.getDeclaringClass() != f.getDeclaringClass()) {
				lastF = null;
				lastBefore = new String[0];
			}
			PacketField annot = f.getAnnotation(PacketField.class);
			if (annot == null) {
				continue;
			}
			Field exists = byName.put(f.getName(), f);
			if (exists != null) {
				throw new PacketAnnotationException(cls, f, annot,
					"Duplicate field name: " + exists);
			}

			precedes.addVertex(f);

			String[] before = annot.before();
			String[] after = annot.after();
			try {
				if (before.length == 0) {
					before = lastBefore;
				}
				for (String b : before) {
					Field bf = getPacketField(cls, b);
					precedes.addEdge(new Precedes(f, bf));
				}

				if (after.length == 0 && lastF != null) {
					after = new String[] { lastF.getName() };
				}
				for (String a : after) {
					Field af = getPacketField(cls, a);
					precedes.addEdge(new Precedes(af, f));
				}
			}
			catch (NoSuchFieldException | SecurityException e) {
				throw new InvalidFieldNameException(cls, f, annot, e.getMessage(), e);
			}

			lastF = f;
			lastBefore = before;
		}
		// Attempt to uniquely sort the graph to obtain the field order
		try {
			fields = new TopologicalSorter<>(precedes, true).sort();
		}
		catch (SorterException e) {
			throw new FieldOrderingException(cls, "Could not order fields", e);
		}
		fieldsByType.put(cls, fields);
		return fields;
	}

	@Override
	public int hashCode() {
		int result = 0;
		try {
			for (Field f : Packet.getFields(this.getClass())) {
				result *= 31;
				Class<?> type = f.getType();
				if (type.isPrimitive()) {
					if (type == boolean.class) {
						result += Boolean.hashCode(f.getBoolean(this));
					}
					else if (type == byte.class) {
						result += Byte.hashCode(f.getByte(this));
					}
					else if (type == char.class) {
						result += Character.hashCode(f.getChar(this));
					}
					else if (type == short.class) {
						result += Short.hashCode(f.getShort(this));
					}
					else if (type == int.class) {
						result += Integer.hashCode(f.getInt(this));
					}
					else if (type == long.class) {
						result += Long.hashCode(f.getLong(this));
					}
					else if (type == float.class) {
						result += Float.hashCode(f.getFloat(this));
					}
					else if (type == double.class) {
						result += Double.hashCode(f.getDouble(this));
					}
					else {
						throw new AssertionError("INTERNAL: Forgot a primitive");
					}
				}
				else if (type.isArray()) {
					if (type == boolean[].class) {
						result += Arrays.hashCode((boolean[]) f.get(this));
					}
					else if (type == byte[].class) {
						result += Arrays.hashCode((byte[]) f.get(this));
					}
					else if (type == char[].class) {
						result += Arrays.hashCode((char[]) f.get(this));
					}
					else if (type == short[].class) {
						result += Arrays.hashCode((short[]) f.get(this));
					}
					else if (type == int[].class) {
						result += Arrays.hashCode((int[]) f.get(this));
					}
					else if (type == long[].class) {
						result += Arrays.hashCode((long[]) f.get(this));
					}
					else if (type == float[].class) {
						result += Arrays.hashCode((float[]) f.get(this));
					}
					else if (type == double[].class) {
						result += Arrays.hashCode((double[]) f.get(this));
					}
					else {
						result += Arrays.hashCode((Object[]) f.get(this));
					}
				}
				else {
					Object o = f.get(this);
					if (o == null) {
						continue;
					}
					result += o.hashCode();
				}
			}
		}
		catch (IllegalArgumentException | IllegalAccessException e) {
			throw new RuntimeException(e);
		}
		return result;
	}

	@Override
	public boolean equals(Object that) {
		Class<? extends Packet> pktType = this.getClass();
		if (pktType != that.getClass()) {
			return false;
		}
		try {
			for (Field f : Packet.getFields(pktType)) {
				Class<?> type = f.getType();
				if (type.isPrimitive()) {
					if (type == boolean.class) {
						if (f.getBoolean(this) != f.getBoolean(that)) {
							return false;
						}
					}
					else if (type == byte.class) {
						if (f.getByte(this) != f.getByte(that)) {
							return false;
						}
					}
					else if (type == char.class) {
						if (f.getChar(this) != f.getChar(that)) {
							return false;
						}
					}
					else if (type == short.class) {
						if (f.getShort(this) != f.getShort(that)) {
							return false;
						}
					}
					else if (type == int.class) {
						if (f.getInt(this) != f.getInt(that)) {
							return false;
						}
					}
					else if (type == long.class) {
						if (f.getLong(this) != f.getLong(that)) {
							return false;
						}
					}
					else if (type == float.class) {
						if (f.getFloat(this) != f.getFloat(that)) {
							return false;
						}
					}
					else if (type == double.class) {
						if (f.getDouble(this) != f.getDouble(that)) {
							return false;
						}
					}
					else {
						throw new AssertionError("INTERNAL: Forgot a primitive");
					}
				}
				else if (type.isArray()) {
					if (type == boolean[].class) {
						if (!Arrays.equals((boolean[]) f.get(this), (boolean[]) f.get(that))) {
							return false;
						}
					}
					else if (type == byte[].class) {
						if (!Arrays.equals((byte[]) f.get(this), (byte[]) f.get(that))) {
							return false;
						}
					}
					else if (type == char[].class) {
						if (!Arrays.equals((char[]) f.get(this), (char[]) f.get(that))) {
							return false;
						}
					}
					else if (type == short[].class) {
						if (!Arrays.equals((short[]) f.get(this), (short[]) f.get(that))) {
							return false;
						}
					}
					else if (type == int[].class) {
						if (!Arrays.equals((int[]) f.get(this), (int[]) f.get(that))) {
							return false;
						}
					}
					else if (type == long[].class) {
						if (!Arrays.equals((long[]) f.get(this), (long[]) f.get(that))) {
							return false;
						}
					}
					else if (type == float[].class) {
						if (!Arrays.equals((float[]) f.get(this), (float[]) f.get(that))) {
							return false;
						}
					}
					else if (type == double[].class) {
						if (!Arrays.equals((double[]) f.get(this), (double[]) f.get(that))) {
							return false;
						}
					}
					else {
						if (!Arrays.equals((Object[]) f.get(this), (Object[]) f.get(that))) {
							return false;
						}
					}
				}
				else {
					Object thisVal = f.get(this);
					Object thatVal = f.get(that);
					if (thisVal == null && thatVal == null) {
						continue;
					}
					else if (thisVal == null || thatVal == null) {
						return false;
					}
					else if (!f.get(this).equals(f.get(that))) {
						return false;
					}
				}
			}
		}
		catch (IllegalArgumentException | IllegalAccessException e) {
			throw new RuntimeException(e);
		}
		return true;
	}

	@Override
	public int compareTo(Packet that) {
		Class<? extends Packet> pktType = this.getClass();
		int c;
		c = pktType.getCanonicalName().compareTo(that.getClass().getCanonicalName());
		if (c != 0) {
			return c;
		}
		try {
			for (Field f : Packet.getFields(pktType)) {
				Class<?> type = f.getType();
				if (type.isPrimitive()) {
					if (type == boolean.class) {
						c = Boolean.compare(f.getBoolean(this), f.getBoolean(that));
					}
					else if (type == byte.class) {
						c = Byte.compare(f.getByte(this), f.getByte(that));
					}
					else if (type == char.class) {
						c = Character.compare(f.getChar(this), f.getChar(that));
					}
					else if (type == short.class) {
						c = Short.compare(f.getShort(this), f.getShort(that));
					}
					else if (type == int.class) {
						c = Integer.compare(f.getInt(this), f.getInt(that));
					}
					else if (type == long.class) {
						c = Long.compare(f.getLong(this), f.getLong(that));
					}
					else if (type == float.class) {
						c = Float.compare(f.getFloat(this), f.getFloat(that));
					}
					else if (type == double.class) {
						c = Double.compare(f.getDouble(this), f.getDouble(that));
					}
					else {
						throw new AssertionError("INTERNAL: Forgot a primitive");
					}
				}
				else {
					c = compareObjects(f.get(this), f.get(that));
				}
				if (c != 0) {
					return c;
				}
			}
		}
		catch (IllegalArgumentException | IllegalAccessException e) {
			throw new RuntimeException(e);
		}
		return 0;
	}

	@Override
	public String toString() {
		Class<? extends Packet> pktType = this.getClass();
		StringBuilder sb = new StringBuilder();
		sb.append(pktType.getSimpleName());
		sb.append('{');
		try {
			boolean first = true;
			for (Field f : Packet.getFields(pktType)) {
				if (Modifier.isFinal(f.getModifiers())) {
					continue;
				}
				if (first) {
					first = false;
				}
				else {
					sb.append(',');
				}
				sb.append(f.getName());
				sb.append('=');
				Object o = f.get(this);
				if (o == null) {
					continue;
				}
				Class<?> type = o.getClass();
				if (type.isArray()) {
					sb.append('[');
					if (type == boolean[].class) {
						sb.append(StringUtils.join((boolean[]) o, ','));
					}
					else if (type == byte[].class) {
						sb.append(StringUtils.join((byte[]) o, ','));
					}
					else if (type == char[].class) {
						sb.append(StringUtils.join((char[]) o, ','));
					}
					else if (type == short[].class) {
						sb.append(StringUtils.join((short[]) o, ','));
					}
					else if (type == int[].class) {
						sb.append(StringUtils.join((int[]) o, ','));
					}
					else if (type == long[].class) {
						sb.append(StringUtils.join((long[]) o, ','));
					}
					else if (type == float[].class) {
						sb.append(StringUtils.join((float[]) o, ','));
					}
					else if (type == double[].class) {
						sb.append(StringUtils.join((double[]) o, ','));
					}
					else {
						sb.append(StringUtils.join((Object[]) o, ','));
					}
					sb.append(']');
				}
				else {
					sb.append(f.get(this));
				}
			}
		}
		catch (IllegalArgumentException | IllegalAccessException e) {
			throw new RuntimeException(e);
		}
		sb.append('}');
		return sb.toString();
	}

	/**
	 * Produce a deep copy of the given object, unless that object need not be copied
	 * 
	 * @param obj the object to copy
	 * @return the copied objects
	 * @throws InstantiationException if a collection type could not be instantiated
	 * @throws IllegalAccessException if a collection type could not be instantiated
	 * @throws SecurityException
	 * @throws NoSuchMethodException
	 * @throws InvocationTargetException
	 * @throws IllegalArgumentException
	 */
	protected static <E> Object copyOrRefObject(Object obj)
			throws InstantiationException, IllegalAccessException, IllegalArgumentException,
			InvocationTargetException, NoSuchMethodException, SecurityException {
		if (obj == null) {
			return null;
		}
		Class<?> type = obj.getClass();
		if (type.isArray()) {
			if (type == boolean[].class) {
				boolean[] mine = (boolean[]) obj;
				return Arrays.copyOf(mine, mine.length);
			}
			else if (type == byte[].class) {
				byte[] mine = (byte[]) obj;
				return Arrays.copyOf(mine, mine.length);
			}
			else if (type == char[].class) {
				char[] mine = (char[]) obj;
				return Arrays.copyOf(mine, mine.length);
			}
			else if (type == short[].class) {
				short[] mine = (short[]) obj;
				return Arrays.copyOf(mine, mine.length);
			}
			else if (type == int[].class) {
				int[] mine = (int[]) obj;
				return Arrays.copyOf(mine, mine.length);
			}
			else if (type == long[].class) {
				long[] mine = (long[]) obj;
				return Arrays.copyOf(mine, mine.length);
			}
			else if (type == float[].class) {
				float[] mine = (float[]) obj;
				return Arrays.copyOf(mine, mine.length);
			}
			else if (type == double[].class) {
				double[] mine = (double[]) obj;
				return Arrays.copyOf(mine, mine.length);
			}
			else { // Object array
				Object[] mine = (Object[]) obj;
				Object result = Array.newInstance(type.getComponentType(), mine.length);
				for (int i = 0; i < mine.length; i++) {
					Array.set(result, i, copyOrRefObject(mine[i]));
				}
				return result;
			}
		}
		else if (Collection.class.isAssignableFrom(type)) {
			@SuppressWarnings("unchecked")
			Collection<E> dst = (Collection<E>) type.getConstructor().newInstance();
			@SuppressWarnings("unchecked")
			Collection<E> src = (Collection<E>) obj;
			for (Object s : src) {
				@SuppressWarnings("unchecked")
				E d = (E) copyOrRefObject(s);
				dst.add(d);
			}
			return dst;
		}
		else if (Packet.class.isAssignableFrom(type)) {
			Packet mySubPacket = (Packet) obj;
			return mySubPacket.copy();
		}
		else { // Just give the reference
			return obj;
		}
	}

	/**
	 * Obtain a deep copy of this packet
	 * 
	 * @return the copy
	 */
	public <P extends Packet> P copy() {
		try {
			@SuppressWarnings("unchecked")
			Class<P> pktType = (Class<P>) this.getClass();
			P that = pktType.getConstructor().newInstance();
			for (Field f : Packet.getFields(pktType)) {
				Class<?> type = f.getType();
				if (type.isPrimitive()) {
					if (type == boolean.class) {
						f.setBoolean(that, f.getBoolean(this));
					}
					else if (type == byte.class) {
						f.setByte(that, f.getByte(this));
					}
					else if (type == char.class) {
						f.setChar(that, f.getChar(this));
					}
					else if (type == short.class) {
						f.setShort(that, f.getShort(this));
					}
					else if (type == int.class) {
						f.setInt(that, f.getInt(this));
					}
					else if (type == long.class) {
						f.setLong(that, f.getLong(this));
					}
					else if (type == float.class) {
						f.setFloat(that, f.getFloat(this));
					}
					else if (type == double.class) {
						f.setDouble(that, f.getDouble(this));
					}
					else {
						throw new AssertionError("INTERNAL: Forgot a primitive");
					}
				}
				else {
					f.set(that, copyOrRefObject(f.get(this)));
				}
			}
			return that;
		}
		catch (InstantiationException | IllegalAccessException | IllegalArgumentException
				| InvocationTargetException | NoSuchMethodException | SecurityException e) {
			throw new RuntimeException(e);
		}
	}

	protected static int compareArrays(boolean[] a, boolean[] b) {
		if (a == null && b == null) {
			return 0;
		}
		else if (a == null) {
			return -1;
		}
		else if (b == null) {
			return 1;
		}
		int c = a.length - b.length;
		if (c != 0) {
			return c;
		}
		for (int i = 0; i < a.length; i++) {
			c = Boolean.compare(a[i], b[i]);
			if (c != 0) {
				return c;
			}
		}
		return 0;
	}

	protected static int compareArrays(byte[] a, byte[] b) {
		if (a == null && b == null) {
			return 0;
		}
		else if (a == null) {
			return -1;
		}
		else if (b == null) {
			return 1;
		}
		int c = a.length - b.length;
		if (c != 0) {
			return c;
		}
		for (int i = 0; i < a.length; i++) {
			c = Byte.compare(a[i], b[i]);
			if (c != 0) {
				return c;
			}
		}
		return 0;
	}

	protected static int compareArrays(char[] a, char[] b) {
		if (a == null && b == null) {
			return 0;
		}
		else if (a == null) {
			return -1;
		}
		else if (b == null) {
			return 1;
		}
		int c = a.length - b.length;
		if (c != 0) {
			return c;
		}
		for (int i = 0; i < a.length; i++) {
			c = Character.compare(a[i], b[i]);
			if (c != 0) {
				return c;
			}
		}
		return 0;
	}

	protected static int compareArrays(short[] a, short[] b) {
		if (a == null && b == null) {
			return 0;
		}
		else if (a == null) {
			return -1;
		}
		else if (b == null) {
			return 1;
		}
		int c = a.length - b.length;
		if (c != 0) {
			return c;
		}
		for (int i = 0; i < a.length; i++) {
			c = Short.compare(a[i], b[i]);
			if (c != 0) {
				return c;
			}
		}
		return 0;
	}

	protected static int compareArrays(int[] a, int[] b) {
		if (a == null && b == null) {
			return 0;
		}
		else if (a == null) {
			return -1;
		}
		else if (b == null) {
			return 1;
		}
		int c = a.length - b.length;
		if (c != 0) {
			return c;
		}
		for (int i = 0; i < a.length; i++) {
			c = Integer.compare(a[i], b[i]);
			if (c != 0) {
				return c;
			}
		}
		return 0;
	}

	protected static int compareArrays(long[] a, long[] b) {
		if (a == null && b == null) {
			return 0;
		}
		else if (a == null) {
			return -1;
		}
		else if (b == null) {
			return 1;
		}
		int c = a.length - b.length;
		if (c != 0) {
			return c;
		}
		for (int i = 0; i < a.length; i++) {
			c = Long.compare(a[i], b[i]);
			if (c != 0) {
				return c;
			}
		}
		return 0;
	}

	protected static int compareArrays(float[] a, float[] b) {
		if (a == null && b == null) {
			return 0;
		}
		else if (a == null) {
			return -1;
		}
		else if (b == null) {
			return 1;
		}
		int c = a.length - b.length;
		if (c != 0) {
			return c;
		}
		for (int i = 0; i < a.length; i++) {
			c = Float.compare(a[i], b[i]);
			if (c != 0) {
				return c;
			}
		}
		return 0;
	}

	protected static int compareArrays(double[] a, double[] b) {
		if (a == null && b == null) {
			return 0;
		}
		else if (a == null) {
			return -1;
		}
		else if (b == null) {
			return 1;
		}
		int c = a.length - b.length;
		if (c != 0) {
			return c;
		}
		for (int i = 0; i < a.length; i++) {
			c = Double.compare(a[i], b[i]);
			if (c != 0) {
				return c;
			}
		}
		return 0;
	}

	protected static int compareArrays(Object[] a, Object[] b) {
		if (a == null && b == null) {
			return 0;
		}
		else if (a == null) {
			return -1;
		}
		else if (b == null) {
			return 1;
		}
		int c = a.length - b.length;
		if (c != 0) {
			return c;
		}
		for (int i = 0; i < a.length; i++) {
			c = compareObjects(a[i], b[i]);
			if (c != 0) {
				return c;
			}
		}
		return 0;
	}

	protected static int compareCollections(Collection<?> a, Collection<?> b) {
		if (a == null && b == null) {
			return 0;
		}
		else if (a == null) {
			return -1;
		}
		else if (b == null) {
			return 1;
		}
		int c = a.size() - b.size();
		if (c != 0) {
			return c;
		}
		Iterator<?> ai = a.iterator();
		Iterator<?> bi = b.iterator();
		while (ai.hasNext()) {
			c = compareObjects(ai.next(), bi.next());
			if (c != 0) {
				return c;
			}
		}
		return 0;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	protected static int compareObjects(Object a, Object b) {
		if (a == null && b == null) {
			return 0;
		}
		else if (a == null) {
			return -1;
		}
		else if (b == null) {
			return 1;
		}
		int c = a.getClass().getCanonicalName().compareTo(b.getClass().getCanonicalName());
		if (c != 0) {
			return c;
		}
		Class<?> type = a.getClass();
		if (type.isArray()) {
			if (type == boolean[].class) {
				return compareArrays((boolean[]) a, (boolean[]) b);
			}
			else if (type == byte[].class) {
				return compareArrays((byte[]) a, (byte[]) b);
			}
			else if (type == char[].class) {
				return compareArrays((char[]) a, (char[]) b);
			}
			else if (type == short[].class) {
				return compareArrays((short[]) a, (short[]) b);
			}
			else if (type == int[].class) {
				return compareArrays((int[]) a, (int[]) b);
			}
			else if (type == long[].class) {
				return compareArrays((long[]) a, (long[]) b);
			}
			else if (type == float[].class) {
				return compareArrays((float[]) a, (float[]) b);
			}
			else if (type == double[].class) {
				return compareArrays((double[]) a, (double[]) b);
			}
			else {
				return compareArrays((Object[]) a, (Object[]) b);
			}
		}
		else if (Collection.class.isAssignableFrom(type)) {
			return compareCollections((Collection) a, (Collection) b);
		}
		Comparable ac = (Comparable<?>) a;
		Comparable bc = (Comparable<?>) b;
		return ac.compareTo(bc);
	}
}
