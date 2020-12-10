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

import java.io.EOFException;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.*;
import java.util.*;
import java.util.concurrent.locks.*;

import ghidra.comm.packet.annot.CountedByField;
import ghidra.comm.packet.annot.RepeatedField;
import ghidra.comm.packet.annot.impl.*;
import ghidra.comm.packet.binary.ByteBufferPacketCodec;
import ghidra.comm.packet.codecs.*;
import ghidra.comm.packet.err.*;
import ghidra.comm.packet.fields.*;
import ghidra.util.Msg;

/**
 * A partial implementation of {@link PacketCodec} that ought to be used as the base for all
 * implementations.
 * 
 * The general pattern for encoding packets is to construct a temporary encode buffer, encode the
 * fields of a given packet into that buffer, and then construct the final encoding from that
 * buffer. Conversely, the general pattern for decoding is to load the encoded data into a decode
 * buffer and then decode each field of the given packet from that buffer. In some cases, e.g.,
 * {@link ByteBufferPacketCodec}, all three forms may be fulfilled by the same class.
 *
 * Fields may be annotated to change its behavior and/or encoding. Some behaviors are implemented by
 * the annotation, others are implemented by the codec. During packet registration, a chain of
 * {@link FieldCodec}s is constructed for each {@link PacketField}-annotated field. It is best to
 * picture these chains from top to bottom, where the top {@link FieldCodec} is provided by the
 * packet codec -- via its {@link FieldCodecFactory} interface. The next codec is provided by the
 * first annotation -- other than {@link PacketField} -- applied to the field. The top codec is
 * closest to the encoded data. The bottom codec in the chain is provided by the last annotation
 * applied to the field. This codec is closest to the decoded data. To decode, data moves from top
 * to bottom. To encode, data moves from bottom to top.
 * 
 * To construct the chain, the {@link WrapperFactory} is obtained for each annotation applied to the
 * field via {@link #getFactoryForAnnotation(Class, Field, Annotation)}. This permits different
 * codecs to implement annotations differently. Some annotations are universally applicable, and
 * they provide their own implementations. Thus, the packet codec ought to check for such an
 * implementation. Implementations using {@link AbstractPacketCodec} need only delegate to the super
 * method. To facilitate interaction among fields, a factory in one chain may also inject another
 * factory into the bottom of a preceding field's chain. The factories then begin building the
 * {@link FieldCodec}s from bottom to top.
 * 
 * First, the type of the field is determined by reflection. Then the chain is asked for a
 * {@link FieldCodec} for that type, via
 * {@link FieldCodecFactory#buildChainForType(Class, Field, Class, PacketCodec, Deque)}. This method
 * is given the list of remaining wrapper factories. If it is empty, it obtains the field codec for
 * the type directly from the {@link FieldCodecFactory}, i.e., this {@link PacketCodec}. Otherwise,
 * it obtains a field codec from the next wrapper factory. That factory will in turn request the
 * field codec(s) for any type(s) it requires following the same method recursively. If at any
 * point, a factory cannot produce a codec for the type required by a lower codec, the packet
 * definition fails validation for this codec.
 * 
 * Take the following example:
 * 
 * <pre>
 * public class ListOfInt extends Packet {
 * 	&#64;PacketField
 * 	public int count;
 * 
 * 	&#64;PacketField
 * 	&#64;RepeatedField
 * 	&#64;CountedByField("count")
 * 	public List<Integer> list;
 * }
 * </pre>
 * 
 * First, the chains are built by processing the annotations. In this case, both annotations provide
 * their own implementations: {@link RepeatedField} is implemented by
 * {@link RepeatedFieldWrapperFactory}, and {@link CountedByField} is implemented by
 * {@link CountedByFieldWrapperFactory}. Thus, the chains initially look like this:
 * 
 * <ul>
 * <li>{@code count}: []</li>
 * <li>{@code list}: [{@link CountedByFieldWrapperFactory},
 * {@link RepeatedFieldWrapperFactory}]</li>
 * </ul>
 * 
 * Chain construction starts with the last field, and each chain is constructed by applying the
 * annotations from the bottom up. Thus, to start {@link FieldCodec} construction,
 * {@link CountedByFieldWrapperFactory} is asked for a field codec for
 * {@link List}{@code <}{@link Integer}{@code >}. It can provide one, because it knows how to count
 * elements of a list. It does not need to transform the list itself, so it will request the same
 * type from {@link RepeatedFieldWrapperFactory}. However, it needs to be able to modify the field
 * {@code count}, so it injects {@link CountedByFieldInjectionFactory} into {@code count}'s chain,
 * which will affect its field codecs. In the meantime, {@link RepeatedFieldWrapper} can provide a
 * field codec for {@link List}{@code <}{@link Integer}{@code >}, because it expects a collection or
 * an array. However, to encode each element, it needs a field codec for {@link Integer}. Because
 * there are no more wrapper factories in the chain, it asks the {@link FieldCodecFactory} for a
 * primitive {@link Integer} field codec, which it ought to provide.
 * 
 * Then, we construct the chain for the {@code count} field, which now consists of
 * [{@link CountedByFieldInjectionFactory}]. Thus, it is asked for an {@link Integer} field codec.
 * Because the injection expects a numeric field, it provides one. This codec does not change the
 * type, but will modify the value, thus it asks the {@link FieldCodecFactory} for a primitive
 * {@link Integer} field codec, and the packet registration is complete.
 * 
 * When encoding a {@code ListOfInt}, e.g., having entries [10, 9, 8], the codec starts with an
 * empty encode buffer at the {@code count} field. The data can be pictured moving through the
 * annotations from bottom to top, starting with the field value and remembering that injection
 * occurs at the bottom. Thus, we start with the current value of {@code count}, which might as well
 * be 0. The codec injected by {@link CountedByFieldInjectionFactory} is asked to encode that 0. It
 * then counts the number of elements in {@code list} and overwrites the value of {@code count} with
 * 3. It then asks the primitive {@link Integer} codec to encode that 3, so 3 is encoded and
 * appended to the buffer.
 * 
 * It then proceeds to the {@code list} field, whose value is [10, 9, 8]. The field codec given by
 * {@link CountedByFieldWrapperFactory} does not modify this value. It asks the next codec up to
 * encode it. The field codec given by {@link RepeatedFieldWrapperFactory} iterates over each
 * element in the list, asking the next codec up to encode it. The next codec up is the primitive
 * {@link Integer} field codec. Thus, 10, 9, and 8 are encoded into the buffer in order. The buffer
 * is then converted to the final output type and returned to the caller of
 * {@link #encodePacket(Packet)}. If primitives are encoded, e.g., as big-endian binary bytes, the
 * result would be {@code 00000003 0000000a 00000009 00000008}.
 * 
 * When decoding a {@code ListOfInt}, the codec starts by placing the data into a decode buffer and
 * begins decoding {@code count}. The data can be pictured moving through the annotations from top
 * to bottom, though the request to decode moves from bottom to top. The injected field codec on
 * {@code count} given by {@link CountedByFieldInjectionFactory} does not modify the request or the
 * data. Thus, a 3 is decoded and stored into {@code count}. Decoding then proceeds to {@code list}.
 * The field codec given by {@link CountedByFieldWrapperFactory} modifies the request, indicating
 * that 3 elements are expected. The field codec given by {@link RepeatedFieldWrapperFactory} then
 * forwards 3 requests, one at a time, to the next codec up. That codec, being a primitive
 * {@link Integer} field codec, then decodes and returns each value 10, 9, and 8 back down the
 * chain. The {@link RepeatedField} codec then packs those into a {@link List}, returning it to the
 * next field codec down. The {@link CountedByField} codec simply returns the result without
 * modification, which is then stored into {@code list}, completing the decode.
 *
 * @param <T> the type of encoded packets
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 */
public abstract class AbstractPacketCodec<T, ENCBUF, DECBUF> extends
		AbstractFieldCodecFactory<ENCBUF, DECBUF> implements PacketCodecInternal<T, ENCBUF, DECBUF>,
		PrimitiveFactory<ENCBUF, DECBUF>, PrimitiveCodec<ENCBUF, DECBUF> {

	private final Map<Field, Deque<FieldCodecFactory<ENCBUF, DECBUF>>> fieldChains =
		new LinkedHashMap<>();
	private final Map<Field, FieldCodec<ENCBUF, DECBUF, ?>> fieldCodecs = new HashMap<>();
	private final Set<Class<? extends Packet>> registry = new HashSet<>();

	private final ReadWriteLock lock = new ReentrantReadWriteLock();
	private final Lock readLock = lock.readLock();
	private final Lock writeLock = lock.writeLock();

	/**
	 * Finalize the encoding by converting an encode buffer into encoded data
	 * 
	 * For some codecs, this is a NOP.
	 * 
	 * @param buf the encode buffer to finalize
	 * @return the finalized data
	 */
	protected abstract T finishEncode(ENCBUF buf);

	/**
	 * Register a single field of a packet type
	 * 
	 * This constructs field codec by linking the applicable wrappers in a chain. For most fields,
	 * the chain is one element derived from its declared type. Annotated fields (other than
	 * {@link PacketField}) and those referred to by annotated fields may have more complex chains.
	 * 
	 * @see #getFactoryForAnnotation(Class, Field, Annotation)
	 * 
	 * @param pkt the packet type declaring the field
	 * @param field the field to register
	 * @param allFields a list of all other fields, in order, contained in the packet type
	 */
	protected <A extends Annotation> void registerField(Class<? extends Packet> pkt, Field field,
			List<Field> allFields) {
		LinkedList<FieldCodecFactory<ENCBUF, DECBUF>> codecChain = new LinkedList<>();
		codecChain.push(this);
		for (Annotation annot : field.getAnnotations()) {
			if (annot.annotationType() == PacketField.class) {
				continue;
			}
			FieldCodecFactory<ENCBUF, DECBUF> factory = getFactoryForAnnotation(pkt, field, annot);
			if (factory == null) {
				continue;
			}
			codecChain.push(factory);
		}
		fieldChains.put(field, codecChain);
	}

	/**
	 * Decodes a field and store or compare its value in the corresponding packet field
	 * 
	 * If the field is non-final, its value is set to the decoded field value. If the field is
	 * final, then its value is checked for equality with the final value. If the final value has
	 * countable elements, then it is measured and the count passed to the field decoder.
	 * 
	 * @see #decodeField(Packet, Field, Object, Integer, PacketFactory)
	 * 
	 * @param pkt the packet whose field to decode
	 * @param field the field to decode
	 * @param buf the buffer positioned at the encoded field
	 * @param factory a packet factory controlling version and dialect
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketDecodeException if the packet is not well formed
	 */
	protected <U> void decodeAndStoreField(Packet pkt, Field field, DECBUF buf,
			PacketFactory factory) throws IOException, PacketDecodeException {
		try {
			int mod = field.getModifiers();
			Object reqObj = null;
			Integer count = null;
			if (Modifier.isFinal(mod)) {
				reqObj = field.get(pkt);
				if (!field.getType().isPrimitive() && !field.getType().isEnum()) {
					count = measureCount(reqObj);
				}
			}
			U decObj = decodeField(pkt, field, buf, count, factory);
			if (Modifier.isFinal(mod)) {
				if (!reqObj.equals(decObj)) {
					throw new PacketFieldValueMismatchException(field, reqObj.toString(),
						decObj.toString());
				}
			}
			else {
				field.set(pkt, decObj);
			}
		}
		catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public <P extends Packet> P decodePacket(Packet parent, Field field, DECBUF buf,
			Class<P> pktType, PacketFactory factory) throws IOException, PacketDecodeException {
		readLock.lock();
		try {
			//Msg.debug(this, "PACKET: Descending into: " + pktType);
			P val = factory.newPacket(pktType);
			if (!registry.contains(val.getClass())) {
				throw new IllegalArgumentException("decoding " + field + ": constructed type " +
					val.getClass() + " is not registered with this codec.");
			}
			Collection<Field> fields = Packet.getFields(val.getClass());
			val.setParent(parent);
			for (Field f : fields) {
				decodeAndStoreField(val, f, buf, factory);
			}
			//Msg.debug(this, "PACKET: Ascending from " + pktType);
			return val;
		}
		catch (InstantiationException | IllegalAccessException | IllegalArgumentException
				| InvocationTargetException | NoSuchMethodException | SecurityException e) {
			throw new RuntimeException("Failed to instantiate " + pktType, e);
		}
		finally {
			readLock.unlock();
		}
	}

	@Override
	public void encodePacket(ENCBUF buf, Field field, Packet val)
			throws IOException, PacketEncodeException {
		readLock.lock();
		try {
			if (val == null) {
				throw new NullPointerException("field " + field + " cannot be encoded with null");
			}
			Class<? extends Packet> pktType = val.getClass();
			if (!registry.contains(pktType)) {
				if (field == null) {
					throw new IllegalArgumentException(
						"packet type " + val.getClass() + " is not registered with this codec.");
				}
				throw new IllegalArgumentException(
					"field " + field + " has value of an unregistered type: " + val);
			}
			Collection<Field> fields = Packet.getFields(pktType);
			for (Field f : fields) {
				encodeField(buf, val, f, f.get(val));
			}
		}
		catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
		finally {
			readLock.unlock();
		}
	}

	@Override
	public void registerPacketType(Class<? extends Packet> pkt) {
		writeLock.lock();
		try {
			if (registry.contains(pkt)) {
				return; // Avoid infinite recursion
			}

			int mod = pkt.getModifiers();
			if (pkt.getDeclaringClass() != null && !Modifier.isStatic(mod)) {
				throw new IllegalArgumentException(
					"Cannot register non-static inner class " + pkt + " as packet");
			}
			if (Modifier.isAbstract(mod)) {
				// Packet factories permit fields to have abstract types
				// The user will need to register the concrete types, though
				registry.add(pkt);
				return;
			}
			// Failure will cause NoSuchMethodException or SecurityException
			@SuppressWarnings("unused")
			Constructor<?> cons = pkt.getConstructor();

			registry.add(pkt);
			List<Field> fields = Packet.getFields(pkt);
			Deque<Field> revFields = new LinkedList<>();
			for (Field f : fields) {
				registerField(pkt, f, fields);
				revFields.push(f);
			}
			for (Field f : revFields) {
				Deque<FieldCodecFactory<ENCBUF, DECBUF>> codecChain = fieldChains.get(f);
				FieldCodec<ENCBUF, DECBUF, ?> fieldCodec =
					FieldCodecFactory.buildChainForType(pkt, f, f.getType(), this, codecChain);
				fieldCodecs.put(f, fieldCodec);
			}
		}
		catch (NoSuchMethodException | SecurityException e) {
			throw new PacketDeclarationException(pkt,
				"Packet must have accessible default constructor", e);
		}
		finally {
			writeLock.unlock();
		}
	}

	@Override
	public <U> U decodeField(Packet pkt, Field field, DECBUF buf, Integer count,
			PacketFactory factory) throws IOException, PacketDecodeException {
		//Msg.debug(this, "PACKET: Decoding " + pkt.getClass().getSimpleName() + "." + field.getName());
		@SuppressWarnings("unchecked")
		FieldCodec<ENCBUF, DECBUF, U> fieldCodec =
			(FieldCodec<ENCBUF, DECBUF, U>) fieldCodecs.get(field);
		U u = fieldCodec.decodeField(pkt, buf, count, factory);
		//Msg.debug(this, "PACKET: " + field.getName() + " = " + u);
		return u;
	}

	@Override
	public <P extends Packet> P decodePacket(Class<P> pktType, T data, PacketFactory factory)
			throws PacketDecodeException {
		readLock.lock();
		try {
			if (!registry.contains(pktType)) {
				throw new IllegalArgumentException(
					"Cannot decode unregistered packet type: " + pktType);
			}
			DECBUF buf = newDecodeBuffer(data);
			P result = decodePacket(null, null, buf, pktType, factory);
			if (measureDecodeRemaining(buf) != 0) {
				throw new InvalidPacketException("Packet did not consume given buffer: " + buf);
			}
			return result;
		}
		catch (RuntimeException e) {
			throw e;
		}
		catch (EOFException e) {
			throw new InvalidPacketException("Reached end of buffer before decoding finished", e);
		}
		catch (PacketDecodeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new AssertionError("Internal error", e);
		}
		finally {
			readLock.unlock();
		}
	}

	protected String toTruncatedString(Object obj, int maxLen) {
		if (maxLen < 3) {
			throw new IllegalArgumentException("Too short, no?");
		}
		String str = obj.toString();
		if (str.length() > maxLen) {
			return str.substring(0, maxLen - 3) + "...";
		}
		return str;
	}

	@Override
	public <U> void encodeField(ENCBUF buf, Packet pkt, Field field, U val)
			throws IOException, PacketEncodeException {
		@SuppressWarnings("unchecked")
		FieldCodec<ENCBUF, DECBUF, U> fieldCodec =
			(FieldCodec<ENCBUF, DECBUF, U>) fieldCodecs.get(field);
		try {
			fieldCodec.encodeField(buf, pkt, val);
		}
		catch (Throwable t) {
			Msg.error(this, t + "; while encoding field " + field + " of packet " + pkt.getClass() +
				" of value " + toTruncatedString(val, 30));
			throw t;
		}
	}

	@Override
	public void encodePacketInto(ENCBUF buf, Packet pkt) throws PacketEncodeException {
		try {
			encodePacket(buf, null, pkt);
		}
		catch (IOException e) {
			throw new AssertionError("Internal error", e);
		}
	}

	@Override
	public T encodePacket(Packet pkt) throws PacketEncodeException {
		try {
			ENCBUF buf = newEncodeBuffer();
			encodePacketInto(buf, pkt);
			return finishEncode(buf);
		}
		catch (RuntimeException e) {
			throw e;
		}
		catch (PacketEncodeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new AssertionError("Internal error", e);
		}
	}

	@Override
	public WrapperFactory<ENCBUF, DECBUF> getFactoryForAnnotation(Class<? extends Packet> pkt,
			Field field, Annotation annot) {
		ImplementedBy wrapAnnot = annot.annotationType().getAnnotation(ImplementedBy.class);
		if (wrapAnnot == null) {
			// Some annotations have no meaning unless used with certain codecs.
			// Silently ignore this
			Msg.debug(this, "Ignoring " + annot + " on " + field + " with " + this);
			return null;
		}

		@SuppressWarnings("unchecked")
		Class<? extends WrapperFactory<?, ?>> factoryType =
			(Class<? extends WrapperFactory<?, ?>>) wrapAnnot.value();
		WrapperFactory<?, ?> factory;
		try {
			factory = factoryType.getConstructor().newInstance();
		}
		catch (InstantiationException | IllegalAccessException | IllegalArgumentException
				| InvocationTargetException | NoSuchMethodException | SecurityException e) {
			throw new PacketAnnotationException(pkt, field, annot, "Could not build wrapper", e);
		}
		// The following two situations are probably mistakes, in either the annotation or codec
		// implementations, or possibly the packet specification.
		if (!factory.getEncodingBufferClass().isAssignableFrom(this.getEncodingBufferClass())) {
			throw new PacketAnnotationException(pkt, field, annot,
				"Encoder offered by annotation is not compatible with this codec");
		}
		if (!factory.getDecodingBufferClass().isAssignableFrom(this.getDecodingBufferClass())) {
			throw new PacketAnnotationException(pkt, field, annot,
				"Decoder offered by annotation is not compatible with this codec");
		}

		@SuppressWarnings("unchecked")
		WrapperFactory<ENCBUF, DECBUF> result = (WrapperFactory<ENCBUF, DECBUF>) factory;
		return result;
	}

	@Override
	public <U> FieldCodec<ENCBUF, DECBUF, U> getFieldCodecForType(Class<? extends Packet> pktType,
			Field field, Class<? extends U> fldType) {
		if (Packet.class.isAssignableFrom(fldType)) {
			@SuppressWarnings("unchecked")
			Class<? extends Packet> subPktType = (Class<? extends Packet>) fldType;

			registerPacketType(subPktType);

			@SuppressWarnings("unchecked")
			FieldCodec<ENCBUF, DECBUF, U> result =
				(FieldCodec<ENCBUF, DECBUF, U>) new PacketFieldCodec<>(this, pktType, field,
					subPktType);
			return result;
		}
		else if (fldType == boolean.class || Boolean.class.isAssignableFrom(fldType)) {
			@SuppressWarnings("unchecked")
			FieldCodec<ENCBUF, DECBUF, U> result =
				(FieldCodec<ENCBUF, DECBUF, U>) new BooleanFieldCodec<>(this, pktType, field);
			return result;
		}
		else if (fldType == byte.class || Byte.class.isAssignableFrom(fldType)) {
			@SuppressWarnings("unchecked")
			FieldCodec<ENCBUF, DECBUF, U> result =
				(FieldCodec<ENCBUF, DECBUF, U>) new ByteFieldCodec<>(this, pktType, field);
			return result;
		}
		else if (fldType == char.class || Character.class.isAssignableFrom(fldType)) {
			@SuppressWarnings("unchecked")
			FieldCodec<ENCBUF, DECBUF, U> result =
				(FieldCodec<ENCBUF, DECBUF, U>) new CharacterFieldCodec<>(this, pktType, field);
			return result;
		}
		else if (fldType == short.class || Short.class.isAssignableFrom(fldType)) {
			@SuppressWarnings("unchecked")
			FieldCodec<ENCBUF, DECBUF, U> result =
				(FieldCodec<ENCBUF, DECBUF, U>) new ShortFieldCodec<>(this, pktType, field);
			return result;
		}
		else if (fldType == int.class || Integer.class.isAssignableFrom(fldType)) {
			@SuppressWarnings("unchecked")
			FieldCodec<ENCBUF, DECBUF, U> result =
				(FieldCodec<ENCBUF, DECBUF, U>) new IntegerFieldCodec<>(this, pktType, field);
			return result;
		}
		else if (fldType == long.class || Long.class.isAssignableFrom(fldType)) {
			@SuppressWarnings("unchecked")
			FieldCodec<ENCBUF, DECBUF, U> result =
				(FieldCodec<ENCBUF, DECBUF, U>) new LongFieldCodec<>(this, pktType, field);
			return result;
		}
		else if (fldType == float.class || Float.class.isAssignableFrom(fldType)) {
			@SuppressWarnings("unchecked")
			FieldCodec<ENCBUF, DECBUF, U> result =
				(FieldCodec<ENCBUF, DECBUF, U>) new FloatFieldCodec<>(this, pktType, field);
			return result;
		}
		else if (fldType == double.class || Double.class.isAssignableFrom(fldType)) {
			@SuppressWarnings("unchecked")
			FieldCodec<ENCBUF, DECBUF, U> result =
				(FieldCodec<ENCBUF, DECBUF, U>) new DoubleFieldCodec<>(this, pktType, field);
			return result;
		}
		else if (CharSequence.class.isAssignableFrom(fldType)) {
			@SuppressWarnings("unchecked")
			FieldCodec<ENCBUF, DECBUF, U> result =
				(FieldCodec<ENCBUF, DECBUF, U>) new CharSequenceFieldCodec<>(this, pktType, field);
			return result;
		}
		return null;
	}

	@Override
	public void injectChain(Class<? extends Packet> pkt, Field targetField,
			InjectionFactory<ENCBUF, DECBUF> factory, Field annotatedField, Annotation annot) {
		Deque<FieldCodecFactory<ENCBUF, DECBUF>> chain = fieldChains.get(targetField);
		if (chain == null) {
			throw new InvalidFieldNameException(pkt, targetField, annot,
				"Modified field must be a @" + PacketField.class.getSimpleName());
		}
		List<Field> all = Packet.getFields(pkt);
		int targetIdx = all.indexOf(targetField);
		assert targetIdx >= 0;
		int annotatedIdx = all.indexOf(annotatedField);
		assert annotatedIdx >= 0;
		if (annotatedIdx <= targetIdx) {
			throw new AnnotatedFieldOrderingException(pkt, annotatedField, annot,
				"Referenced field must precede the annotated field");
		}
		chain.push(factory);
	}

	@Override
	public int measureCount(Object obj) {
		if (obj instanceof String) {
			return ((String) obj).length();
		}
		else if (obj instanceof Collection) {
			return ((Collection<?>) obj).size();
		}
		else if (obj.getClass().isArray()) {
			return Array.getLength(obj);
		}
		throw new IllegalArgumentException("Do not know how to measure length of " + obj);
	}
}
