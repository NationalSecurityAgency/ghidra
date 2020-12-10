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
package ghidra.comm.packet.codecs;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.*;
import java.util.Map.Entry;

import org.apache.commons.lang3.reflect.TypeUtils;

import ghidra.comm.packet.*;
import ghidra.comm.packet.annot.SizedByField;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.packet.fields.*;

/**
 * The internal interface for {@link PacketCodec}
 * 
 * This interface should only be used by codec and annotation implementations. Implementors ought to
 * extend {@link AbstractPacketCodec}.
 *
 * A codec must internally provide factories for encoding and decoding all of the types it natively
 * supports. Every codec ought to support Java's primitives, {@link String}s, and nested
 * {@link Packet}s.
 * 
 * It must also provide general mechanisms for interacting with its temporary encode and decode
 * buffers. These permit measured packet fields, e.g., those annotated with {@link SizedByField}, to
 * operate correctly.
 *
 * @param <T> the type of encoded packets
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 */
public interface PacketCodecInternal<T, ENCBUF, DECBUF>
		extends PacketCodec<T>, FieldCodecFactory<ENCBUF, DECBUF> {
	/**
	 * A utility for obtaining the class given for a type parameter by a subclass
	 * 
	 * @param type the subclass type
	 * @param sup the superclass type having the type parameter of interest
	 * @param name the name of the type parameter of interest
	 * @return the class given for the parameter, or null if it another variable or the name is not
	 *         found
	 */
	public static Class<?> getTypeParameterRaw(Type type, Class<?> sup, String name) {
		Type generic = getTypeParameterValue(type, sup, name);
		if (generic == null) {
			return null;
		}
		return TypeUtils.getRawType(generic, type);
	}

	/**
	 * A utility for obtaining the type given for a type parameter by a subclass
	 * 
	 * @param type the subclass type
	 * @param sup the superclass type having the type parameter of interest
	 * @param name the name of the type parameter of interest
	 * @return the type given for the parameter, or null if the name is not found
	 */
	public static Type getTypeParameterValue(Type type, Class<?> sup, String name) {
		for (Entry<TypeVariable<?>, Type> ent : TypeUtils.getTypeArguments(type, sup).entrySet()) {
			if (ent.getKey().getName().equals(name)) {
				return ent.getValue();
			}
		}
		return null;
	}

	/**
	 * Decode a packet field from a given buffer
	 * 
	 * This method <em>need not</em> actually set the field value. Just return it, and the caller
	 * will handle setting the field or comparing it to a final field value.
	 * 
	 * @param pkt the packet whose field to decode
	 * @param field the field to decode
	 * @param buf the buffer positioned at the encoded field
	 * @param count for repeated fields, the number of repetitions expected
	 * @param factory a factory for instantiating abstract types
	 * @return the field value
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketDecodeException if the packet is not well formed
	 */
	public <U> U decodeField(Packet pkt, Field field, DECBUF buf, Integer count,
			PacketFactory factory) throws IOException, PacketDecodeException;

	/**
	 * Encode a packet field into a buffer
	 * 
	 * @param buf the destination buffer to append encoded data
	 * @param pkt the packet whose field to encode
	 * @param field the field to encode
	 * @param val the value of the field to encode
	 * @throws IOException if there is an issue accessing a device or buffer
	 * @throws PacketEncodeException if the packet is not well formed
	 */
	public <U> void encodeField(ENCBUF buf, Packet pkt, Field field, U val)
			throws IOException, PacketEncodeException;

	/**
	 * Encode a packet into a buffer
	 * 
	 * During encoding, some field values may be modified, e.g., a field that measures the size of
	 * another field will be set to the appropriate value.
	 * 
	 * @param buf the destination buffer to append encoded data
	 * @param pkt the packet to encode
	 * @throws PacketEncodeException if the packet is not well formed
	 */
	public void encodePacketInto(ENCBUF buf, Packet pkt) throws PacketEncodeException;

	/**
	 * Obtain the field codec wrapper factory for a given field and annotation
	 * 
	 * @param pkt the packet type being registered
	 * @param field the packet field being registered
	 * @param annot the annotation currently being processed
	 * @return a factory to construct a link in the field codec chain
	 */
	public WrapperFactory<ENCBUF, DECBUF> getFactoryForAnnotation(Class<? extends Packet> pkt,
			Field field, Annotation annot);

	/**
	 * Inject a wrapper into a field's codec chain
	 * 
	 * This action essentially associates two fields. It is most often used when the value of one
	 * field controls the decoding, usually by determining the size, count, or type, of another
	 * field. In general, the annotation associating two fields is applied to the controlled field.
	 * Some attribute of that annotation identifies the controlling field, into which a wrapper must
	 * be injected.
	 * 
	 * @param pkt the packet type being registered
	 * @param controllingField the field into whose chain to inject the wrapper
	 * @param injected the factory providing the wrapper to inject
	 * @param controlledField the field whose annotation is injecting the wrapper
	 * @param annot the annotation injecting the wrapper
	 */
	void injectChain(Class<? extends Packet> pkt, Field controllingField,
			InjectionFactory<ENCBUF, DECBUF> injected, Field controlledField, Annotation annot);

	/**
	 * Construct a new decode buffer for the given encoded data
	 * 
	 * @param data the encoded data
	 * @return the buffer ready to decode the data
	 * @throws IOException if there is an issue accessing a device or buffer
	 */
	public DECBUF newDecodeBuffer(T data) throws IOException;

	/**
	 * Construct a new blank encode buffer
	 * 
	 * @return the buffer ready to encode data
	 * @throws IOException if there is an issue accessing a device or buffer
	 */
	public ENCBUF newEncodeBuffer() throws IOException;

	/**
	 * Apply a mark to the decode buffer which prevents consumption of data beyond it
	 * 
	 * This is essentially the converse of {@link #measureEncodeSize(Object)}. Both are used in
	 * circumstances where one field measures the encoded length of another. This one is used during
	 * decode to limit the given field to the measured amount of data.
	 * 
	 * @see #getDecodePosition(Object) regarding "position"
	 * 
	 * @param buf the buffer whose consumption to restrict
	 * @param pos the position beyond which data cannot be consumed
	 * @return the previous mark
	 */
	public int limitDecodeBuffer(DECBUF buf, int pos);

	/**
	 * Measure the count of elements in an object
	 * 
	 * Counts of collections, arrays, and strings are well understood to mean the size or length.
	 * The provided codecs implement this count. If a codec wishes to encode and decode other kinds
	 * of "countable" objects, it should override this method.
	 * 
	 * @param obj the object being measured
	 * @return the count of elements in the object
	 */
	public int measureCount(Object obj);

	/**
	 * Measure the length of an encoded buffer
	 * 
	 * This is essentially the converse of {@link #limitDecodeBuffer(Object, int)}. Both are used in
	 * circumstances where one field measures the encoded length of another. This one is used during
	 * encoding to set the value of the controlling field.
	 * 
	 * @see #setEncodePosition(Object, int)} regarding "position"
	 * 
	 * @param buf the buffer containing the encoded data
	 * @return the size or length of the data
	 */
	public int measureEncodeSize(ENCBUF buf);

	/**
	 * Measure the length of data remaining in a decode buffer
	 * 
	 * @param buf the buffer containing data to decode
	 * @return the size or length of the data remaining
	 */
	public int measureDecodeRemaining(DECBUF buf);

	/**
	 * Copy the contents of one buffer into another immediately following its current contents
	 * 
	 * @param into the destination buffer
	 * @param from the source buffer
	 * @throws IOException if there is an issue accessing a device or buffer
	 */
	public void appendEncoded(ENCBUF into, ENCBUF from) throws IOException;

	/**
	 * Obtain the position in a decode buffer
	 * 
	 * @param buf the buffer whose position is to be obtained
	 * @return the position
	 */
	public int getDecodePosition(DECBUF buf);

	/**
	 * (Re)set the position in a decode buffer
	 * 
	 * "Position" is not strictly defined, though it is usually the position of, e.g., the cursor,
	 * as an offset from the start of the buffer. The codec can use whatever definition is most
	 * suitable for the decode buffer, so long as that position can be represented by an integer.
	 * The same definition must be used by {@link #getDecodePosition(Object)} and
	 * {@link #limitDecodeBuffer(Object, int)}. Furthermore, {@link #measureDecodeRemaining(Object)}
	 * should return a delta position.
	 * 
	 * @param buf the buffer whose position to set
	 * @param pos the position
	 */
	public void setDecodePosition(DECBUF buf, int pos);

	/**
	 * (Re)set the position in an encode buffer
	 * 
	 * "Position" is not strictly defined, though it is usually the position of, e.g., the cursor,
	 * as an offset from the start of the buffer. The codec can use whatever definition is most
	 * suitable for the encode buffer, so long as that position can be represented by an integer.
	 * The same definition must be used by {@link #measureEncodeSize(Object)}, though it should
	 * return a delta position.
	 * 
	 * @param buf the buffer whose position to set
	 * @param pos the position
	 */
	public void setEncodePosition(ENCBUF buf, int pos);
}
