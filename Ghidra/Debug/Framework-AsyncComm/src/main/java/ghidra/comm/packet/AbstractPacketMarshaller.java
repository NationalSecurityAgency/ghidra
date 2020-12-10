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

import static ghidra.comm.packet.codecs.PacketCodecInternal.getTypeParameterRaw;

/**
 * A partial implementation of {@link PacketMarshaller} that handles the codec and type registration
 * 
 * It also includes a facility for switching from one packet factory to another and registering its
 * packet types.
 *
 * @param <W> the type of packets to write, possibly abstract
 * @param <R> the type of packets to read, possiblt abstract
 * @param <E> the type of the buffer for framing and encoded packets, usually {@link ByteBuffer}
 */
public abstract class AbstractPacketMarshaller<W extends Packet, R extends Packet, E>
		implements PacketMarshaller<W, R, E> {
	/** The underlying codec */
	protected final PacketCodec<E> codec;
	/** The type to use for reading packets when not overridden */
	protected final Class<? extends R> defaultType;
	/** The current packet factory, initialized to the default packet factory */
	protected PacketFactory factory = DefaultPacketFactory.getInstance();

	/**
	 * Construct a new marshaller
	 * 
	 * @param codec the underlying codec
	 * @param defaultType the type to read when a more-specific type is not given
	 */
	@SuppressWarnings("unchecked")
	public AbstractPacketMarshaller(PacketCodec<E> codec, Class<? extends R> defaultType) {
		this.codec = codec;
		this.defaultType = defaultType;

		Class<?> cls;
		cls = getTypeParameterRaw(this.getClass(), AbstractPacketMarshaller.class, "S");
		if (cls != null) {
			codec.registerPacketType((Class<? extends Packet>) cls);
		}
		cls = getTypeParameterRaw(this.getClass(), AbstractPacketMarshaller.class, "R");
		if (cls != null) {
			codec.registerPacketType((Class<? extends Packet>) cls);
		}
	}

	/**
	 * Register a packet type with the underlying codec
	 * 
	 * @param pktType the packet type to register
	 */
	public void registerPacketType(Class<? extends Packet> pktType) {
		codec.registerPacketType(pktType);
	}

	/**
	 * Set the packet factory to use for decoding packets
	 * 
	 * This will automatically register the factory's types with the underlying codec.
	 * 
	 * @param factory the factory
	 */
	public void setPacketFactory(PacketFactory factory) {
		this.factory = factory;
		this.factory.registerTypes(codec);
	}

	@Override
	public Class<? extends R> getDefaultType() {
		return defaultType;
	}
}
