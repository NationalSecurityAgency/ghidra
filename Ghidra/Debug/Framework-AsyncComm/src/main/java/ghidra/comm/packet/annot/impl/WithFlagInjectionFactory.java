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
package ghidra.comm.packet.annot.impl;

import java.lang.reflect.Field;
import java.util.Deque;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.annot.WithFlag;
import ghidra.comm.packet.codecs.PacketCodecInternal;
import ghidra.comm.packet.fields.*;

/**
 * The factory injecting {@link WithFlagInjectedFieldCodec} on behalf of {@link WithFlag}
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 */
public class WithFlagInjectionFactory<ENCBUF, DECBUF> extends AbstractWrapperFactory<ENCBUF, DECBUF>
		implements InjectionFactory<ENCBUF, DECBUF> {

	private final Field controlledField;
	@SuppressWarnings("rawtypes")
	private final Enum flag;
	private final WithFlag.Mode mode;

	public WithFlagInjectionFactory(Field controlledField, @SuppressWarnings("rawtypes") Enum flag,
			WithFlag.Mode mode) {
		this.controlledField = controlledField;
		this.flag = flag;
		this.mode = mode;
	}

	@Override
	public <T> FieldCodec<ENCBUF, DECBUF, T> getWrappedFieldCodecForType(
			Class<? extends Packet> pktType, Field field, Class<? extends T> fldType,
			PacketCodecInternal<?, ENCBUF, DECBUF> codec,
			Deque<FieldCodecFactory<ENCBUF, DECBUF>> chain) {
		FieldCodec<ENCBUF, DECBUF, T> chainNext =
			FieldCodecFactory.buildChainForType(pktType, field, fldType, codec, chain);
		return new WithFlagInjectedFieldCodec<>(pktType, field, controlledField, flag, mode,
			chainNext);
	}
}
