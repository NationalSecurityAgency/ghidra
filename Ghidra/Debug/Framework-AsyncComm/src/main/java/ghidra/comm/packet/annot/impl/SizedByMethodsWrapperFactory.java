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

import static ghidra.comm.packet.fields.AbstractFieldCodec.isIntegralType;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Deque;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.annot.SizedByMethods;
import ghidra.comm.packet.codecs.PacketCodecInternal;
import ghidra.comm.packet.err.*;
import ghidra.comm.packet.fields.*;

/**
 * The factory implementing {@link SizedByMethods}
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 */
public class SizedByMethodsWrapperFactory<ENCBUF, DECBUF>
		extends AbstractWrapperFactory<ENCBUF, DECBUF> {
	@Override
	public <T> FieldCodec<ENCBUF, DECBUF, T> getWrappedFieldCodecForType(
			Class<? extends Packet> pktType, Field field, Class<? extends T> fldType,
			PacketCodecInternal<?, ENCBUF, DECBUF> codec,
			Deque<FieldCodecFactory<ENCBUF, DECBUF>> chain) {
		SizedByMethods annot = field.getAnnotation(SizedByMethods.class);
		/*
		 * if (chain.peek() instanceof WrapperFactory) { throw new
		 * PacketAnnotationException(pktType, field, annot,
		 * "must be applied directly above the field"); }
		 */

		final Method getter;
		Method setter = null;
		final Field modified;
		try {
			getter = pktType.getMethod(annot.getter());
			if (!isIntegralType(getter.getReturnType())) {
				throw new InvalidMethodNameException(pktType, field, annot,
					"getter for must return an integral type");
			}
			setter = pktType.getMethod(annot.setter(), getter.getReturnType());
			modified = pktType.getField(annot.modifies());
		}
		catch (NoSuchMethodException e) {
			throw new InvalidMethodNameException(pktType, field, annot, e.getMessage(), e);
		}
		catch (NoSuchFieldException e) {
			throw new InvalidFieldNameException(pktType, field, annot, e.getMessage(), e);
		}
		catch (SecurityException e) {
			throw new PacketAnnotationException(pktType, field, annot, e.getMessage(), e);
		}

		SizedByMethodsInjectionFactory<ENCBUF, DECBUF> injected =
			new SizedByMethodsInjectionFactory<>(field, getter, setter);
		codec.injectChain(pktType, modified, injected, field, annot);

		FieldCodec<ENCBUF, DECBUF, T> chainNext =
			FieldCodecFactory.buildChainForType(pktType, field, fldType, codec, chain);
		return new SizedByMethodsFieldCodec<>(pktType, field, getter, codec, chainNext);
	}
}
