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
package ghidra.trace.model.listing;

import java.nio.ByteBuffer;

import com.google.common.collect.Range;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.util.TypeMismatchException;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.symbol.TraceReference;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.util.Saveable;

/**
 * A code unit in a {@link Trace}
 */
public interface TraceCodeUnit extends CodeUnit {
	/**
	 * Get the trace in which this code unit exists
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	@Override
	TraceProgramView getProgram();

	TraceAddressSpace getTraceSpace();

	/**
	 * Get the thread associated with this code unit
	 * 
	 * <p>
	 * A thread is associated with a code unit if it exists in a register space
	 * 
	 * @return the thread
	 */
	TraceThread getThread();

	/**
	 * Get the language of this code unit
	 * 
	 * <p>
	 * Currently, for data units, this is always the base or "host" language of the trace. For
	 * instructions, this may be a guest language.
	 * 
	 * @return the language
	 */
	Language getLanguage();

	/**
	 * Get the bounds of this unit in space and time
	 * 
	 * @return the bounds
	 */
	TraceAddressSnapRange getBounds();

	/**
	 * Get the address range covered by this unit
	 * 
	 * @return the range
	 */
	AddressRange getRange();

	/**
	 * Get the lifespan of this code unit
	 * 
	 * @return the lifepsna
	 */
	Range<Long> getLifespan();

	/**
	 * Get the start snap of this code unit
	 * 
	 * @return the first snap of this unit's lifespan
	 */
	long getStartSnap();

	/**
	 * Set the end snap of this code unit
	 * 
	 * @param endSnap the last snap of this unit's lifespan
	 * @throws IllegalArgumentException if the end snap is less than the start snap
	 */
	void setEndSnap(long endSnap);

	/**
	 * Get the end snap of this code unit
	 * 
	 * @return the last snap of this unit's lifespan
	 */
	long getEndSnap();

	/**
	 * Delete this code unit
	 */
	void delete();

	/**
	 * Read bytes starting at this unit's address plus the given offset into the given buffer
	 * 
	 * <p>
	 * This method honors the markers (position and limit) of the destination buffer. Use those
	 * markers to control the destination offset and maximum length.
	 * 
	 * @param buffer the destination buffer
	 * @param addressOffset the offset from this unit's (minimum) address
	 * @return the number of bytes read
	 */
	int getBytes(ByteBuffer buffer, int addressOffset);

	/**
	 * Set a property of the given type to the given value
	 * 
	 * <p>
	 * This method is preferred to {@link #setTypedProperty(String, Object)}, because in the case
	 * the property map does not already exist, the desired type is given explicitly.
	 * 
	 * <p>
	 * While it is best practice to match {@code valueClass} exactly with the type of the map, this
	 * method will work so long as the given {@code valueClass} is a subtype of the map's type. If
	 * the property map does not already exist, it is created with the given {@code valueClass}.
	 * Note that there is no established mechanism for restoring values of a subtype from the
	 * underlying database.
	 * 
	 * <p>
	 * Currently, the only supported types are {@link Integer}, {@link String}, {@link Void}, and
	 * subtypes of {@link Saveable}.
	 * 
	 * @param name the name of the property
	 * @param valueClass the type of the property
	 * @param value the value of the property
	 */
	<T> void setProperty(String name, Class<T> valueClass, T value);

	/**
	 * Set a property having the same type as the given value
	 * 
	 * <p>
	 * If the named property has a super-type of the value's type, the value is accepted. If not, a
	 * {@link TypeMismatchException} is thrown. If the property map does not already exist, it is
	 * created having <em>exactly</em> the type of the given value.
	 * 
	 * <p>
	 * This method exists for two reasons: 1) To introduce the type variable U, which is more
	 * existential, and 2) to remove the requirement to subtype {@link Saveable}. Otherwise, this
	 * method is identical in operation to {@link #setProperty(String, Saveable)}.
	 * 
	 * @param name the name of the property
	 * @param value the value of the property
	 */
	<T, U extends T> void setTypedProperty(String name, T value);

	/**
	 * Get a property having the given type
	 * 
	 * <p>
	 * If the named property has a sub-type of the given {@code valueClass}, the value (possibly
	 * {@code null}) is returned. If the property does not exist, {@code null} is returned.
	 * Otherwise {@link TypeMismatchException} is thrown, even if the property is not set at this
	 * unit's address.
	 * 
	 * <p>
	 * Note that getting a {@link Void} property will always return {@code null}. Use
	 * {@link #getVoidProperty(String)} instead to detect if the property is set.
	 * {@link #hasProperty(String)} will also work, but it does not verify that the property's type
	 * is actually {@link Void}.
	 * 
	 * @param name the name of the property
	 * @param valueClass the expected type of the value (or a super-type thereof)
	 * @return the value of the property, or {@code null}
	 */
	<T> T getProperty(String name, Class<T> valueClass);

	@Override
	TraceReference[] getMnemonicReferences();

	@Override
	TraceReference[] getOperandReferences(int index);

	@Override
	TraceReference getPrimaryReference(int index);

	@Override
	TraceReference[] getReferencesFrom();
}
