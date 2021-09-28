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
package db;

/**
 * <code>FixedField</code> provides an abstract implementation of an unsigned fixed-length
 * field whose value is specified with a byte-array.  This field behaves similar to a 
 * {@link PrimitiveField} in that a null "state" (see {@link #isNull()}) is supported for 
 * sparse record column use with a zero (0) value.  Unlike a variable-length 
 * {@link BinaryField} a null "value" (i.e., data byte array) is not permitted.
 * <br>
 * Implementations may use the internal data byte-array as a lazy storage cache for
 * the actual fixed-length value (i.e., invoking {@link #getBinaryData()} may update
 * the internal data byte-array if needed).
 */
abstract class FixedField extends BinaryField {

	private boolean isNull = false;

	/**
	 * Construct a fixed-length field.  A null "state" may only be established 
	 * by invoking the {@link #setNull()} method after construction provided
	 * the instance is mutable.
	 * @param data initial storage value (may be null)
	 * @param immutable true if field value is immutable
	 */
	FixedField(byte[] data, boolean immutable) {
		super(data, immutable);
	}

	@Override
	public final boolean isVariableLength() {
		return false;
	}

	@Override
	public final boolean isNull() {
		return isNull;
	}

	@Override
	void setNull() {
		checkImmutable();
		this.isNull = true;
	}

	/**
	 * Invoked prior to setting the field's primitive value this
	 * method will perform an immutable check and set to a non-null 
	 * state.
	 */
	final void updatingValue() {
		checkImmutable();
		this.isNull = false;
	}

	@Override
	void truncate(int length) {
		throw new UnsupportedOperationException("Field may not be truncated");
	}

	@Override
	public abstract FixedField copyField();

	@Override
	public abstract FixedField newField();

	@Override
	abstract FixedField getMinValue();

	@Override
	abstract FixedField getMaxValue();

}
