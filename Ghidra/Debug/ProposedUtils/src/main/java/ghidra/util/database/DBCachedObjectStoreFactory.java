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
package ghidra.util.database;

import java.io.IOException;
import java.lang.reflect.*;
import java.lang.reflect.Field;
import java.nio.*;
import java.nio.charset.*;
import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import db.*;
import ghidra.util.Msg;
import ghidra.util.database.annot.*;
import ghidra.util.database.annot.DBAnnotatedField.DefaultCodec;
import ghidra.util.database.err.NoDefaultCodecException;
import ghidra.util.exception.VersionException;

/**
 * A factory for creating object stores for classes extending {@link DBAnnotatedObject}
 * 
 * <p>
 * See {@link DBAnnotatedObject} for more documentation, including an example object definition. To
 * create a store, e.g., for {@code Person}:
 * 
 * <pre>
 * interface MyDomainObject {
 * 	Person createPerson(String name, String address);
 * 
 * 	Person getPerson(long id);
 * 
 * 	Collection<? extends Person> getPeopleNamed(String name);
 * }
 * 
 * public class DBMyDomainObject extends DBCachedDomainObjectAdapter implements MyDomainObject {
 * 	private final DBCachedObjectStoreFactory factory;
 * 	private final DBCachedObjectStore<DBPerson> people;
 * 	private final DBCachedObjectIndex<String, DBPerson> peopleByName;
 * 
 * 	public DBMyDomainObject() { // Constructor parameters elided
 * 		// super() invocation elided
 * 		factory = new DBCachedObjectStoreFactory(this);
 * 		try {
 * 			people = factory.getOrCreateCachedStore(DBPerson.TABLE_NAME, DBPerson.class,
 * 				DBPerson::new, false);
 * 			peopleByName = people.getIndex(String.class, DBPerson.NAME_COLUMN);
 * 		}
 * 		catch (VersionException e) {
 * 			// ...
 * 		}
 * 		catch (IOException e) {
 * 			// ...
 * 		}
 * 	}
 * 
 * 	&#64;Override
 * 	public Person createPerson(String name, String address) {
 * 		// Locking details elided
 * 		DBPerson person = people.create();
 * 		person.set(name, address);
 * 		return person;
 * 	}
 * 
 * 	&#64;Override
 * 	public Person getPerson(int id) {
 * 		// Locking details elided
 * 		return people.getAt(id);
 * 	}
 * 
 * 	&#64;Override
 * 	public Collection<Person> getPeopleNamed(String name) {
 * 		// Locking details elided
 * 		return peopleByName.get(name);
 * 	}
 * }
 * </pre>
 * 
 * <p>
 * The factory manages tables on behalf of the domain object, so it is typically the first thing
 * constructed. In practice, complex domain objects should be composed of several managers, each of
 * which constructs its own stores, but for simplicity in this example, we construct the people
 * store in the domain object. This will check the schema and could throw a
 * {@link VersionException}. Typically, immediately after constructing the store, all desired
 * indexes of the store are retrieved. The domain object then provides API methods for creating and
 * retrieving people. Providing direct API client access to the store from a domain object is highly
 * discouraged.
 * 
 * @implNote This class bears the responsibility of processing the {@link DBAnnotatedField},
 *           {@link DBAnnotatedColumn}, and {@link DBAnnotatedObjectInfo} annotations. The relevant
 *           entry point is {{@link #buildInfo(Class)}. It creates a {@link TableInfo} for the given
 *           class, which builds the schema for creating the {@link Table} that backs an object
 *           store for that class.
 */
public class DBCachedObjectStoreFactory {

	/**
	 * A codec for encoding alternative data types
	 *
	 * <p>
	 * The database framework supports limited types of fields, each capable for storing a specific
	 * Java data type. A simple codec is provided for "encoding" each of the supported types into
	 * its corresponding {@link db.Field} type. For other types, additional custom codecs must be
	 * implemented. Custom codecs must be explicitly selected using the
	 * {@link DBAnnotatedField#codec()} attribute.
	 * 
	 * <p>
	 * <b>NOTE:</b> When changing the implementation of a codec, keep in mind whether or not it
	 * implies a change to the schema of tables that use the codec. If it does, their schema
	 * versions, i.e., {@link DBAnnotatedObjectInfo#version()} should be incremented and
	 * considerations made for supporting upgrades.
	 * 
	 * <p>
	 * In some cases, the codec may require context information from the containing object. This is
	 * facilitated via the {@link OT} type parameter. If no additional context is required,
	 * {@link DBAnnotatedObject} is sufficient. If context is required, then additional interfaces
	 * can be required via type intersection:
	 * 
	 * <pre>
	 * public interface MyContext {
	 * 	// ...
	 * }
	 * 
	 * public interface ContextProvider {
	 * 	MyContext getContext();
	 * }
	 * 
	 * public static class MyDBFieldCodec<OT extends DBAnnotatedObject & ContextProvider> extends
	 * 		AbstractDBFieldCodec<MyType, OT, BinaryField> {
	 * 
	 * 	public MyDBFieldCodec(Class<OT> objectType, Field field, int column) {
	 * 		super(MyType.class, objectType, BinaryField.class, field, column);
	 * 	}
	 * 
	 * 	&#64;Override
	 * 	protected void doStore(OT obj, DBRecord record) {
	 * 		MyContext ctx = obj.getContext();
	 * 		// ...
	 * 	}
	 * 	// ...
	 * }
	 * </pre>
	 * 
	 * <p>
	 * Note that this implementation uses {@link AbstractDBFieldCodec}, which is highly recommended.
	 * Whether or not the abstract codec is used, the constructor must have the signature
	 * {@code (Class<OT>, Field, int)}, which are the containing object's actual type, the field of
	 * the Java class whose values to encode, and the record column number into which to store those
	 * encoded values. The type variables {@link VT} and {@link FT} of the codec indicate it can
	 * encode values of type {@code MyType} into a byte array for storage into a
	 * {@link BinaryField}. See {@link ByteDBFieldCodec} for the simplest example with actual
	 * encoding and decoding implementations. To use the example codec in an object:
	 * 
	 * <pre>
	 * &#64;DBAnnotatedObjectInfo(version = 1)
	 * public static class SomeObject extends DBAnnotatedObject implements ContextProvider {
	 * 	static final String MY_COLUMN_NAME = "My";
	 * 
	 * 	&#64;DBAnnotatedColumn(MY_COLUMN_NAME)
	 * 	static DBObjectColumn MY_COLUMN;
	 * 
	 * 	&#64;DBAnnotatedField(column = MY_COLUMN_NAME, codec = MyDBFieldCodec.class)
	 * 	private MyType my;
	 * 
	 * 	// ...
	 * 
	 * 	&#64;Override
	 * 	public MyContext getContext() {
	 * 		// ...
	 * 	}
	 * }
	 * </pre>
	 * 
	 * <p>
	 * Notice that {@code SomeObject} must implement {@code ContextProvider}. This restriction is
	 * checked at runtime when the object store is created, but a compile-time annotation processor
	 * can check this restriction sooner. This has been implemented, at least in part, in the
	 * {@code AnnotationProcessor} project. It is recommended that at most one additional interface
	 * is required in by {@link OT}. If multiple contexts are required, consider declaring an
	 * interface that extends the multiple required interfaces. Alternatively, consider a new
	 * interface that provides one composite context.
	 * 
	 * @param <VT> the type of the value encoded, i.e., the object field's Java type
	 * @param <OT> the upper bound on objects containing the field
	 * @param <FT> the type of the database field into which the value is encoded
	 */
	public interface DBFieldCodec<VT, OT extends DBAnnotatedObject, FT extends db.Field> {
		/**
		 * Encode the field from the given object into the given record
		 * 
		 * @param obj the source object
		 * @param record the destination record
		 */
		void store(OT obj, DBRecord record);

		/**
		 * Encode the given field value into the given field
		 * 
		 * @param value the value
		 * @param f the field
		 */
		void store(VT value, FT f);

		/**
		 * Decode the field from the given record into the given object
		 * 
		 * @param obj the destination object
		 * @param record the source record
		 */
		void load(OT obj, DBRecord record);

		/**
		 * Get the type of values encoded and decoded
		 * 
		 * @return the value type
		 */
		Class<VT> getValueType();

		/**
		 * Get the upper bound on objects with fields using this codec
		 * 
		 * @return the upper bound
		 */
		Class<OT> getObjectType();

		/**
		 * Get the type of field storing the values
		 * 
		 * @return the field type
		 */
		Class<FT> getFieldType();

		/**
		 * Encode the given value into a new field
		 * 
		 * @param value the value
		 * @return the field with the encoded value
		 */
		default FT encodeField(VT value) {
			try {
				FT field = getFieldType().getConstructor().newInstance();
				store(value, field);
				return field;
			}
			catch (InstantiationException | IllegalAccessException | IllegalArgumentException
					| InvocationTargetException | NoSuchMethodException | SecurityException e) {
				throw new AssertionError(e);
			}
		}

		/**
		 * Get the value from the object
		 * 
		 * @param obj the source object
		 * @return the value
		 */
		VT getValue(OT obj);
	}

	/**
	 * An abstract implementation of {@link DBFieldCodec}
	 * 
	 * <p>
	 * This reduces the implementation burden to {@link #doLoad(DBAnnotatedObject, DBRecord)},
	 * {@link #doStore(DBAnnotatedObject, DBRecord)}, and {@link #store(Object, db.Field)}.
	 */
	public static abstract class AbstractDBFieldCodec<VT, OT extends DBAnnotatedObject, FT extends db.Field>
			implements DBFieldCodec<VT, OT, FT> {
		protected final Class<VT> valueType;
		protected final Class<OT> objectType;
		protected final Class<FT> fieldType;
		protected final Field field;
		protected final int column;

		/**
		 * Construct a codec
		 * 
		 * @param valueType
		 * @param objectType
		 * @param fieldType
		 * @param field
		 * @param column
		 */
		public AbstractDBFieldCodec(Class<VT> valueType, Class<OT> objectType, Class<FT> fieldType,
				Field field, int column) {
			if (!field.getDeclaringClass().isAssignableFrom(objectType)) {
				throw new IllegalArgumentException(
					"Given field does not apply to given object type");
			}
			if (field.getType() != valueType) {
				throw new IllegalArgumentException(
					"Given field does not have the given type: " + valueType + " != " + field);
			}
			this.valueType = valueType;
			this.objectType = objectType;
			this.fieldType = fieldType;
			this.field = field;
			this.column = column;
		}

		@Override
		public void store(OT obj, DBRecord record) {
			try {
				doStore(obj, record);
			}
			catch (IllegalArgumentException | IllegalAccessException e) {
				throw new AssertionError(e);
			}
		}

		@Override
		public void load(OT obj, DBRecord record) {
			try {
				doLoad(obj, record);
			}
			catch (IllegalArgumentException | IllegalAccessException e) {
				throw new AssertionError(e);
			}
		}

		@Override
		public Class<VT> getValueType() {
			return valueType;
		}

		@Override
		public Class<OT> getObjectType() {
			return objectType;
		}

		@Override
		public Class<FT> getFieldType() {
			return fieldType;
		}

		@Override
		public VT getValue(OT obj) {
			try {
				return valueType.cast(field.get(obj));
			}
			catch (IllegalArgumentException | IllegalAccessException e) {
				throw new AssertionError(e);
			}
		}

		/**
		 * Set the value of the object
		 * 
		 * @param obj the object whose field to set
		 * @param value the value to assign
		 * @throws IllegalArgumentException as in {@link Field#set(Object, Object)}
		 * @throws IllegalAccessException as in {@link Field#set(Object, Object)}
		 */
		protected void setValue(OT obj, VT value)
				throws IllegalArgumentException, IllegalAccessException {
			field.set(obj, value);
		}

		/**
		 * Same as {@link #store(DBAnnotatedObject, DBRecord)}, but permits exceptions
		 */
		protected abstract void doStore(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException;

		/**
		 * Same as {@link #load(DBAnnotatedObject, DBRecord), but permits exceptions
		 */
		protected abstract void doLoad(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException;
	}

	/**
	 * The built-in codec for {@code boolean}
	 */
	public static class BooleanDBFieldCodec<OT extends DBAnnotatedObject>
			extends AbstractDBFieldCodec<Boolean, OT, BooleanField> {
		public BooleanDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(boolean.class, objectType, BooleanField.class, field, column);
		}

		@Override
		public void doStore(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			record.setBooleanValue(column, field.getBoolean(obj));
		}

		@Override
		public void store(Boolean value, BooleanField f) {
			f.setBooleanValue(value);
		}

		@Override
		public void doLoad(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			field.setBoolean(obj, record.getBooleanValue(column));
		}
	}

	/**
	 * The built-in codec for {@code byte}
	 */
	public static class ByteDBFieldCodec<OT extends DBAnnotatedObject>
			extends AbstractDBFieldCodec<Byte, OT, ByteField> {
		public ByteDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(byte.class, objectType, ByteField.class, field, column);
		}

		@Override
		public void doStore(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			record.setByteValue(column, field.getByte(obj));
		}

		@Override
		public void store(Byte value, ByteField f) {
			f.setByteValue(value);
		}

		@Override
		public void doLoad(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			field.setByte(obj, record.getByteValue(column));
		}
	}

	/**
	 * The built-in codec for {@code short}
	 */
	public static class ShortDBFieldCodec<OT extends DBAnnotatedObject>
			extends AbstractDBFieldCodec<Short, OT, ShortField> {
		public ShortDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(short.class, objectType, ShortField.class, field, column);
		}

		@Override
		public void doStore(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			record.setShortValue(column, field.getShort(obj));
		}

		@Override
		public void store(Short value, ShortField f) {
			f.setShortValue(value);
		}

		@Override
		public void doLoad(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			field.setShort(obj, record.getShortValue(column));
		}
	}

	/**
	 * The built-in codec for {@code int}
	 */
	public static class IntDBFieldCodec<OT extends DBAnnotatedObject>
			extends AbstractDBFieldCodec<Integer, OT, IntField> {
		public IntDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(int.class, objectType, IntField.class, field, column);
		}

		@Override
		public void doStore(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			record.setIntValue(column, field.getInt(obj));
		}

		@Override
		public void store(Integer value, IntField f) {
			f.setIntValue(value);
		}

		@Override
		public void doLoad(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			field.setInt(obj, record.getIntValue(column));
		}
	}

	/**
	 * The built-in codec for {@code long}
	 */
	public static class LongDBFieldCodec<OT extends DBAnnotatedObject>
			extends AbstractDBFieldCodec<Long, OT, LongField> {
		public LongDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(long.class, objectType, LongField.class, field, column);
		}

		@Override
		public void doStore(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			record.setLongValue(column, field.getLong(obj));
		}

		@Override
		public void store(Long value, LongField f) {
			f.setLongValue(value);
		}

		@Override
		public void doLoad(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			field.setLong(obj, record.getLongValue(column));
		}
	}

	/**
	 * The built-in codec for {@link String}
	 */
	public static class StringDBFieldCodec<OT extends DBAnnotatedObject>
			extends AbstractDBFieldCodec<String, OT, StringField> {
		public StringDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(String.class, objectType, StringField.class, field, column);
		}

		@Override
		public void doStore(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			record.setString(column, getValue(obj));
		}

		@Override
		public void store(String value, StringField f) {
			f.setString(value);
		}

		@Override
		public void doLoad(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			setValue(obj, record.getString(column));
		}
	}

	/**
	 * The built-in codec for {@code byte[]}
	 */
	public static class ByteArrayDBFieldCodec<OT extends DBAnnotatedObject>
			extends AbstractDBFieldCodec<byte[], OT, BinaryField> {
		public ByteArrayDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(byte[].class, objectType, BinaryField.class, field, column);
		}

		@Override
		public void doStore(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			record.setBinaryData(column, getValue(obj));
		}

		@Override
		public void store(byte[] value, BinaryField f) {
			f.setBinaryData(value);
		}

		@Override
		public void doLoad(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			setValue(obj, record.getBinaryData(column));
		}
	}

	/**
	 * The built-in codec for {@code long[]}
	 */
	public static class LongArrayDBFieldCodec<OT extends DBAnnotatedObject>
			extends AbstractDBFieldCodec<long[], OT, BinaryField> {

		public LongArrayDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(long[].class, objectType, BinaryField.class, field, column);
		}

		protected byte[] encode(long[] val) {
			if (val == null) {
				return null;
			}
			ByteBuffer bytes = ByteBuffer.allocate(val.length * Long.BYTES);
			bytes.asLongBuffer().put(val);
			return bytes.array();
		}

		protected long[] decode(byte[] enc) {
			if (enc == null) {
				return null;
			}
			if (enc.length % 8 != 0) {
				Msg.warn(this, "Database record for long[] has remaning bytes");
			}
			int len = enc.length / 8;
			ByteBuffer bytes = ByteBuffer.wrap(enc);
			long[] val = new long[len];
			bytes.asLongBuffer().get(val);
			return val;
		}

		@Override
		protected void doStore(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			record.setBinaryData(column, encode(getValue(obj)));
		}

		@Override
		public void store(long[] value, BinaryField f) {
			f.setBinaryData(encode(value));
		}

		@Override
		protected void doLoad(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			setValue(obj, decode(record.getBinaryData(column)));
		}
	}

	/**
	 * The built-in codec for {@link Enum}
	 */
	public static class EnumDBByteFieldCodec<OT extends DBAnnotatedObject, E extends Enum<E>>
			extends AbstractDBFieldCodec<E, OT, ByteField> {
		private final E[] consts;

		@SuppressWarnings("unchecked")
		public EnumDBByteFieldCodec(Class<OT> objectType, Field field, int column) {
			super((Class<E>) field.getType(), objectType, ByteField.class, field, column);
			this.consts = valueType.getEnumConstants();
			if (consts.length > 255) {
				throw new IllegalArgumentException(
					"Too many constants in " + valueType + " to encode as a byte");
			}
		}

		@Override
		protected void doStore(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			E value = getValue(obj);
			if (value == null) {
				record.setByteValue(column, (byte) -1);
			}
			else {
				record.setByteValue(column, (byte) value.ordinal());
			}
		}

		@Override
		public void store(E value, ByteField f) {
			if (value == null) {
				f.setByteValue((byte) -1);
			}
			else {
				f.setByteValue((byte) value.ordinal());
			}
		}

		@Override
		protected void doLoad(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			byte b = record.getByteValue(column);
			if (b == -1) {
				setValue(obj, null);
			}
			else {
				setValue(obj, consts[b & 0xff]);
			}
		}
	}

	/**
	 * Codec for a primitive type
	 * 
	 * <p>
	 * This is used by {@link VariantDBFieldCodec} to encode primitive values. Sadly, the existing
	 * primitive field codecs cannot be used, since they write to fields directly. All these encode
	 * into byte buffers, since the variant codec uses {@link BinaryField}.
	 * 
	 * @param <T> the type of values encoded
	 */
	public interface PrimitiveCodec<T> {
		/**
		 * A byte value which identifies this codec's type as the selected type
		 * 
		 * @return the selector
		 */
		byte getSelector();

		/**
		 * Decode the value from the given buffer
		 * 
		 * @param buffer the source buffer
		 * @return the value
		 */
		T decode(ByteBuffer buffer);

		/**
		 * Encode the value into the given buffer
		 * 
		 * @param buffer the destination buffer
		 * @param value the value
		 */
		void encode(ByteBuffer buffer, T value);

		/**
		 * The the class describing {@link T}
		 * 
		 * @return the class
		 */
		Class<T> getValueClass();

		/**
		 * An abstract implementation of {@link PrimitiveCodec}
		 */
		abstract class AbstractPrimitiveCodec<T> implements PrimitiveCodec<T> {
			static byte nextSelector = 0;
			protected final byte selector = nextSelector++;
			protected final Class<T> valueClass;

			public AbstractPrimitiveCodec(Class<T> valueClass) {
				this.valueClass = valueClass;
			}

			@Override
			public byte getSelector() {
				return selector;
			}

			@Override
			public Class<T> getValueClass() {
				return valueClass;
			}
		}

		/**
		 * A implementation of {@link PrimitiveCodec} from lambdas or method references
		 */
		class SimplePrimitiveCodec<T> extends AbstractPrimitiveCodec<T> {
			protected final Function<ByteBuffer, T> decode;
			protected final BiConsumer<ByteBuffer, T> encode;

			public SimplePrimitiveCodec(Class<T> valueClass, Function<ByteBuffer, T> decode,
					BiConsumer<ByteBuffer, T> encode) {
				super(valueClass);
				this.decode = decode;
				this.encode = encode;
			}

			@Override
			public T decode(ByteBuffer buffer) {
				return decode.apply(buffer);
			}

			@Override
			public void encode(ByteBuffer buffer, T value) {
				encode.accept(buffer, value);
			}
		}

		/**
		 * An implementation of an array codec, using its element codec, where elements can be
		 * primitives
		 *
		 * @param <E> the type of elements
		 * @param <T> the type of the value, i.e., would be {@code E[]}, except we want {@link E} to
		 *            be primitive.
		 */
		class ArrayPrimitiveCodec<E, T> extends AbstractPrimitiveCodec<T> {
			protected final PrimitiveCodec<E> elemCodec;
			protected final Class<E> elemClass;

			public ArrayPrimitiveCodec(Class<T> valueClass, PrimitiveCodec<E> elemCodec) {
				super(valueClass);
				assert valueClass.isArray();
				this.elemCodec = elemCodec;
				this.elemClass = elemCodec.getValueClass();
			}

			@Override
			public T decode(ByteBuffer buffer) {
				List<E> result = new ArrayList<>();
				while (buffer.hasRemaining()) {
					result.add(elemCodec.decode(buffer));
				}
				int size = result.size();
				Object arr = Array.newInstance(valueClass.getComponentType(), size);
				for (int i = 0; i < size; i++) {
					Array.set(arr, i, result.get(i));
				}
				return valueClass.cast(arr);
			}

			@Override
			public void encode(ByteBuffer buffer, T value) {
				int len = Array.getLength(value);
				for (int i = 0; i < len; i++) {
					elemCodec.encode(buffer, elemClass.cast(Array.get(value, i)));
				}
			}
		}

		/**
		 * An implementation of an array codec, using its element codec, where elements are objects
		 * 
		 * @param <E> the type of elements
		 */
		class ArrayObjectCodec<E> extends ArrayPrimitiveCodec<E, E[]> {
			@SuppressWarnings("unchecked")
			public ArrayObjectCodec(PrimitiveCodec<E> elemCodec) {
				super((Class<E[]>) Array.newInstance(elemCodec.getValueClass(), 0).getClass(),
					elemCodec);
			}
		}

		/**
		 * A codec which encodes length-value, using the (unbounded) codec for value
		 */
		class LengthBoundCodec<T> extends AbstractPrimitiveCodec<T> {
			protected final PrimitiveCodec<T> unbounded;

			public LengthBoundCodec(PrimitiveCodec<T> unbounded) {
				super(unbounded.getValueClass());
				this.unbounded = unbounded;
			}

			@Override
			public T decode(ByteBuffer buffer) {
				int length = buffer.getInt();
				int oldLimit = buffer.limit();
				try {
					buffer.limit(buffer.position() + length);
					return unbounded.decode(buffer);
				}
				finally {
					buffer.limit(oldLimit);
				}
			}

			@Override
			public void encode(ByteBuffer buffer, T value) {
				int lenPos = buffer.position();
				buffer.putInt(0);
				int startPos = buffer.position();
				unbounded.encode(buffer, value);
				int endPos = buffer.position();
				buffer.putInt(lenPos, endPos - startPos);
			}
		}

		/*
		 * WARNING: Careful changing the order of these declarations, as this will change the
		 * selectors. Doing so would require a schema version bump of any table using the
		 * {@link VariantDBFieldCodec}.
		 */
		/** Codec for {@code boolean} */
		PrimitiveCodec<Boolean> BOOL = new SimplePrimitiveCodec<>(Boolean.class,
			buf -> buf.get() != 0, (buf, b) -> buf.put((byte) (b ? 1 : 0)));
		/** Codec for {@code byte} */
		PrimitiveCodec<Byte> BYTE =
			new SimplePrimitiveCodec<>(Byte.class, ByteBuffer::get, ByteBuffer::put);
		/** Codec for {@code char} */
		PrimitiveCodec<Character> CHAR =
			new SimplePrimitiveCodec<>(Character.class, ByteBuffer::getChar, ByteBuffer::putChar);
		/** Codec for {@code short} */
		PrimitiveCodec<Short> SHORT =
			new SimplePrimitiveCodec<>(Short.class, ByteBuffer::getShort, ByteBuffer::putShort);
		/** Codec for {@code int} */
		PrimitiveCodec<Integer> INT =
			new SimplePrimitiveCodec<>(Integer.class, ByteBuffer::getInt, ByteBuffer::putInt);
		/** Codec for {@code long} */
		PrimitiveCodec<Long> LONG =
			new SimplePrimitiveCodec<>(Long.class, ByteBuffer::getLong, ByteBuffer::putLong);
		/** Codec for {@link String} */
		PrimitiveCodec<String> STRING = new AbstractPrimitiveCodec<>(String.class) {
			final Charset cs = Charset.forName("UTF-8");

			@Override
			public String decode(ByteBuffer buffer) {
				CharsetDecoder dec = cs.newDecoder();
				try {
					CharBuffer cb = dec.decode(buffer);
					return cb.toString();
				}
				catch (CharacterCodingException e) {
					throw new AssertionError(e);
				}
			}

			@Override
			public void encode(ByteBuffer buffer, String value) {
				CharsetEncoder enc = cs.newEncoder();
				enc.encode(CharBuffer.wrap(value), buffer, true);
			}
		};
		/** Codec for {@code boolean[]} */
		PrimitiveCodec<boolean[]> BOOL_ARR = new ArrayPrimitiveCodec<>(boolean[].class, BOOL);
		/** Codec for {@code byte[]} */
		PrimitiveCodec<byte[]> BYTE_ARR = new AbstractPrimitiveCodec<>(byte[].class) {
			@Override
			public byte[] decode(ByteBuffer buffer) {
				byte[] result = new byte[buffer.remaining()];
				buffer.get(result);
				return result;
			}

			@Override
			public void encode(ByteBuffer buffer, byte[] value) {
				buffer.put(value);
			}
		};
		/** Codec for {@code char[]} */
		PrimitiveCodec<char[]> CHAR_ARR = new ArrayPrimitiveCodec<>(char[].class, CHAR);
		/** Codec for {@code short[]} */
		PrimitiveCodec<short[]> SHORT_ARR = new ArrayPrimitiveCodec<>(short[].class, SHORT);
		/** Codec for {@code int[]} */
		PrimitiveCodec<int[]> INT_ARR = new ArrayPrimitiveCodec<>(int[].class, INT);
		/** Codec for {@code long[]} */
		PrimitiveCodec<long[]> LONG_ARR = new ArrayPrimitiveCodec<>(long[].class, LONG);
		/** Codec for {@code String[]} */
		PrimitiveCodec<String[]> STRING_ARR =
			new ArrayObjectCodec<>(new LengthBoundCodec<>(STRING));

		Map<Byte, PrimitiveCodec<?>> CODECS_BY_SELECTOR = Stream
				.of(BOOL, BYTE, CHAR, SHORT, INT, LONG, STRING, BOOL_ARR, BYTE_ARR, CHAR_ARR,
					SHORT_ARR, INT_ARR, LONG_ARR, STRING_ARR)
				.collect(Collectors.toMap(c -> c.getSelector(), c -> c));
		Map<Class<?>, PrimitiveCodec<?>> CODECS_BY_CLASS = CODECS_BY_SELECTOR.values()
				.stream()
				.collect(Collectors.toMap(c -> c.getValueClass(), c -> c));

		/**
		 * Get the codec for the given type
		 * 
		 * @param <T> the type
		 * @param cls the class describing {@link T}
		 * @return the codec
		 * @throws IllegalArgumentException if the type is not supported
		 */
		static <T> PrimitiveCodec<T> getCodec(Class<T> cls) {
			@SuppressWarnings("unchecked")
			PrimitiveCodec<T> obj = (PrimitiveCodec<T>) CODECS_BY_CLASS.get(cls);
			if (obj == null) {
				throw new IllegalArgumentException("No variant codec for class " + cls);
			}
			return obj;
		}

		/**
		 * Get the codec for the given selector
		 * 
		 * @param sel the selector
		 * @return the codec
		 * @throws IllegalArgumentException if the selector is unknown
		 */
		static PrimitiveCodec<?> getCodec(byte sel) {
			PrimitiveCodec<?> obj = CODECS_BY_SELECTOR.get(sel);
			if (obj == null) {
				throw new IllegalArgumentException("No variant codec with selector " + sel);
			}
			return obj;
		}
	}

	/**
	 * A custom codec for field of "variant" type
	 * 
	 * <p>
	 * This is suitable for use on fields of type {@link Object}; however, only certain types can
	 * actually be encoded. The encoding uses a 1-byte type selector followed by the byte-array
	 * encoded value.
	 */
	public static class VariantDBFieldCodec<OT extends DBAnnotatedObject>
			extends AbstractDBFieldCodec<Object, OT, BinaryField> {
		public VariantDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(Object.class, objectType, BinaryField.class, field, column);
		}

		protected PrimitiveCodec<?> getPrimitiveCodec(Class<?> cls) {
			return PrimitiveCodec.getCodec(cls);
		}

		protected PrimitiveCodec<?> getPrimitiveCodec(OT obj, byte sel) {
			return PrimitiveCodec.getCodec(sel);
		}

		protected byte[] encode(Object value) {
			if (value == null) {
				return null;
			}
			@SuppressWarnings("unchecked")
			PrimitiveCodec<Object> codec =
				(PrimitiveCodec<Object>) getPrimitiveCodec(value.getClass());
			ByteBuffer buf = ByteBuffer.allocate(1024);
			while (true) {
				try {
					buf.clear();
					buf.put(codec.getSelector());
					codec.encode(buf, value);
					buf.flip();
					byte[] result = new byte[buf.remaining()];
					buf.get(result);
					return result;
				}
				catch (BufferOverflowException e) {
					buf = ByteBuffer.allocate(buf.capacity() * 2);
				}
			}
		}

		protected Object decode(OT obj, byte[] enc) {
			if (enc == null) {
				return null;
			}
			ByteBuffer buf = ByteBuffer.wrap(enc);
			PrimitiveCodec<?> codec = getPrimitiveCodec(obj, buf.get());
			return codec.decode(buf);
		}

		@Override
		public void store(Object value, BinaryField f) {
			f.setBinaryData(encode(value));
		}

		@Override
		protected void doStore(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			record.setBinaryData(column, encode(getValue(obj)));
		}

		@Override
		protected void doLoad(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			setValue(obj, decode(obj, record.getBinaryData(column)));
		}
	}

	/**
	 * The information needed to construct a {@link Table} and store objects into it
	 *
	 * @param <OT> the type of object stored in the table
	 */
	private static class TableInfo<OT extends DBAnnotatedObject> {
		public final Schema schema;
		public final int[] indexColumns;
		public final ArrayList<DBFieldCodec<?, OT, ?>> codecs;

		/**
		 * Derive the table information
		 * 
		 * @param objectType the class of objects being described
		 * @param schemaVersion the schema version as given in
		 *            {@link DBAnnotatedObjectInfo#version()}
		 * @param fieldsByColumnName the class fields by user-defined column name
		 * @param indexFields the fields selected for table indexes
		 * @param sparseFields the fields selected for sparse storage
		 */
		TableInfo(Class<OT> objectType, int schemaVersion, Map<String, Field> fieldsByColumnName,
				Collection<Field> indexFields, Collection<Field> sparseFields) {
			codecs = new ArrayList<>(fieldsByColumnName.size());
			List<Integer> indexCols = new ArrayList<>(indexFields.size());
			SchemaBuilder builder = new SchemaBuilder();
			builder.version(schemaVersion);
			builder.keyField("Key", LongField.class);

			for (Map.Entry<String, Field> ent : fieldsByColumnName.entrySet()) {
				int next = builder.fieldCount();
				Field field = ent.getValue();
				DBFieldCodec<?, OT, ?> codec = makeCodec(objectType, field, next);
				if (indexFields.contains(field)) {
					indexCols.add(next);
				}
				codecs.add(codec);
				builder.field(ent.getKey(), codec.getFieldType(), sparseFields.contains(field));
			}
			schema = builder.build();

			indexColumns = SchemaBuilder.toIntArray(indexCols);
		}

		/**
		 * Initialize the static {@link DBObjectColumn} fields marked with {@link DBAnnotatedColumn}
		 * 
		 * @param objectType the clas of objects being described
		 * @param numbersByName the assigned column numbers by user-defined name
		 */
		void writeColumnNumbers(Class<? extends DBAnnotatedObject> objectType,
				Map<String, Integer> numbersByName) {
			Class<?> superType = objectType.getSuperclass();
			if (DBAnnotatedObject.class.isAssignableFrom(superType)) {
				writeColumnNumbers(superType.asSubclass(DBAnnotatedObject.class), numbersByName);
			}
			for (Field f : objectType.getDeclaredFields()) {
				DBAnnotatedColumn annotation = f.getAnnotation(DBAnnotatedColumn.class);
				if (annotation == null) {
					continue;
				}
				int mod = f.getModifiers();
				if (!Modifier.isStatic(mod)) {
					throw new IllegalArgumentException(
						"@" + DBAnnotatedColumn.class.getSimpleName() +
							" fields must be static. Got " + f);
				}
				if (f.getType() != DBObjectColumn.class) {
					throw new IllegalArgumentException(
						"@" + DBAnnotatedColumn.class.getSimpleName() + " fields must be " +
							DBObjectColumn.class.getSimpleName() + " type. Got " + f);
				}

				String name = annotation.value();

				Integer columnNumber = numbersByName.get(name);
				if (columnNumber == null) {
					throw new IllegalArgumentException("Cannot find column '" + name + "' for @" +
						DBAnnotatedColumn.class.getSimpleName() + " on " + f);
				}

				f.setAccessible(true);
				try {
					DBObjectColumn already = (DBObjectColumn) f.get(null);
					if (already == null) {
						f.set(null, DBObjectColumn.get(columnNumber.intValue()));
					}
					else if (already.columnNumber != columnNumber.intValue()) {
						throw new AssertionError();
					}
				}
				catch (IllegalAccessException e) {
					throw new AssertionError(e);
				}
			}
		}

		/**
		 * Initialize the static {@link DBObjectColumn} fields marked with {@link DBAnnotatedColumn}
		 * 
		 * @param objectType the clas of objects being described
		 */
		void writeColumnNumbers(Class<? extends DBAnnotatedObject> objectType) {
			Map<String, Integer> numbersByName = new HashMap<>();
			String[] names = schema.getFieldNames();
			for (int i = 0; i < names.length; i++) {
				numbersByName.put(names[i], i);
			}
			writeColumnNumbers(objectType, numbersByName);
		}
	}

	/**
	 * A cache of derived table information by class
	 */
	private static final Map<Class<? extends DBAnnotatedObject>, TableInfo<?>> INFO_MAP =
		new HashMap<>();

	/**
	 * Get a built-in codec for a field of the given type
	 * 
	 * @param type the type
	 * @return the built-in codec
	 * @throws NoDefaultCodecException if there is no built-in codec for the field
	 */
	private static Class<?> getDefaultCodecClass(Class<?> type) {
		if (type == boolean.class || type == Boolean.class) {
			return BooleanDBFieldCodec.class;
		}
		if (type == byte.class || type == Byte.class) {
			return ByteDBFieldCodec.class;
		}
		if (type == short.class || type == Short.class) {
			return ShortDBFieldCodec.class;
		}
		if (type == int.class || type == Integer.class) {
			return IntDBFieldCodec.class;
		}
		if (type == long.class || type == Long.class) {
			return LongDBFieldCodec.class;
		}
		if (type == String.class) {
			return StringDBFieldCodec.class;
		}
		if (type == byte[].class) {
			return ByteArrayDBFieldCodec.class;
		}
		// TODO: Other primitive arrays?
		if (type == long[].class) {
			return LongArrayDBFieldCodec.class;
		}
		if (Enum.class.isAssignableFrom(type)) {
			return EnumDBByteFieldCodec.class;
		}
		throw new NoDefaultCodecException(
			type + " does not have a default codec. Please specify a codec.");
	}

	/**
	 * Construct the codec for the given field
	 * 
	 * <p>
	 * This adheres to the custom codec, if specified on the fields annotation.
	 * 
	 * @param <OT> the type of objects being described
	 * @param objectType the class describing {@link OT}
	 * @param field the field to encode and decode
	 * @param column the column number in the record
	 * @return the codec
	 * @throws IllegalArgumentException if the selected codec's constructor does not have the
	 *             required signature
	 */
	@SuppressWarnings({ "unchecked" })
	private static <OT extends DBAnnotatedObject> DBFieldCodec<?, OT, ?> makeCodec(
			Class<OT> objectType, Field field, int column) throws IllegalArgumentException {
		Class<?> type = field.getType();
		DBAnnotatedField annotation = field.getAnnotation(DBAnnotatedField.class);
		assert annotation != null;
		Class<?> codecCls = annotation.codec();
		if (codecCls == DefaultCodec.class) {
			codecCls = getDefaultCodecClass(type);
		}
		try {
			Constructor<?> codecCons = codecCls.getConstructor(Class.class, Field.class, int.class);
			return (DBFieldCodec<?, OT, ?>) codecCons.newInstance(objectType, field, column);
		}
		catch (NoSuchMethodException | SecurityException | InstantiationException
				| IllegalAccessException e) {
			throw new AssertionError(e);
		}
		catch (InvocationTargetException e) {
			Throwable cause = e.getCause();
			if (cause instanceof RuntimeException) {
				throw (RuntimeException) cause;
			}
			throw new RuntimeException(cause); // TODO: What exception type for this?
		}
	}

	/**
	 * Get the table information for the given class
	 * 
	 * @param <T> the type of objects to store in a table
	 * @param cls the class describing {@link T}
	 * @return the table information
	 */
	@SuppressWarnings("unchecked")
	private static <T extends DBAnnotatedObject> TableInfo<T> getInfo(Class<T> cls) {
		synchronized (INFO_MAP) {
			return (TableInfo<T>) INFO_MAP.computeIfAbsent(cls,
				DBCachedObjectStoreFactory::buildInfo);
		}
	}

	/**
	 * Get the codecs for the given class
	 * 
	 * @param <OT> the type of objects to store in the table
	 * @param objectType the class describing {@link OT}
	 * @return the codecs, in column order
	 */
	static <OT extends DBAnnotatedObject> List<DBFieldCodec<?, OT, ?>> getCodecs(
			Class<OT> objectType) {
		return getInfo(objectType).codecs;
	}

	/**
	 * The non-cached implementation of {@link #getInfo(Class)}
	 */
	private static <OT extends DBAnnotatedObject> TableInfo<OT> buildInfo(Class<OT> objectType) {
		DBAnnotatedObjectInfo info = objectType.getAnnotation(DBAnnotatedObjectInfo.class);
		if (info == null) {
			throw new IllegalArgumentException(
				DBAnnotatedObject.class.getSimpleName() + " " + objectType.getName() +
					" must have @" + DBAnnotatedObjectInfo.class.getSimpleName() + " annotation");
		}

		Map<String, Field> fields = new LinkedHashMap<>();
		List<Field> indexFields = new ArrayList<>();
		List<Field> sparseFields = new ArrayList<>();
		collectFields(objectType, fields, indexFields, sparseFields);

		TableInfo<OT> tableInfo =
			new TableInfo<>(objectType, info.version(), fields, indexFields, sparseFields);
		tableInfo.writeColumnNumbers(objectType);

		return tableInfo;
	}

	/**
	 * Collect the fields of the given class, recursively, starting with its super class
	 * 
	 * @param cls the class
	 * @param fields a map to receive the fields
	 * @param indexFields a list for receiving fields to be indexed
	 * @param sparseFields a list for receiving fields to have sparse storage
	 */
	private static void collectFields(Class<?> cls, Map<String, Field> fields,
			List<Field> indexFields, List<Field> sparseFields) {
		Class<?> superclass = cls.getSuperclass();
		if (superclass != null) {
			collectFields(superclass, fields, indexFields, sparseFields);
		}
		for (Field f : cls.getDeclaredFields()) {
			DBAnnotatedField annotation = f.getAnnotation(DBAnnotatedField.class);
			if (annotation == null) {
				continue;
			}
			int mod = f.getModifiers();
			if (Modifier.isStatic(mod) || Modifier.isFinal(mod)) {
				throw new IllegalArgumentException(
					DBAnnotatedField.class.getSimpleName() + " must be non-static and non-final");
			}
			f.setAccessible(true);
			Field old = fields.put(annotation.column(), f);
			if (old != null) {
				indexFields.remove(old);
			}
			if (annotation.indexed()) {
				indexFields.add(f);
			}
			if (annotation.sparse()) {
				sparseFields.add(f);
			}
		}
	}

	private final DBHandle handle;
	private final DBCachedDomainObjectAdapter adapter;

	/**
	 * Construct an object store factory
	 * 
	 * @param adapter the object whose tables to manage
	 */
	public DBCachedObjectStoreFactory(DBCachedDomainObjectAdapter adapter) {
		this.handle = adapter.getDBHandle();
		this.adapter = adapter;
	}

	/**
	 * Get or create the table needed to store objects of the given class
	 * 
	 * <p>
	 * See {@link #getOrCreateCachedStore(String, Class, DBAnnotatedObjectFactory, boolean)}
	 * 
	 * @param name the table name
	 * @param cls the type of objects to store
	 * @param upgradable true if {@link VersionException}s should be marked upgradable when an
	 *            existing table's version is earlier than expected
	 * @return the table
	 * @throws IOException if there's an issue accessing the database
	 * @throws VersionException if an existing table's version does not match that expected
	 */
	public Table getOrCreateTable(String name, Class<? extends DBAnnotatedObject> cls,
			boolean upgradable) throws IOException, VersionException {
		// TODO: System of upgraders
		Table table = handle.getTable(name);
		TableInfo<?> info = getInfo(cls);
		if (table == null) {
			table = handle.createTable(name, info.schema, info.indexColumns);
		}
		int tableVersion = table.getSchema().getVersion();
		int latestVersion = info.schema.getVersion();
		if (tableVersion != latestVersion) {
			throw new VersionException(upgradable && tableVersion < latestVersion);
		}
		return table;
	}

	/**
	 * Get or create a cached store of objects of the given class
	 * 
	 * @param <T> the type of objects in the store
	 * @param tableName the table name
	 * @param cls the class describing {@link T}
	 * @param factory the object's constructor, usually a method reference or lambda
	 * @param upgradable true if {@link VersionException}s should be marked upgradable when an
	 *            existing table's version is earlier than expected
	 * @return the table
	 * @throws IOException if there's an issue accessing the database
	 * @throws VersionException if an existing table's version does not match that expected
	 */
	public <T extends DBAnnotatedObject> DBCachedObjectStore<T> getOrCreateCachedStore(
			String tableName, Class<T> cls, DBAnnotatedObjectFactory<T> factory, boolean upgradable)
			throws VersionException, IOException {
		Table table = getOrCreateTable(tableName, cls, upgradable);
		return new DBCachedObjectStore<>(adapter, cls, factory, table);
	}
}
