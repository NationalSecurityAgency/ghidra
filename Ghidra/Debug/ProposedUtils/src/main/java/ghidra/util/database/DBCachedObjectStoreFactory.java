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

public class DBCachedObjectStoreFactory {

	public interface DBFieldCodec<VT, OT extends DBAnnotatedObject, FT extends db.Field> {
		void store(OT obj, DBRecord record);

		void store(VT value, FT f);

		void load(OT obj, DBRecord record);

		Class<VT> getValueType();

		Class<OT> getObjectType();

		Class<FT> getFieldType();

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

		VT getValue(OT obj);
	}

	public static abstract class AbstractDBFieldCodec<VT, OT extends DBAnnotatedObject, FT extends db.Field>
			implements DBFieldCodec<VT, OT, FT> {
		protected final Class<VT> valueType;
		protected final Class<OT> objectType;
		protected final Class<FT> fieldType;
		protected final Field field;
		protected final int column;

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

		protected void setValue(OT obj, VT value)
				throws IllegalArgumentException, IllegalAccessException {
			field.set(obj, value);
		}

		protected abstract void doStore(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException;

		protected abstract void doLoad(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException;
	}

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

	public interface PrimitiveCodec<T> {
		byte getSelector();

		T decode(ByteBuffer buffer);

		void encode(ByteBuffer buffer, T value);

		Class<T> getValueClass();

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

		class ArrayPrimitiveCodec<E, T> extends AbstractPrimitiveCodec<T> {
			protected final PrimitiveCodec<E> elemCodec;
			protected final Class<E> elemClass;

			public <P> ArrayPrimitiveCodec(Class<T> valueClass, PrimitiveCodec<E> elemCodec) {
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

		class ArrayObjectCodec<E> extends ArrayPrimitiveCodec<E, E[]> {
			@SuppressWarnings("unchecked")
			public ArrayObjectCodec(PrimitiveCodec<E> elemCodec) {
				super((Class<E[]>) Array.newInstance(elemCodec.getValueClass(), 0).getClass(),
					elemCodec);
			}
		}

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

		PrimitiveCodec<Boolean> BOOL = new SimplePrimitiveCodec<>(Boolean.class,
			buf -> buf.get() != 0, (buf, b) -> buf.put((byte) (b ? 1 : 0)));
		PrimitiveCodec<Byte> BYTE =
			new SimplePrimitiveCodec<>(Byte.class, ByteBuffer::get, ByteBuffer::put);
		PrimitiveCodec<Character> CHAR =
			new SimplePrimitiveCodec<>(Character.class, ByteBuffer::getChar, ByteBuffer::putChar);
		PrimitiveCodec<Short> SHORT =
			new SimplePrimitiveCodec<>(Short.class, ByteBuffer::getShort, ByteBuffer::putShort);
		PrimitiveCodec<Integer> INT =
			new SimplePrimitiveCodec<>(Integer.class, ByteBuffer::getInt, ByteBuffer::putInt);
		PrimitiveCodec<Long> LONG =
			new SimplePrimitiveCodec<>(Long.class, ByteBuffer::getLong, ByteBuffer::putLong);
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
		PrimitiveCodec<boolean[]> BOOL_ARR = new ArrayPrimitiveCodec<>(boolean[].class, BOOL);
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
		PrimitiveCodec<char[]> CHAR_ARR = new ArrayPrimitiveCodec<>(char[].class, CHAR);
		PrimitiveCodec<short[]> SHORT_ARR = new ArrayPrimitiveCodec<>(short[].class, SHORT);
		PrimitiveCodec<int[]> INT_ARR = new ArrayPrimitiveCodec<>(int[].class, INT);
		PrimitiveCodec<long[]> LONG_ARR = new ArrayPrimitiveCodec<>(long[].class, LONG);
		PrimitiveCodec<String[]> STRING_ARR =
			new ArrayObjectCodec<>(new LengthBoundCodec<>(STRING));

		Map<Byte, PrimitiveCodec<?>> CODECS_BY_SELECTOR = Stream
				.of(BOOL, BYTE, CHAR, SHORT, INT, LONG, STRING, BOOL_ARR, BYTE_ARR, CHAR_ARR,
					SHORT_ARR, INT_ARR, LONG_ARR, STRING_ARR)
				.collect(Collectors.toMap(c -> c.getSelector(), c -> c));
		Map<Class<?>, PrimitiveCodec<?>> CODECS_BY_CLASS = CODECS_BY_SELECTOR.values()
				.stream()
				.collect(Collectors.toMap(c -> c.getValueClass(), c -> c));

		static <T> PrimitiveCodec<T> getCodec(Class<T> cls) {
			@SuppressWarnings("unchecked")
			PrimitiveCodec<T> obj = (PrimitiveCodec<T>) CODECS_BY_CLASS.get(cls);
			if (obj == null) {
				throw new IllegalArgumentException("No variant codec for class " + cls);
			}
			return obj;
		}

		static PrimitiveCodec<?> getCodec(byte sel) {
			PrimitiveCodec<?> obj = CODECS_BY_SELECTOR.get(sel);
			if (obj == null) {
				throw new IllegalArgumentException("No variant codec with selector " + sel);
			}
			return obj;
		}
	}

	public static abstract class AbstractVariantDBFieldCodec<OT extends DBAnnotatedObject>
			extends AbstractDBFieldCodec<Object, OT, BinaryField> {
		public AbstractVariantDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(Object.class, objectType, BinaryField.class, field, column);
		}

		protected abstract PrimitiveCodec<?> getPrimitiveCodec(Class<?> cls);

		protected abstract PrimitiveCodec<?> getPrimitiveCodec(OT obj, byte sel);

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

	public static class VariantDBFieldCodec<OT extends DBAnnotatedObject>
			extends AbstractVariantDBFieldCodec<OT> {
		public VariantDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(objectType, field, column);
		}

		@Override
		protected PrimitiveCodec<?> getPrimitiveCodec(Class<?> cls) {
			return PrimitiveCodec.getCodec(cls);
		}

		@Override
		protected PrimitiveCodec<?> getPrimitiveCodec(OT obj, byte sel) {
			return PrimitiveCodec.getCodec(sel);
		}
	}

	private static class TableInfo<OT extends DBAnnotatedObject> {
		public final Schema schema;
		public final int[] indexColumns;
		public final ArrayList<DBFieldCodec<?, OT, ?>> codecs;

		TableInfo(Class<OT> objectType, int schemaVersion, Map<String, Field> fieldsByColumnName,
				Collection<Field> indexFields) {
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
				builder.field(ent.getKey(), codec.getFieldType());
			}
			schema = builder.build();

			indexColumns = new int[indexCols.size()];
			for (int i = 0; i < indexColumns.length; i++) {
				indexColumns[i] = indexCols.get(i);
			}
		}

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

		void writeColumnNumbers(Class<? extends DBAnnotatedObject> objectType) {
			Map<String, Integer> numbersByName = new HashMap<>();
			String[] names = schema.getFieldNames();
			for (int i = 0; i < names.length; i++) {
				numbersByName.put(names[i], i);
			}
			writeColumnNumbers(objectType, numbersByName);
		}
	}

	private static final Map<Class<? extends DBAnnotatedObject>, TableInfo<?>> INFO_MAP =
		new HashMap<>();

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

	@SuppressWarnings("unchecked")
	public static <T extends DBAnnotatedObject> TableInfo<T> getInfo(Class<T> cls) {
		synchronized (INFO_MAP) {
			return (TableInfo<T>) INFO_MAP.computeIfAbsent(cls,
				DBCachedObjectStoreFactory::buildInfo);
		}
	}

	static <OT extends DBAnnotatedObject> List<DBFieldCodec<?, OT, ?>> getCodecs(
			Class<OT> objectType) {
		return getInfo(objectType).codecs;
	}

	private static <OT extends DBAnnotatedObject> TableInfo<OT> buildInfo(Class<OT> objectType) {
		DBAnnotatedObjectInfo info = objectType.getAnnotation(DBAnnotatedObjectInfo.class);
		if (info == null) {
			throw new IllegalArgumentException(
				DBAnnotatedObject.class.getSimpleName() + " " + objectType.getName() +
					" must have @" + DBAnnotatedObjectInfo.class.getSimpleName() + " annotation");
		}

		Map<String, Field> fields = new LinkedHashMap<>();
		List<Field> indexFields = new ArrayList<>();
		collectFields(objectType, fields, indexFields);

		TableInfo<OT> tableInfo = new TableInfo<>(objectType, info.version(), fields, indexFields);
		tableInfo.writeColumnNumbers(objectType);

		return tableInfo;
	}

	private static void collectFields(Class<?> cls, Map<String, Field> fields,
			List<Field> indexFields) {
		Class<?> superclass = cls.getSuperclass();
		if (superclass != null) {
			collectFields(superclass, fields, indexFields);
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
		}
	}

	private final DBHandle handle;
	private final DBCachedDomainObjectAdapter adapter;

	public DBCachedObjectStoreFactory(DBCachedDomainObjectAdapter adapter) {
		this.handle = adapter.getDBHandle();
		this.adapter = adapter;
	}

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

	public <T extends DBAnnotatedObject> DBCachedObjectStore<T> getOrCreateCachedStore(
			String tableName, Class<T> cls, DBAnnotatedObjectFactory<T> factory, boolean upgradable)
			throws VersionException, IOException {
		Table table = getOrCreateTable(tableName, cls, upgradable);
		return new DBCachedObjectStore<>(adapter, cls, factory, table);
	}
}
