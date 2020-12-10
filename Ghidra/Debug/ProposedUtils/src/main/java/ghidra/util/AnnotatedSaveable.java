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
package ghidra.util;

import java.lang.annotation.*;
import java.lang.reflect.Field;
import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.Function;

import com.google.common.collect.ImmutableMap;

@Deprecated
public abstract class AnnotatedSaveable implements Saveable {
	protected static ImmutableMap.Builder<Class<?>, FieldAccessorFactory> accessorFactoriesBuilder =
		ImmutableMap.builder();
	protected static Map<Class<?>, FieldAccessorFactory> accessorFactories =
		accessorFactoriesBuilder //
			.put(boolean.class, BoolFieldAccessor::new) //
			.put(Boolean.class, BoolFieldAccessor::new) //
			.put(byte.class, ByteFieldAccessor::new) //
			.put(Byte.class, ByteFieldAccessor::new) //
			.put(byte[].class, ByteArrayFieldAccessor::new) //
			.put(double.class, DoubleFieldAccessor::new) //
			.put(Double.class, DoubleFieldAccessor::new) //
			.put(double[].class, DoubleArrayFieldAccessor::new) //
			.put(float.class, FloatFieldAccessor::new) //
			.put(Float.class, FloatFieldAccessor::new) //
			.put(float[].class, FloatArrayFieldAccessor::new) //
			.put(int.class, IntFieldAccessor::new) //
			.put(Integer.class, IntFieldAccessor::new) //
			.put(int[].class, IntArrayFieldAccessor::new) //
			.put(long.class, LongFieldAccessor::new) //
			.put(Long.class, LongFieldAccessor::new) //
			.put(long[].class, LongArrayFieldAccessor::new) //
			.put(short.class, ShortFieldAccessor::new) //
			.put(Short.class, ShortFieldAccessor::new) //
			.put(short[].class, ShortArrayFieldAccessor::new) //
			.put(String.class, StringFieldAccessor::new) //
			.put(String[].class, StringArrayFieldAccessor::new) //
			.build();

	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.FIELD)
	public static @interface SaveableField {
	}

	public static interface FieldAccessor {
		void save(AnnotatedSaveable saveable, ObjectStorage objStorage);

		void restore(AnnotatedSaveable saveable, ObjectStorage objStorage);
	}

	public static abstract class AbstractFieldAccessor<T> implements FieldAccessor {
		protected final Field field;
		protected final Function<ObjectStorage, T> objGetter;
		protected final BiConsumer<ObjectStorage, T> objPutter;

		public AbstractFieldAccessor(Field field, Function<ObjectStorage, T> objGetter,
				BiConsumer<ObjectStorage, T> objPutter) {
			this.field = field;
			this.objGetter = objGetter;
			this.objPutter = objPutter;
		}

		@SuppressWarnings("unchecked")
		@Override
		public void save(AnnotatedSaveable saveable, ObjectStorage objStorage) {
			try {
				objPutter.accept(objStorage, (T) field.get(saveable));
			}
			catch (Exception e) {
				throw new AssertionError(e);
			}
		}

		@Override
		public void restore(AnnotatedSaveable saveable, ObjectStorage objStorage) {
			try {
				field.set(saveable, objGetter.apply(objStorage));
			}
			catch (Exception e) {
				throw new AssertionError(e);
			}
		}
	}

	public static class BoolFieldAccessor extends AbstractFieldAccessor<Boolean> {
		public BoolFieldAccessor(Field field) {
			super(field, ObjectStorage::getBoolean, ObjectStorage::putBoolean);
		}
	}

	public static class ByteFieldAccessor extends AbstractFieldAccessor<Byte> {
		public ByteFieldAccessor(Field field) {
			super(field, ObjectStorage::getByte, ObjectStorage::putByte);
		}
	}

	public static class ByteArrayFieldAccessor extends AbstractFieldAccessor<byte[]> {
		public ByteArrayFieldAccessor(Field field) {
			super(field, ObjectStorage::getBytes, ObjectStorage::putBytes);
		}
	}

	public static class DoubleFieldAccessor extends AbstractFieldAccessor<Double> {
		public DoubleFieldAccessor(Field field) {
			super(field, ObjectStorage::getDouble, ObjectStorage::putDouble);
		}
	}

	public static class DoubleArrayFieldAccessor extends AbstractFieldAccessor<double[]> {
		public DoubleArrayFieldAccessor(Field field) {
			super(field, ObjectStorage::getDoubles, ObjectStorage::putDoubles);
		}
	}

	public static class FloatFieldAccessor extends AbstractFieldAccessor<Float> {
		public FloatFieldAccessor(Field field) {
			super(field, ObjectStorage::getFloat, ObjectStorage::putFloat);
		}
	}

	public static class FloatArrayFieldAccessor extends AbstractFieldAccessor<float[]> {
		public FloatArrayFieldAccessor(Field field) {
			super(field, ObjectStorage::getFloats, ObjectStorage::putFloats);
		}
	}

	public static class IntFieldAccessor extends AbstractFieldAccessor<Integer> {
		public IntFieldAccessor(Field field) {
			super(field, ObjectStorage::getInt, ObjectStorage::putInt);
		}
	}

	public static class IntArrayFieldAccessor extends AbstractFieldAccessor<int[]> {
		public IntArrayFieldAccessor(Field field) {
			super(field, ObjectStorage::getInts, ObjectStorage::putInts);
		}
	}

	public static class LongFieldAccessor extends AbstractFieldAccessor<Long> {
		public LongFieldAccessor(Field field) {
			super(field, ObjectStorage::getLong, ObjectStorage::putLong);
		}
	}

	public static class LongArrayFieldAccessor extends AbstractFieldAccessor<long[]> {
		public LongArrayFieldAccessor(Field field) {
			super(field, ObjectStorage::getLongs, ObjectStorage::putLongs);
		}
	}

	public static class ShortFieldAccessor extends AbstractFieldAccessor<Short> {
		public ShortFieldAccessor(Field field) {
			super(field, ObjectStorage::getShort, ObjectStorage::putShort);
		}
	}

	public static class ShortArrayFieldAccessor extends AbstractFieldAccessor<short[]> {
		public ShortArrayFieldAccessor(Field field) {
			super(field, ObjectStorage::getShorts, ObjectStorage::putShorts);
		}
	}

	public static class StringFieldAccessor extends AbstractFieldAccessor<String> {
		public StringFieldAccessor(Field field) {
			super(field, ObjectStorage::getString, ObjectStorage::putString);
		}
	}

	public static class StringArrayFieldAccessor extends AbstractFieldAccessor<String[]> {
		public StringArrayFieldAccessor(Field field) {
			super(field, ObjectStorage::getStrings, ObjectStorage::putStrings);
		}
	}

	public static interface FieldAccessorFactory extends Function<Field, FieldAccessor> {
	}

	public static class AnnotatedSaveableException extends AssertionError {
		public AnnotatedSaveableException(String message) {
			super(message);
		}
	}

	protected final FieldAccessor[] fields;
	protected final Class<?>[] fieldClasses;

	public AnnotatedSaveable() {
		List<Field> fields = new ArrayList<>();
		collectAnnotatedFields(fields, this.getClass());
		fields.sort((f1, f2) -> {
			int result;
			result = f1.getClass().getName().compareTo(f2.getClass().getName());
			if (result != 0) {
				return result;
			}
			result = f1.getName().compareTo(f2.getName());
			if (result != 0) {
				return result;
			}
			return 0;
		});
		this.fields = new FieldAccessor[fields.size()];
		this.fieldClasses = new Class<?>[fields.size()];
		for (int i = 0; i < fields.size(); i++) {
			Field f = fields.get(i);
			FieldAccessorFactory factory = accessorFactories.get(f.getType());
			if (factory == null) {
				throw new AnnotatedSaveableException("Cannot type for field " + f);
			}
			this.fields[i] = factory.apply(f);
			this.fieldClasses[i] = f.getType();
		}
	}

	@SuppressWarnings("unchecked")
	static void collectAnnotatedFields(List<Field> fields, Class<? extends AnnotatedSaveable> cls) {
		if (cls.equals(AnnotatedSaveable.class)) {
			return;
		}
		collectAnnotatedFields(fields, (Class<? extends AnnotatedSaveable>) cls.getSuperclass());
		for (Field f : cls.getDeclaredFields()) {
			SaveableField annot = f.getAnnotation(SaveableField.class);
			if (annot == null) {
				continue;
			}
			f.setAccessible(true);
			fields.add(f);
		}
	}

	@Override
	public Class<?>[] getObjectStorageFields() {
		return fieldClasses;
	}

	@Override
	public void save(ObjectStorage objStorage) {
		for (FieldAccessor fa : fields) {
			fa.save(this, objStorage);
		}
	}

	@Override
	public void restore(ObjectStorage objStorage) {
		for (FieldAccessor fa : fields) {
			fa.restore(this, objStorage);
		}
	}

	@Override
	public boolean isUpgradeable(int oldSchemaVersion) {
		return false;
	}

	@Override
	public boolean upgrade(ObjectStorage oldObjStorage, int oldSchemaVersion,
			ObjectStorage currentObjStorage) {
		return false;
	}

	@Override
	public boolean isPrivate() {
		return false;
	}
}
