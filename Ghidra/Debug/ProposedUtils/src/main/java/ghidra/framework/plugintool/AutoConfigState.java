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
package ghidra.framework.plugintool;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles.Lookup;
import java.lang.reflect.*;
import java.util.*;

import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.annotation.AutoConfigStateField;
import ghidra.framework.plugintool.annotation.AutoConfigStateField.DefaultConfigFieldCodec;

public interface AutoConfigState {
	interface ConfigFieldCodec<T> {
		T read(SaveState state, String name, T current);

		void write(SaveState state, String name, T value);
	}

	static class BooleanConfigFieldCodec implements ConfigFieldCodec<Boolean> {
		public static final BooleanConfigFieldCodec INSTANCE = new BooleanConfigFieldCodec();

		@Override
		public Boolean read(SaveState state, String name, Boolean current) {
			return state.getBoolean(name, false);
		}

		@Override
		public void write(SaveState state, String name, Boolean value) {
			state.putBoolean(name, value);
		}
	}

	static class ByteConfigFieldCodec implements ConfigFieldCodec<Byte> {
		public static final ByteConfigFieldCodec INSTANCE = new ByteConfigFieldCodec();

		@Override
		public Byte read(SaveState state, String name, Byte current) {
			return state.getByte(name, (byte) 0);
		}

		@Override
		public void write(SaveState state, String name, Byte value) {
			state.putByte(name, value);
		}
	}

	static class ShortConfigFieldCodec implements ConfigFieldCodec<Short> {
		public static final ShortConfigFieldCodec INSTANCE = new ShortConfigFieldCodec();

		@Override
		public Short read(SaveState state, String name, Short current) {
			return state.getShort(name, (short) 0);
		}

		@Override
		public void write(SaveState state, String name, Short value) {
			state.putShort(name, value);
		}
	}

	static class IntConfigFieldCodec implements ConfigFieldCodec<Integer> {
		public static final IntConfigFieldCodec INSTANCE = new IntConfigFieldCodec();

		@Override
		public Integer read(SaveState state, String name, Integer current) {
			return state.getInt(name, 0);
		}

		@Override
		public void write(SaveState state, String name, Integer value) {
			state.putInt(name, value);
		}
	}

	static class LongConfigFieldCodec implements ConfigFieldCodec<Long> {
		public static final LongConfigFieldCodec INSTANCE = new LongConfigFieldCodec();

		@Override
		public Long read(SaveState state, String name, Long current) {
			return state.getLong(name, 0);
		}

		@Override
		public void write(SaveState state, String name, Long value) {
			state.putLong(name, value);
		}
	}

	static class FloatConfigFieldCodec implements ConfigFieldCodec<Float> {
		public static final FloatConfigFieldCodec INSTANCE = new FloatConfigFieldCodec();

		@Override
		public Float read(SaveState state, String name, Float current) {
			return state.getFloat(name, 0);
		}

		@Override
		public void write(SaveState state, String name, Float value) {
			state.putFloat(name, value);
		}
	}

	static class DoubleConfigFieldCodec implements ConfigFieldCodec<Double> {
		public static final DoubleConfigFieldCodec INSTANCE = new DoubleConfigFieldCodec();

		@Override
		public Double read(SaveState state, String name, Double current) {
			return state.getDouble(name, 0);
		}

		@Override
		public void write(SaveState state, String name, Double value) {
			state.putDouble(name, value);
		}
	}

	static class StringConfigFieldCodec implements ConfigFieldCodec<String> {
		public static final StringConfigFieldCodec INSTANCE = new StringConfigFieldCodec();

		@Override
		public String read(SaveState state, String name, String current) {
			return state.getString(name, null);
		}

		@Override
		public void write(SaveState state, String name, String value) {
			state.putString(name, value);
		}
	}

	static class BooleanArrayConfigFieldCodec implements ConfigFieldCodec<boolean[]> {
		public static final BooleanArrayConfigFieldCodec INSTANCE =
			new BooleanArrayConfigFieldCodec();

		@Override
		public boolean[] read(SaveState state, String name, boolean[] current) {
			return state.getBooleans(name, null);
		}

		@Override
		public void write(SaveState state, String name, boolean[] value) {
			state.putBooleans(name, value);
		}
	}

	static class ByteArrayConfigFieldCodec implements ConfigFieldCodec<byte[]> {
		public static final ByteArrayConfigFieldCodec INSTANCE = new ByteArrayConfigFieldCodec();

		@Override
		public byte[] read(SaveState state, String name, byte[] current) {
			return state.getBytes(name, null);
		}

		@Override
		public void write(SaveState state, String name, byte[] value) {
			state.putBytes(name, value);
		}
	}

	static class ShortArrayConfigFieldCodec implements ConfigFieldCodec<short[]> {
		public static final ShortArrayConfigFieldCodec INSTANCE = new ShortArrayConfigFieldCodec();

		@Override
		public short[] read(SaveState state, String name, short[] current) {
			return state.getShorts(name, null);
		}

		@Override
		public void write(SaveState state, String name, short[] value) {
			state.putShorts(name, value);
		}
	}

	static class IntArrayConfigFieldCodec implements ConfigFieldCodec<int[]> {
		public static final IntArrayConfigFieldCodec INSTANCE = new IntArrayConfigFieldCodec();

		@Override
		public int[] read(SaveState state, String name, int[] current) {
			return state.getInts(name, null);
		}

		@Override
		public void write(SaveState state, String name, int[] value) {
			state.putInts(name, value);
		}
	}

	static class LongArrayConfigFieldCodec implements ConfigFieldCodec<long[]> {
		public static final LongArrayConfigFieldCodec INSTANCE = new LongArrayConfigFieldCodec();

		@Override
		public long[] read(SaveState state, String name, long[] current) {
			return state.getLongs(name, null);
		}

		@Override
		public void write(SaveState state, String name, long[] value) {
			state.putLongs(name, value);
		}
	}

	static class FloatArrayConfigFieldCodec implements ConfigFieldCodec<float[]> {
		public static final FloatArrayConfigFieldCodec INSTANCE = new FloatArrayConfigFieldCodec();

		@Override
		public float[] read(SaveState state, String name, float[] current) {
			return state.getFloats(name, null);
		}

		@Override
		public void write(SaveState state, String name, float[] value) {
			state.putFloats(name, value);
		}
	}

	static class DoubleArrayConfigFieldCodec implements ConfigFieldCodec<double[]> {
		public static final DoubleArrayConfigFieldCodec INSTANCE =
			new DoubleArrayConfigFieldCodec();

		@Override
		public double[] read(SaveState state, String name, double[] current) {
			return state.getDoubles(name, null);
		}

		@Override
		public void write(SaveState state, String name, double[] value) {
			state.putDoubles(name, value);
		}
	}

	static class StringArrayConfigFieldCodec implements ConfigFieldCodec<String[]> {
		public static final StringArrayConfigFieldCodec INSTANCE =
			new StringArrayConfigFieldCodec();

		@Override
		public String[] read(SaveState state, String name, String[] current) {
			return state.getStrings(name, null);
		}

		@Override
		public void write(SaveState state, String name, String[] value) {
			state.putStrings(name, value);
		}
	}

	static class EnumConfigFieldCodec implements ConfigFieldCodec<Enum<?>> {
		public static final EnumConfigFieldCodec INSTANCE = new EnumConfigFieldCodec();

		@Override
		public Enum<?> read(SaveState state, String name, Enum<?> current) {
			return state.getEnum(name, null);
		}

		@Override
		public void write(SaveState state, String name, Enum<?> value) {
			state.putEnum(name, value);
		}
	}

	class ConfigStateField<T> {
		private static final Map<Class<?>, ConfigFieldCodec<?>> CODECS_BY_TYPE = new HashMap<>();
		private static final Map<Class<?>, ConfigFieldCodec<?>> CODECS_BY_SPEC = new HashMap<>();

		static {
			addCodec(boolean.class, BooleanConfigFieldCodec.INSTANCE);
			addCodec(Boolean.class, BooleanConfigFieldCodec.INSTANCE);
			addCodec(byte.class, ByteConfigFieldCodec.INSTANCE);
			addCodec(Byte.class, ByteConfigFieldCodec.INSTANCE);
			addCodec(short.class, ShortConfigFieldCodec.INSTANCE);
			addCodec(Short.class, ShortConfigFieldCodec.INSTANCE);
			addCodec(int.class, IntConfigFieldCodec.INSTANCE);
			addCodec(Integer.class, IntConfigFieldCodec.INSTANCE);
			addCodec(long.class, LongConfigFieldCodec.INSTANCE);
			addCodec(Long.class, LongConfigFieldCodec.INSTANCE);
			addCodec(float.class, FloatConfigFieldCodec.INSTANCE);
			addCodec(Float.class, FloatConfigFieldCodec.INSTANCE);
			addCodec(double.class, DoubleConfigFieldCodec.INSTANCE);
			addCodec(Double.class, DoubleConfigFieldCodec.INSTANCE);
			addCodec(String.class, StringConfigFieldCodec.INSTANCE);

			addCodec(boolean[].class, BooleanArrayConfigFieldCodec.INSTANCE);
			addCodec(byte[].class, ByteArrayConfigFieldCodec.INSTANCE);
			addCodec(short[].class, ShortArrayConfigFieldCodec.INSTANCE);
			addCodec(int[].class, IntArrayConfigFieldCodec.INSTANCE);
			addCodec(long[].class, LongArrayConfigFieldCodec.INSTANCE);
			addCodec(float[].class, FloatArrayConfigFieldCodec.INSTANCE);
			addCodec(double[].class, DoubleArrayConfigFieldCodec.INSTANCE);
			addCodec(String[].class, StringArrayConfigFieldCodec.INSTANCE);
		}

		private static <T> void addCodec(Class<T> cls, ConfigFieldCodec<T> codec) {
			CODECS_BY_TYPE.put(cls, codec);
		}

		@SuppressWarnings({ "unchecked", "rawtypes" })
		public static <T> ConfigFieldCodec<T> getCodecByType(Class<T> cls) {
			if (Enum.class.isAssignableFrom(cls)) {
				return (ConfigFieldCodec) EnumConfigFieldCodec.INSTANCE;
			}
			return (ConfigFieldCodec) CODECS_BY_TYPE.get(cls);
		}

		private static <T extends ConfigFieldCodec<?>> T getCodecBySpec(Class<T> cls) {
			synchronized (CODECS_BY_SPEC) {
				@SuppressWarnings("unchecked")
				T codec = (T) CODECS_BY_SPEC.get(cls);
				if (codec != null) {
					return codec;
				}
				try {
					Constructor<T> constructor = cls.getConstructor();
					codec = constructor.newInstance();
					CODECS_BY_SPEC.put(cls, codec);
					return codec;
				}
				catch (NoSuchMethodException | InstantiationException | IllegalAccessException
						| IllegalArgumentException | InvocationTargetException e) {
					throw new AssertionError(
						"Illegal codec specification. Constructor() cannot be invoked: " + cls, e);
				}
			}
		}

		/**
		 * Put an object into a {@link SaveState} using a known codec
		 * 
		 * <p>
		 * This seems like something that should be in SaveState itself, but the object value must
		 * be one of the supported types.
		 * 
		 * @param <T> the type of the value
		 * @param state the state to write into
		 * @param type the type of the value
		 * @param name the name of the name-value pair
		 * @param value the value of the name-value pair
		 */
		public static <T> void putState(SaveState state, Class<T> type, String name, T value) {
			ConfigFieldCodec<T> codec = getCodecByType(type);
			if (codec == null) {
				throw new IllegalArgumentException("No codec for type " + type);
			}
			codec.write(state, name, value);
		}

		/**
		 * Get an object from a {@link SaveState} using a known codec
		 * 
		 * <p>
		 * This seems like something that should be in SaveState itself.
		 * 
		 * @param <T> the type of the value
		 * @param state the state to read from
		 * @param type the expected type of the value
		 * @param name the name of the name-value pair
		 * @return the value of the name-value pair
		 */
		public static <T> T getState(SaveState state, Class<T> type, String name) {
			ConfigFieldCodec<T> codec = getCodecByType(type);
			if (codec == null) {
				throw new IllegalArgumentException("No codec for type " + type);
			}
			return codec.read(state, name, null);
		}

		private final MethodHandle getter;
		private final MethodHandle setter;

		private final ConfigFieldCodec<T> codec;
		private final String name;

		@SuppressWarnings("unchecked")
		private ConfigStateField(AutoConfigStateField annot, Field f, Class<T> type, Lookup lookup)
				throws IllegalAccessException {
			getter = lookup.unreflectGetter(f);
			setter = Modifier.isFinal(f.getModifiers()) ? null : lookup.unreflectSetter(f);
			name = f.getName();

			@SuppressWarnings("rawtypes")
			Class<? extends ConfigFieldCodec> codecCls = annot.codec();
			if (codecCls == DefaultConfigFieldCodec.class) {
				codec = getCodecByType(type);
			}
			else {
				// TODO: Type check here, or in an annotation processor
				codec = getCodecBySpec(codecCls);
			}
			if (codec == null) {
				throw new AssertionError(AutoConfigStateField.class.getSimpleName() +
					": Specify a codec for " + f + ".");
			}
		}

		private void save(Object from, SaveState into) {
			T val;
			try {
				val = (T) getter.invoke(from);
			}
			catch (Throwable e) {
				throw new AssertionError(e);
			}
			assert val != null;
			codec.write(into, name, val);
		}

		private void load(Object into, SaveState from) {
			if (!from.hasValue(name)) {
				return; // leave the intial value as "default"
			}
			try {
				T current = (T) getter.invoke(into);
				T val = codec.read(from, name, current);
				if (val == null || val == current) {
					return;
				}
				if (setter == null) {
					throw new IllegalAccessException("Codec cannot modify final field: " + name);
				}
				setter.invoke(into, val);
			}
			catch (Throwable e) {
				throw new AssertionError(e);
			}
		}
	}

	class ClassHandler<T> {
		private final Set<ConfigStateField<?>> fields = new LinkedHashSet<>();

		ClassHandler(Class<T> cls, Lookup lookup) throws IllegalAccessException {
			gatherAnnotatedFields(cls, lookup);
		}

		private void gatherAnnotatedFields(Class<?> cls, Lookup lookup)
				throws IllegalAccessException {
			for (Field f : cls.getDeclaredFields()) {
				AutoConfigStateField annot = f.getAnnotation(AutoConfigStateField.class);
				if (annot == null) {
					continue;
				}
				fields.add(new ConfigStateField<>(annot, f, f.getType(), lookup));
			}
		}

		public void writeConfigState(T from, SaveState into) {
			for (ConfigStateField<?> f : fields) {
				f.save(from, into);
			}
		}

		public void readConfigState(T into, SaveState from) {
			for (ConfigStateField<?> f : fields) {
				f.load(into, from);
			}
		}
	}

	/**
	 * Wire up a handler for the given class, using the given lookup
	 * 
	 * <p>
	 * This does not consider super classes, since the writeConfigState of a class using this and
	 * the applicable annotations should likely call super.writeConfigState to allow the super class
	 * to handle its fields, whether or not it also uses the annotations.
	 * 
	 * @param <T> the type of the class whose fields are annotated by {@link AutoConfigStateField}
	 * @param cls the class whose fields are annotated
	 * @param lookup a lookup from within the class, granting access to the annotated fields
	 * @return the handler
	 */
	static <T> ClassHandler<T> wireHandler(Class<T> cls, Lookup lookup) {
		try {
			return new ClassHandler<>(cls, lookup);
		}
		catch (IllegalAccessException e) {
			throw new AssertionError(e);
		}
	}
}
