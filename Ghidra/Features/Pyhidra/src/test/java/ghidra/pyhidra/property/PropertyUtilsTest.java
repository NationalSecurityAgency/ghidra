package ghidra.pyhidra.property;

import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import static org.junit.Assert.assertArrayEquals;

@RunWith(Parameterized.class)
public class PropertyUtilsTest {

	@Parameters(name = "{0}")
	public static List<Object[]> data() {
		return convertData(PropertyUtilsTest.class.getNestMembers());
	}

	private final Class<?> cls;

	public PropertyUtilsTest(String name, Class<?> cls) {
		this.cls = cls;
	}

	private TestResult[] getExpected() {
		return Arrays.stream(cls.getAnnotationsByType(ExpectedResult.class))
				.map(TestResult::new)
				.toArray(TestResult[]::new);
	}

	@Test
	public void test() {
		TestResult[] expected = getExpected();
		TestResult[] properties = getProperties(cls);
		assertArrayEquals(expected, properties);
	}

	private static TestResult[] getProperties(Class<?> cls) {
		return Arrays.stream(PropertyUtils.getProperties(cls))
				.map(AbstractJavaProperty.class::cast)
				.map(TestResult::new)
				.toArray(TestResult[]::new);
	}

	private static List<Object[]> convertData(Class<?>[] classes) {
		List<Object[]> result = new ArrayList<>(classes.length);
		for (Class<?> cls : classes) {
			if (cls.isRecord() || cls.isAnnotation()) {
				continue;
			}
			result.add(new Object[] { cls.getSimpleName(), cls });
		}
		return result;
	}

	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.TYPE)
	@Repeatable(ExpectedResults.class)
	private static @interface ExpectedResult {
		String field();

		boolean getter();

		boolean setter();
	}

	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.TYPE)
	private static @interface ExpectedResults {
		ExpectedResult[] value();
	}

	private static record TestResult(String field, boolean getter, boolean setter) {
		TestResult(AbstractJavaProperty<?> property) {
			this(property.field, property.hasGetter(), property.hasValidSetter());
		}

		TestResult(ExpectedResult result) {
			this(result.field(), result.getter(), result.setter());
		}
	}

	@ExpectedResult(field = "length", getter = true, setter = false)
	public static class TestGetter {
		public int getLength() {
			return 0;
		}
	}

	@ExpectedResult(field = "length", getter = false, setter = true)
	public static class TestSetter {
		public void setLength(int i) {
		}
	}

	@ExpectedResult(field = "length", getter = true, setter = true)
	public static class TestProperty {
		public int getLength() {
			return 0;
		}

		public void setLength(int i) {
		}
	}

	@ExpectedResult(field = "length", getter = true, setter = true)
	public static class TestMultiSetter {
		public int getLength() {
			return 0;
		}

		public void setLength(int i) {
		}

		public void setLength(short s) {
		}
	}

	@ExpectedResult(field = "length", getter = true, setter = true)
	public static class TestBoxedMultiSetter {
		public int getLength() {
			return 0;
		}

		public void setLength(int i) {
		}

		public void setLength(Integer i) {
		}
	}

	public static class TestMultiSetterNoGetter {
		public void setLength(int i) {
		}

		public void setLength(short s) {
		}
	}

	@ExpectedResult(field = "valid", getter = true, setter = false)
	public static class TestIsGetter {
		public boolean isValid() {
			return true;
		}
	}

	@ExpectedResult(field = "valid", getter = true, setter = true)
	public static class TestIsProperty {
		public boolean isValid() {
			return true;
		}

		public void setValid(boolean valid) {
		}
	}

	@ExpectedResult(field = "valid", getter = true, setter = false)
	public static class TestIsBoxedGetter {
		public Boolean isValid() {
			return true;
		}
	}

	@ExpectedResult(field = "valid", getter = true, setter = true)
	public static class TestIsBoxedProperty {
		public Boolean isValid() {
			return true;
		}

		public void setValid(boolean valid) {
		}
	}

	public static class TestBadIsGetter {
		public int isValid() {
			return 1;
		}
	}

	public static class TestIsGetterName {
		public boolean isvalid() {
			return true;
		}
	}

	public static class TestBadGetterName {
		public int getlength() {
			return 0;
		}
	}

	public static class TestBadSetterName {
		public void setlength(int i) {
		}
	}

	public static class TestBadIsTooShortName {
		public boolean i() {
			return true;
		}
	}

	public static class TestBadGetTooShortName {
		public int ge() {
			return 0;
		}
	}

	public static class TestBadSetTooShortName {
		public int se() {
			return 0;
		}
	}

	public static class TestBadIsNoName {
		public boolean is() {
			return true;
		}
	}

	public static class TestBadGetNoName {
		public int get() {
			return 0;
		}
	}

	public static class TestBadSetNoName {
		public int set() {
			return 0;
		}
	}
}
