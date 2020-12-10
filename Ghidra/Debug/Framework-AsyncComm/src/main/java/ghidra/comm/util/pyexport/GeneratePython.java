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
package ghidra.comm.util.pyexport;

import java.io.File;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.*;
import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.lang3.ClassUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.reflect.TypeUtils;

import com.google.common.primitives.Primitives;
import com.google.common.reflect.ClassPath;
import com.google.common.reflect.ClassPath.ClassInfo;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.annot.TypedByField;
import ghidra.comm.packet.binary.BinaryPacketCodec;
import ghidra.comm.packet.fields.PacketField;
import ghidra.graph.algo.SorterException;
import ghidra.util.Msg;

/**
 * A command-line utility to export a set of packet specification to Python
 * 
 * The exported classes are generally usable out-of-the-box, but there are some caveats:
 * 
 * <ol>
 * <li>The names of nested classes are slightly mangled, since nested classes in Python have a
 * subtly different meaning than those in Java. The packet class my.pkg.A.B in java will be exported
 * as my.pkg.A_B in Python.</li>
 * <li>The exported classes must be used with the provided {@code ghidra.comm.packet} and
 * {@code java} Python packages.</li>
 * <li>Any custom annotations must be ported manually to Python.</li>
 * <li>Any custom field types must be ported manually to Python.</li>
 * <li>Currently, only {@link BinaryPacketCodec} is ported to Python.</li>
 * <li>Some common Java types may not have placeholders implemented. If more are needed, it may be
 * necessary to submit a feature request or monkey patch them in.</li>
 * </ol>
 */
public class GeneratePython {
	/**
	 * Execute the utility:
	 * 
	 * <pre>
	 * java -cp ... GeneratePython [PACKAGE] [OUTPUT_DIR]
	 * </pre>
	 * 
	 * This exports all packets found in the package {@code [PACKAGE]} and all of its subpackages
	 * into a Python package at {@code [OUTPUT_DIR]}.
	 * 
	 * @param args
	 */
	public static void main(String[] args) {
		System.exit(new GeneratePython().run(args));
	}

	private PythonPackage rootPkg = new PythonPackage(this, "", null);

	private void exportClass(Class<?> cls)
			throws IllegalAccessException, IllegalArgumentException, InvocationTargetException,
			NoSuchFieldException, SecurityException, NoSuchMethodException {
		exportClass(cls, new HashSet<>());
	}

	@SuppressWarnings("unchecked")
	private void exportClass(Class<?> cls, Set<Class<?>> visited)
			throws IllegalAccessException, IllegalArgumentException, InvocationTargetException,
			NoSuchFieldException, SecurityException, NoSuchMethodException {
		if (!visited.add(cls)) {
			return;
		}
		if (Packet.class.isAssignableFrom(cls)) {
			exportPacketClass((Class<? extends Packet>) cls);
		}
		else if (cls.isEnum()) {
			exportEnumClass((Class<? extends Enum<?>>) cls);
		}
		for (Class<?> scls : cls.getClasses()) {
			exportClass(scls, visited);
		}
	}

	private void exportEnumClass(Class<? extends Enum<?>> javaEnum)
			throws NoSuchFieldException, SecurityException, IllegalAccessException,
			IllegalArgumentException, InvocationTargetException, NoSuchMethodException {
		PythonClass pyCls = javaToPyClass(javaEnum);
		pyCls.addBase(javaToPyClass(Enum.class));
		if (!pyCls.isExported) {
			pyCls.isExported = true;
			Map<String, Method> attrs = new LinkedHashMap<>();
			attrs.put("ordinal", javaEnum.getMethod("ordinal"));
			attrs.put("name", javaEnum.getMethod("name"));
			for (Method m : javaEnum.getDeclaredMethods()) {
				if (m.getName().startsWith("get")) {
					if (m.getParameterCount() == 0) {
						attrs.put(StringUtils.uncapitalize(m.getName().substring(3)), m);
					}
				}
			}
			pyCls.addLine(
				String.format("def __init__(self, %s):", StringUtils.join(attrs.keySet(), ", ")));
			for (String a : attrs.keySet()) {
				pyCls.addLine(String.format("    self.%s = %s", a, a));
			}

			Set<String> values = new LinkedHashSet<>();
			for (Enum<?> eConst : javaEnum.getEnumConstants()) {
				values.add(String.format("%s.%s", pyCls.getPythonShortName(), eConst.name()));
				Set<String> attrAssigns = new LinkedHashSet<>();
				for (Entry<String, Method> a : attrs.entrySet()) {
					attrAssigns.add(String.format("%s=%s", a.getKey(),
						regenerateValue(pyCls, javaEnum, a.getValue().invoke(eConst))));
				}
				pyCls.addPostAssign(eConst.name(), String.format("%s(%s)",
					pyCls.getPythonShortName(), StringUtils.join(attrAssigns, ", ")));
			}
			pyCls.addPostAssign("values", regenerateValue(pyCls, javaEnum, values));
		}
	}

	private void exportPackage(String pkgName) throws IOException, IllegalAccessException,
			IllegalArgumentException, InvocationTargetException, NoSuchFieldException,
			SecurityException, NoSuchMethodException {
		rootPkg.getSubPackage(pkgName).isExported = true;
		ClassPath cp = ClassPath.from(this.getClass().getClassLoader());
		for (ClassInfo ci : cp.getTopLevelClassesRecursive(pkgName)) {
			exportClass(ci.load());
		}
	}

	private void exportPacketClass(Class<? extends Packet> pktType)
			throws IllegalAccessException, IllegalArgumentException, InvocationTargetException,
			NoSuchFieldException, SecurityException {
		final List<Field> fields;
		try {
			if (Modifier.isAbstract(pktType.getModifiers())) {
				fields = Collections.emptyList();
			}
			else {
				fields = Packet.getFields(pktType);
			}
		}
		catch (Exception e) {
			Msg.error(this, "Could not export " + pktType, e);
			return;
		}

		PythonClass pyCls = packetToPyClass(pktType);
		if (!pyCls.isExported) {
			pyCls.isExported = true;
			PythonClass pySup = javaToPyClass(pktType.getSuperclass());
			pyCls.addBase(pySup);
			for (Field f : fields) {
				pyCls.addLine();
				for (Annotation annot : f.getAnnotations()) {
					Class<? extends Annotation> atype = annot.annotationType();
					if (atype == PacketField.class) {
						continue;
					}
					pyCls.addImport(javaToPyClass(atype));
					pyCls.addLine("@" + regenerateAnnotation(pyCls, pktType, annot));
				}
				Type type = f.getGenericType();
				String pytype = regenerateType(pyCls, pktType, type);
				StringBuilder decl = new StringBuilder();
				decl.append(String.format("@field(%s", pytype));
				if (Modifier.isFinal(f.getModifiers())) {
					decl.append(
						String.format(", fixed=%s", regenerateValue(pyCls, pktType, f.get(null))));
				}
				decl.append(")");
				pyCls.addLine(decl.toString());
				pyCls.addLine(String.format("def %s(self):", avoidReserved(f.getName())));
				pyCls.addLine("    pass");
			}
		}
	}

	private String avoidReserved(String id) {
		if ("exec".equals(id)) {
			return "_exec";
		}
		return id;
	}

	private PythonClass javaToPyClass(Class<?> cls) {
		PythonPackage pkg = rootPkg.getSubPackage(ClassUtils.getPackageName(cls));
		return pkg.getClass(ClassUtils.getShortClassName(cls).replace('.', '_'));
	}

	private String regenerateAnnotation(PythonClass pyCls, Class<?> javaCls, Annotation annot)
			throws IllegalAccessException, IllegalArgumentException, InvocationTargetException,
			NoSuchFieldException, SecurityException {
		StringBuilder sb = new StringBuilder();
		Class<?> type = annot.annotationType();
		PythonClass pyType = javaToPyClass(type);
		sb.append(pyType.getFullName(false));
		sb.append("(");
		boolean first = true;
		for (Method m : type.getDeclaredMethods()) {
			Object val = m.invoke(annot);
			if (m.getDefaultValue() == null || !m.getDefaultValue().equals(val)) {
				if (!first) {
					sb.append(", ");
				}
				first = false;
				sb.append(m.getName());
				sb.append("=");
				sb.append(regenerateValue(pyCls, javaCls, val));
			}
		}
		sb.append(")");

		// TODO: I don't care much for specific cases here, but aw well
		if (type == TypedByField.class) {
			TypedByField tbf = (TypedByField) annot;
			String mapName = tbf.map();
			if (!"".equals(mapName)) {
				Map<?, ?> map = (Map<?, ?>) javaCls.getField(mapName).get(null);
				pyCls.preLine(
					String.format("%s = %s", mapName, regenerateValue(pyCls, javaCls, map)));
				pyCls.preLine();
			}
		}

		return sb.toString();
	}

	private String regenerateArray(PythonClass pyCls, Class<?> javaCls, Object arr)
			throws ArrayIndexOutOfBoundsException, IllegalAccessException, IllegalArgumentException,
			InvocationTargetException, NoSuchFieldException, SecurityException {
		StringBuilder sb = new StringBuilder();
		sb.append('[');
		for (int i = 0; i < Array.getLength(arr); i++) {
			sb.append(regenerateValue(pyCls, javaCls, Array.get(arr, i)));
			sb.append(", ");
		}
		sb.append(']');
		return sb.toString();
	}

	private String regenerateEnum(PythonClass pyCls, Enum<?> enumval) {
		PythonClass pyEnum = javaToPyClass(enumval.getClass());
		return pyEnum.getFullName(true) + "." + enumval.name();
	}

	private String regenerateMap(PythonClass pyCls, Class<?> javaCls, Map<?, ?> map)
			throws IllegalAccessException, IllegalArgumentException, InvocationTargetException,
			NoSuchFieldException, SecurityException {
		pyCls.addImport("collections", "OrderedDict");
		StringBuilder sb = new StringBuilder();
		sb.append("OrderedDict([");
		for (Entry<?, ?> ent : map.entrySet()) {
			sb.append(String.format("(%s, %s), ", regenerateValue(pyCls, javaCls, ent.getKey()),
				regenerateValue(pyCls, javaCls, ent.getValue())));
		}
		sb.append("])");
		return sb.toString();
	}

	private String regenerateString(String str) {
		return "'" + str + "'";
	}

	private String regenerateType(PythonClass pyCls, Class<?> javaCls, Type type) {
		Class<?> asCls = TypeUtils.getRawType(type, javaCls);
		if (asCls.isArray()) {
			PythonClass pyType = javaToPyClass(List.class);
			pyCls.addImport(pyType);
			return String.format("typedesc(lambda:%s, E=%s)", pyType.getFullName(true),
				regenerateType(pyCls, javaCls, asCls.getComponentType()));
		}
		else if (asCls.isPrimitive()) {
			return regenerateType(pyCls, javaCls, Primitives.wrap(asCls));
		}
		else {
			StringBuilder sb = new StringBuilder();
			// TODO: This lambda thing is a bit dirty of a hack
			sb.append("typedesc(lambda:");
			PythonClass pyType = javaToPyClass(asCls);
			pyCls.addImport(pyType);
			sb.append(pyType.getFullName(true));
			for (Entry<TypeVariable<?>, Type> arg : TypeUtils.getTypeArguments(type, asCls)
				.entrySet()) {
				sb.append(String.format(", %s=%s", arg.getKey().getName(),
					regenerateType(pyCls, javaCls, arg.getValue())));
			}
			sb.append(")");
			return sb.toString();
		}
	}

	private String regenerateValue(PythonClass pyCls, Class<?> javaCls, Object val)
			throws IllegalAccessException, IllegalArgumentException, InvocationTargetException,
			NoSuchFieldException, SecurityException {
		if (val instanceof Annotation) {
			return regenerateAnnotation(pyCls, javaCls, (Annotation) val);
		}
		else if (val.getClass().isArray()) {
			return regenerateArray(pyCls, javaCls, val);
		}
		else if (val instanceof Class) {
			return regenerateType(pyCls, javaCls, (Class<?>) val);
		}
		else if (val instanceof Map) {
			return regenerateMap(pyCls, javaCls, (Map<?, ?>) val);
		}
		else if (val instanceof String) {
			return regenerateString((String) val);
		}
		else if (val instanceof Enum) {
			return regenerateEnum(pyCls, (Enum<?>) val);
		}
		else {
			return val.toString();
		}
	}

	private int run(String pkgName, File outputDir) throws IllegalAccessException,
			IllegalArgumentException, InvocationTargetException, IOException, NoSuchFieldException,
			SecurityException, SorterException, NoSuchMethodException {
		exportPackage(pkgName);
		rootPkg.generate(outputDir.getCanonicalFile().toPath());
		return 0;
	}

	private int run(String[] args) {
		if (args.length != 2) {
			System.err.println(
				"Usage: " + this.getClass().getCanonicalName() + " [PACKAGE] [OUTPUT_DIR]");
			return -1;
		}
		File outputDir = new File(args[1]);

		try {
			run(args[0], outputDir);
		}
		catch (Exception e) {
			e.printStackTrace();
			return -2;
		}

		return 0;
	}

	PythonClass packetToPyClass(Class<? extends Packet> pkt) {
		return javaToPyClass(pkt);
	}
}
