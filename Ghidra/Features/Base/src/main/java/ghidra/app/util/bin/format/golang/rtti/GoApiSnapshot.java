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
package ghidra.app.util.bin.format.golang.rtti;

import java.io.*;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import generic.jar.ResourceFile;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.golang.GoVer;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.framework.Application;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Contains function definitions and type information found in a specific Golang runtime toolchain
 * version.
 * <p>
 * Useful to apply function parameter information to functions found in a go binary.
 * <p>
 * Snapshot json files contain function / type information about functions and types extracted from
 * the golang toolchain itself, for each arch and OSes that the golang toolchain supports,
 * via cross-compiling against each GOARCH and GOOS.
 * <p>
 * Function and type info that is incompatible or not present in other arch / os targets will be
 * split into different arch lookup keys that can be specified when deserializing the json.
 * <p>
 * The arch names will be one of "all", cpu-arch-name (eg. amd64), operating-system-name (eg. linux),
 * operating-system-cpu-arch-name (eg. linux-amd64), or "unix" (artificial arch name that indicates
 * the sub-elements are common to all unix-like arches).  
 * <p>
 * Non-exhaustive list of current values:
 * <ul>
 * <li>all - everything that is generically compatible with all platforms</li>
 * <li>386</li>
 * <li>amd64</li>
 * <li>arm</li>
 * <li>arm64</li>
 * <li>cgo</li>
 * <li>darwin</li>
 * <li>darwin-amd64</li>
 * <li>darwin-amd64-cgo</li>
 * <li>darwin-arm64</li>
 * <li>darwin-arm64-cgo</li>
 * <li>linux</li>
 * <li>linux-386</li>
 * <li>linux-386-cgo</li>
 * <li>linux-amd64</li>
 * <li>linux-amd64-cgo</li>
 * <li>linux-arm</li>
 * <li>linux-arm-cgo</li>
 * <li>linux-arm64</li>
 * <li>linux-arm64-cgo</li>
 * <li>linux-cgo</li>
 * <li>unix - an artificial goos that groups linux/bsd/darwin/aix/etc together</li>
 * <li>windows</li>
 * <li>windows-386</li>
 * <li>windows-386-cgo</li>
 * <li>windows-amd64</li>
 * <li>windows-amd64-cgo</li>
 * </ul>
 *  
 */
public class GoApiSnapshot {

	/**
	 * Returns a matching {@link GoApiSnapshot} for the specified golang version.  If an exact
	 * match isn't found, earlier patch revs will be tried until all patch levels are exhausted.   
	 * 
	 * @param goVer go version (controls which .json file is opened)
	 * @param goArch GOARCH string
	 * @param goOS GOOS string
	 * @param monitor {@link TaskMonitor}
	 * @return {@link GoApiSnapshot} instance, possibly an {@link #EMPTY} instance if no matching
	 * snapshot file is found
	 * @throws IOException if error parsing json or opening the snapshot container file
	 * @throws CancelledException if user cancels
	 */
	public static GoApiSnapshot get(GoVer goVer, String goArch, String goOS, TaskMonitor monitor)
			throws IOException, CancelledException {

		try (ByteProvider bp = getApiSnapshotJsonFile(goVer, monitor)) {
			if (bp != null) {
				try (InputStream is = bp.getInputStream(0)) {
					List<String> archSearchOrder = List.of(goOS + "-" + goArch, goOS,
						IS_GOOS_UNIX.contains(goOS) ? "unix" : "", goArch, "all");

					return GoApiSnapshot.read(is, archSearchOrder, goVer);
				}
			}
		}
		return GoApiSnapshot.EMPTY;
	}

	public static ByteProvider getApiSnapshotJsonFile(GoVer goVer, TaskMonitor monitor)
			throws IOException, CancelledException {
		FileSystemService fsService = FileSystemService.getInstance();

		GoVer baseVer = goVer.withPatch(0);
		File jsonFile = getApiSnapshotFile(baseVer, "", "");
		if (jsonFile == null) {
			return null;
		}

		ByteProvider bp = null;
		if (goVer.getPatch() == 0) {
			// doesn't need diffpatching
			bp = fsService.getByteProvider(fsService.getLocalFSRL(jsonFile), false, monitor);
		}
		else {
			File patchDiffFile = getApiSnapshotFile(goVer, "patchverdiffs/", ".diff");
			if (patchDiffFile != null) {
				FSRL fsrl =
					fsService.getFullyQualifiedFSRL(fsService.getLocalFSRL(jsonFile), monitor);
				bp = fsService.getDerivedByteProviderPush(fsrl, null,
					"go%s.json".formatted(goVer), -1, os -> {
						JsonPatch jsonPatch = JsonPatch.read(patchDiffFile);
						JsonPatchApplier jpa = new JsonPatchApplier(jsonFile);
						monitor.initialize(jsonPatch.getSectionCount(),
							"Patching golang api snapshot %s -> %s".formatted(baseVer, goVer));
						jpa.apply(jsonPatch, monitor);
						OutputStreamWriter osw = new OutputStreamWriter(os, StandardCharsets.UTF_8);
						new Gson().toJson(jpa.getJson(), osw);
						osw.flush(); // don't close outputstream, handled by caller
					}, monitor);
			}
		}
		return bp;
	}

	static File getApiSnapshotFile(GoVer goVer, String subdir, String suffix) {
		try {
			ResourceFile rfile = Application.getModuleDataFile(
				"typeinfo/golang/%sgo%s.json%s".formatted(subdir, goVer.toString(), suffix));
			return rfile.getFile(true);

		}
		catch (IOException e) {
			return null;
		}
	}

	private static final Set<String> IS_GOOS_UNIX = Set.of("aix", "android", "darwin", "dragonfly",
		"freebsd", "hurd", "illumos", "ios", "linux", "netbsd", "openbsd", "solaris");

	public static File getApiFile(File baseDir, GoVer ver) {
		String filename =
			"go%d.%d.%d.json".formatted(ver.getMajor(), ver.getMinor(), ver.getPatch());
		File f = new File(baseDir, filename);
		if (!f.isFile() && ver.getPatch() == 0) {
			filename = "go%d.%d.json".formatted(ver.getMajor(), ver.getMinor());
			f = new File(baseDir, filename);
		}
		return f.isFile() ? f : null;
	}

	/**
	 * Reads a json snapshot file produced by the go-api-parser exfil tool.
	 * <p>
	 * Information for archs that are not need will be omitted during reading.
	 * 
	 * @param is {@link InputStream} containing the json file
	 * @param archNames list of arch names that should be retained when reading the json data,
	 * in search priority, example: [ "linux-amd64", "linux", "amd64", "all" ] 
	 * @return {@link GoApiSnapshot} instance with only the requested archs / os data
	 * @throws IOException if error parsing
	 */
	private static GoApiSnapshot read(InputStream is, List<String> archNames, GoVer ver)
			throws IOException {
		Gson gson =
			new GsonBuilder().registerTypeAdapter(GoTypeDef.class, new GoTypeDefDeserializer())
					.create();
		Map<String, GoArch> arches = new HashMap<>();
		Set<String> archNamesToKeep = new HashSet<>(archNames);

		try (JsonReader reader = new JsonReader(new InputStreamReader(is))) {
			reader.beginObject();
			while (reader.peek() == JsonToken.NAME) {
				String archName = reader.nextName();
				if (!archNamesToKeep.contains(archName)) {
					reader.skipValue();
					continue;
				}
				GoArch arch = gson.fromJson(reader, GoArch.class);
				arches.put(archName, arch);
			}
			reader.endObject();
		}

		Map<String, GoArch> results = new LinkedHashMap<>();
		for (String archName : archNames) {
			if (archName == null || archName.isEmpty()) {
				continue;
			}
			GoArch arch = arches.get(archName);
			if (arch != null) {
				results.put(archName, arch);
			}
		}

		return new GoApiSnapshot(ver, results);
	}

	public static final GoApiSnapshot EMPTY = new GoApiSnapshot(GoVer.INVALID, Map.of());

	public static class GoNameTypePair {
		String Name;
		String DataType;

		@Override
		public String toString() {
			return "GoNameTypePair [Name=" + Name + ", DataType=" + DataType + "]";
		}

		public String getPairString() {
			String s = Objects.requireNonNullElse(Name, "");
			if (DataType != null && !DataType.isEmpty()) {
				if (!s.isEmpty()) {
					s += " ";
				}
				s += DataType;
			}
			return s;
		}

		public static String listToString(List<GoNameTypePair> list) {
			return list.stream()
					.map(item -> item.getPairString())
					.collect(Collectors.joining(", "));
		}
	}

	public enum FuncFlags {
		VarArg(1), Generic(2), Method(4), NoReturn(8);

		private int flagVal;

		FuncFlags(int i) {
			this.flagVal = i;
		}

		private static final FuncFlags[] vals = values();

		public static EnumSet<FuncFlags> parse(int i) {
			EnumSet<FuncFlags> result = EnumSet.noneOf(FuncFlags.class);
			for (FuncFlags ff : vals) {
				if ((i & ff.flagVal) != 0) {
					result.add(ff);
				}
			}
			return result;
		}
	}

	public static class GoFuncDef {
		List<GoNameTypePair> Params;
		List<GoNameTypePair> Results;
		List<String> TypeParams;
		int Flags;

		EnumSet<FuncFlags> getFuncFlags() {
			return FuncFlags.parse(Flags);
		}

		@Override
		public String toString() {
			return "GoFuncDef [Params=" + Params + ", Results=" + Results + ", TypeParams=" +
				TypeParams + ", Flags=" + Flags + "]";
		}

		public String getDefinitionString(GoSymbolName symbolName) {
			String resultsStr;
			if (Results.size() == 0) {
				resultsStr = "";
			}
			else if (Results.size() == 1 && Results.get(0).Name.isEmpty()) {
				resultsStr = " " + Results.get(0).DataType;
			}
			else {
				resultsStr = " (%s)".formatted(GoNameTypePair.listToString(Results));
			}

			List<GoNameTypePair> tmpParams = Params;
			if (symbolName.hasReceiver() && Params.size() > 0) {
				tmpParams = Params.subList(1, Params.size());
			}

			return "func %s(%s)%s".formatted(symbolName.asString(),
				GoNameTypePair.listToString(tmpParams), resultsStr);
		}

	}

	public static class GoTypeDef {

		@Override
		public String toString() {
			return "GoTypeDef []";
		}
	}

	public static class GoStructDef extends GoTypeDef {
		List<GoNameTypePair> Fields;
		List<String> TypeParams;

		@Override
		public String toString() {
			return "GoStructDef [Fields=" + Fields + ", TypeParams=" + TypeParams + "]";
		}
	}

	public static class GoInterfaceDef extends GoTypeDef {

		@Override
		public String toString() {
			return "GoInterfaceDef []";
		}

	}

	public static class GoAliasDef extends GoTypeDef {
		String Target;

		@Override
		public String toString() {
			return "GoAliasDef [Target=" + Target + "]";
		}
	}

	public static class GoBasicDef extends GoTypeDef {
		String DataType;
		Map<String, String> EnumValues;  // TODO: work in progress

		@Override
		public String toString() {
			return "GoBasicDef [DataType=" + DataType + ", EnumValues=" + EnumValues + "]";
		}
	}

	public static class GoFuncTypeDef extends GoTypeDef {
		List<GoNameTypePair> Params;
		List<GoNameTypePair> Results;
		List<String> TypeParams;
		int Flags;

		@Override
		public String toString() {
			return "GoFuncTypeDef [Params=" + Params + ", Results=" + Results + ", TypeParams=" +
				TypeParams + ", Flags=" + Flags + "]";
		}

	}

	static class GoArch {
		Map<String, GoFuncDef> Funcs;
		Map<String, GoTypeDef> Types;
	}

	static class GoTypeDefDeserializer implements JsonDeserializer<GoTypeDef> {

		@Override
		public GoTypeDef deserialize(JsonElement json, Type typeOfT,
				JsonDeserializationContext context) throws JsonParseException {
			JsonObject obj = json.getAsJsonObject();
			String Kind = obj.get("Kind").getAsString();
			switch (Kind) {
				case "struct":
					return context.deserialize(obj, GoStructDef.class);
				case "iface":
					return context.deserialize(obj, GoInterfaceDef.class);
				case "basic":
					return context.deserialize(obj, GoBasicDef.class);
				case "alias":
					return context.deserialize(obj, GoAliasDef.class);
				case "funcdef":
					return context.deserialize(obj, GoFuncTypeDef.class);
			}
			return null;
		}

	}

	private final Map<String, GoArch> arches;
	private final GoVer ver;

	public GoApiSnapshot(GoVer ver, Map<String, GoArch> arches) {
		this.ver = ver;
		this.arches = arches;
	}

	public GoVer getVer() {
		return ver;
	}

	/**
	 * Returns a {@link GoFuncDef} for the specified function name.  The function name should
	 * not contain generics (eg. "cmp.Compare" and not "cmp.Compare[sometypename]").
	 * 
	 * @param funcName fully qualified name of function, without any generics
	 * @return {@link GoFuncDef} instance, or null
	 */
	public GoFuncDef getFuncdef(String funcName) {
		for (GoArch arch : arches.values()) {
			GoFuncDef funcDef = arch.Funcs.get(funcName);
			if (funcDef != null) {
				return funcDef;
			}
		}
		return null;
	}

	public GoTypeDef getTypeDef(String typeName) {
		for (GoArch arch : arches.values()) {
			GoTypeDef typeDef = arch.Types.get(typeName);
			if (typeDef != null) {
				return typeDef;
			}
		}
		return null;
	}

}
