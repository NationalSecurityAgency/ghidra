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
package ghidra.program.model.data.ISF;

import java.io.Closeable;
import java.io.IOException;
import java.io.Writer;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import com.google.gson.ExclusionStrategy;
import com.google.gson.FieldAttributes;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.stream.JsonWriter;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractIsfWriter implements Closeable {

	protected JsonWriter writer;
	protected Gson gson = new GsonBuilder().setPrettyPrinting().create();

	protected JsonObject root = new JsonObject();
	protected JsonArray objects = new JsonArray();

	public AbstractIsfWriter(Writer baseWriter) throws IOException {
		if (baseWriter != null) {
			this.writer = new JsonWriter(baseWriter);
			writer.setIndent("  ");
		}
		this.gson = new GsonBuilder().addSerializationExclusionStrategy(strategy).setPrettyPrinting().create();
	}

	protected abstract void genRoot(TaskMonitor monitor) throws CancelledException, IOException;

	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.FIELD)
	public @interface Exclude {
		// EMPTY
	}

	// Am setting this as the default, but it's possible we may want more latitude
	// in the future
	protected boolean STRICT = true;

	// @Exclude used for properties that might be desirable for a non-STRICT
	// implementation.
	ExclusionStrategy strategy = new ExclusionStrategy() {
		@Override
		public boolean shouldSkipClass(Class<?> clazz) {
			return false;
		}

		@Override
		public boolean shouldSkipField(FieldAttributes field) {
			return STRICT && field.getAnnotation(Exclude.class) != null;
		}
	};

	public JsonObject getRootObject(TaskMonitor monitor) throws CancelledException, IOException {
		genRoot(monitor);
		return root;
	}

	public JsonArray getResults() {
		return objects;
	}

	public JsonElement getTree(Object obj) {
		return gson.toJsonTree(obj);
	}

	public Object getObject(JsonElement element, Class<? extends Object> clazz) {
		return gson.fromJson(element, clazz);
	}

	public void write(JsonObject object) {
		gson.toJson(object, writer);
	}

	public void close() throws IOException {
		if (writer != null) {
			writer.flush();
			writer.close();
		}
	}

}
