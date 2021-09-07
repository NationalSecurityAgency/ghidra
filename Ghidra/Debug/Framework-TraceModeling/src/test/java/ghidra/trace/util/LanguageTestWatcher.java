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
package ghidra.trace.util;

import java.lang.annotation.*;

import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import ghidra.program.database.ProgramBuilder;

public class LanguageTestWatcher extends TestWatcher {

	@Target(ElementType.METHOD)
	@Retention(RetentionPolicy.RUNTIME)
	public @interface TestLanguage {
		String value();
	}

	protected String language;

	public LanguageTestWatcher() {
		this(ProgramBuilder._TOY64_BE);
	}

	public LanguageTestWatcher(String defaultLanguage) {
		this.language = defaultLanguage;
	}

	@Override
	protected void starting(Description description) {
		TestLanguage annot = description.getAnnotation(TestLanguage.class);
		if (annot == null) {
			return;
		}
		language = annot.value();
	}

	public String getLanguage() {
		return language;
	}
}
