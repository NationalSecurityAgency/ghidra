/* ###
 * IP: GHIDRA
 * NOTE: Dummy placeholder for lucene class
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
package org.apache.lucene.analysis;

import java.io.Closeable;
import java.io.IOException;

import org.apache.lucene.util.AttributeFactory;
import org.apache.lucene.util.AttributeSource;

public abstract class TokenStream extends AttributeSource implements Closeable {
	public static final AttributeFactory DEFAULT_TOKEN_ATTRIBUTE_FACTORY = null;

	public abstract boolean incrementToken() throws IOException;
}
