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
package ghidra.comm.packet.fields;

import java.lang.annotation.*;

/**
 * An annotation specifying a universal implementation of a packet annotation
 * 
 * Some packet annotations can be applied regardless of the codec. Others are only applicable to
 * certain codecs. The codec may override any universal implementation.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.ANNOTATION_TYPE)
public @interface ImplementedBy {
	@SuppressWarnings("rawtypes")
	Class<? extends WrapperFactory> value();
}
