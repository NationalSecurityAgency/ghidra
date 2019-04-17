/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package generic.continues;

import java.lang.reflect.Method;

import net.sf.cglib.proxy.MethodInterceptor;
import net.sf.cglib.proxy.MethodProxy;

class ContinuesInterceptor implements MethodInterceptor {
    private final ExceptionHandler handler;

    ContinuesInterceptor(ExceptionHandler handler) {
        this.handler = handler;
    }

    @Override
    public Object intercept(Object obj, Method method, Object[] args,
            MethodProxy proxy) throws Throwable {
        Object retValFromSuper = null;
        if (method.getAnnotation(DoNotContinue.class) != null) {
            retValFromSuper = proxy.invokeSuper(obj, args);
        } else {
            try {
                retValFromSuper = proxy.invokeSuper(obj, args);
            }
            catch (Exception e) {
                handler.handle(e);
            }
        }
        return retValFromSuper;
    }
}
