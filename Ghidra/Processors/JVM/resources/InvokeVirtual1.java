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
public class InvokeVirtual1{


    public void func0_2(long a){
        a++;
        return;
    }    

    public long getLong(){
        return 1L;
    }

    public long longAndVoidTest(long a, long b){
        long c = a + b;
        func0_2(c);
        long d = getLong();
        return c + d;
    }



}
