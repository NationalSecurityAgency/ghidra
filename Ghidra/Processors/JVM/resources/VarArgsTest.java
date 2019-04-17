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
class VarArgsTest{

    public static int voidCall(){
        return callVarArgs();
    }

    public static int oneCall(){
        return callVarArgs(1);
    }

    public static int twoCall(){
        return callVarArgs(1,2);
    }
  
    public static int callVarArgs(int... args){
       int sum = 0;
       for(int i = 0; i < args.length; ++i){
           sum += args[i];
       }
       return sum;
    }
}
