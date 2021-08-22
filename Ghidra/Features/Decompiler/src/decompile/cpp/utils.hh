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
/// \file utils.hh
/// \brief Generic utilities

#ifndef __UTILS__
#define __UTILS__

#include <string>
#include <type_traits>

template <typename T>
inline T to_number(const std::string &s, size_t *idx = nullptr, int base = 0)

{
  static_assert(std::is_integral<T>::value, "no instance of function template \"to_number\" matches the argument list");
  return to_number<std::decay<int4>::type>(s, idx, base);
}

template <typename T>
inline T to_hex_number(const std::string &s, size_t *idx = nullptr)

{
  return to_number<T>(s, idx, 16);
}

template<>
inline int to_number<int>(const std::string &s, size_t *idx, int base)

{
  return std::stoi(s, idx, base);
}

template<>
inline long to_number<long>(const std::string &s, size_t *idx, int base)

{
  return std::stol(s, idx, base);
}

template<>
inline long long to_number<long long>(const std::string &s, size_t *idx, int base)

{
  return std::stoll(s, idx, base);
}

template<>
inline unsigned long to_number<unsigned long>(const std::string &s, size_t *idx, int base)

{
  return std::stoul(s, idx, base);
}

template<>
inline unsigned long long to_number<unsigned long long>(const std::string &s, size_t *idx, int base)

{
  return std::stoull(s, idx, base);
}

#endif
