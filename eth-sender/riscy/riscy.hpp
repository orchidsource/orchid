/* Orchid - WebRTC P2P VPN Market (on Ethereum)
 * Copyright (C) 2017-2020  The Orchid Authors
*/

/* GNU Affero General Public License, Version 3 {{{ */
/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
**/
/* }}} */


#ifndef ORCHID_RISCY_HPP
#define ORCHID_RISCY_HPP

typedef void (*riscy_Output)(void *baton, const uint8_t *data, size_t size);

inline void riscy_Output_string(void *baton, const uint8_t *data, size_t size) {
    auto &result(*static_cast<std::string *>(baton));
    result.resize(size);
    memcpy(result.data(), data, size);
}


extern "C" void riscy_image(
    const uint8_t *elf_data, size_t elf_size,
    const uint8_t image_data[32]
);


extern "C" void riscy_execute(
    const uint8_t *elf_data, size_t elf_size,
    const uint8_t *input_data, size_t input_size,
    riscy_Output journal_code, void *journal_data
);

extern "C" void riscy_prove(
    const uint8_t *elf_data, size_t elf_size,
    const uint8_t *input_data, size_t input_size,
    riscy_Output receipt_code, void *receipt_data
);

extern "C" void riscy_verify(
    const uint8_t *receipt_data, size_t receipt_size,
    const uint8_t image_data[32],
    riscy_Output journal_code, void *journal_data
);

#endif//ORCHID_RISCY_HPP
