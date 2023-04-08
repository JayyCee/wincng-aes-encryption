#pragma once

int base64_encode(const unsigned char *in_data, size_t in_data_size, const char **out_data_p, size_t *out_data_size_p);

int base64_decode(const char *in_data, size_t in_data_size, const unsigned char **out_data_p, size_t *out_data_size_p);
