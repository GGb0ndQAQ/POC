<a name="xZDQN"></a>
# Reproduction
<a name="soAUT"></a>
#### Environment
OS: Ubuntu `20.04.5 LTS`<br />Compiler: `gcc version 9.4.0`<br />version: commit `d5afe84cd1bd029fdeb1aae0e8705b6adfaa49fb`
<a name="rZGRf"></a>
# Compile TinyEXR with Address Sanitizer
```bash
$ git clone https://github.com/syoyo/tinyexr.git
$ cd tinyext
$ mkdir build
$ cd build
$ CFLAGS="-g -O0 -lpthread -fsanitize=address" CXXFLAGS="-g -O0 -lpthread -fsanitize=address" cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=../ -DASTCENC_ISA_AVX2=ON -DASTCENC_ISA_SSE41=ON -DASTCENC_ISA_SSE2=ON ..
$ make -j8
```

---

<a name="WGz0J"></a>
# 0x01.SEGV caused by a READ memory access in tinyexr.h:6925
<a name="BUN77"></a>
#### Steps to reproduce the behavior:
POC1:[https://github.com/GGb0ndQAQ/POC/blob/main/tinyexr/poc1](https://github.com/GGb0ndQAQ/POC/blob/main/tinyexr/poc1)
<a name="q3MoH"></a>
#### Desctiption
<a name="RT9lM"></a>
## 1.Compile TinyEXR with Address Sanitizer
<a name="QbGSW"></a>
## 2.Run
```bash
./test_tinyexr ./poc1
```
Here is the trace reported by ASAN:
```bash
$ ./test_tinyexr poc1
AddressSanitizer:DEADLYSIGNAL
=================================================================
==4164395==ERROR: AddressSanitizer: SEGV on unknown address 0x7fd99349788e (pc 0x560063e257dc bp 0x7fd993497886 sp 0x7ffd1bda2e80 T0)
==4164395==The signal is caused by a READ memory access.
    #0 0x560063e257db in DecodeEXRImage /usr/include/x86_64-linux-gnu/bits/string_fortified.h:34
    #1 0x560063e27107 in LoadEXRImageFromMemory /home/lucas/Desktop/oss/tinyexr/tinyexr.h:6925
    #2 0x560063e2a801 in LoadEXRImageFromFile /home/lucas/Desktop/oss/tinyexr/tinyexr.h:6902
    #3 0x560063e3b147 in LoadEXRWithLayer /home/lucas/Desktop/oss/tinyexr/tinyexr.h:6201
    #4 0x560063e019a5 in LoadEXR /home/lucas/Desktop/oss/tinyexr/tinyexr.h:6148
    #5 0x560063e019a5 in test_main /home/lucas/Desktop/oss/tinyexr/test_tinyexr.cc:223
    #6 0x560063e019a5 in main /home/lucas/Desktop/oss/tinyexr/test_tinyexr.cc:194
    #7 0x7fd964049082 in __libc_start_main ../csu/libc-start.c:308
    #8 0x560063e01ddd in _start (/home/lucas/Desktop/oss/tinyexr/install/test_tinyexr+0xcddd)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /usr/include/x86_64-linux-gnu/bits/string_fortified.h:34 in DecodeEXRImage
==4164395==ABORTING

########################################
(gdb) break main
Breakpoint 1 at 0xc850: file /home/lucas/Desktop/oss/tinyexr/test_tinyexr.cc, line 194.
(gdb) run ./poc1
Starting program: /home/lucas/Desktop/oss/tinyexr/install/test_tinyexr ./poc1
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, main (argc=2, argv=0x7fffffffe168) at /home/lucas/Desktop/oss/tinyexr/test_tinyexr.cc:194
194     int main(int argc, char** argv) { return test_main(argc, argv); }
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x0000555555584795 in tinyexr::DecodeEXRImage (exr_image=<optimized out>, exr_header=0x7fffffffdb50, head=<optimized out>, marker=<optimized out>, size=<optimized out>, err=<optimized out>) at /usr/include/x86_64-linux-gnu/bits/string_fortified.h:34
34        return __builtin___memcpy_chk (__dest, __src, __len, __bos0 (__dest));
(gdb) backtrace 
#0  0x0000555555584795 in tinyexr::DecodeEXRImage (exr_image=<optimized out>, exr_header=0x7fffffffdb50, head=<optimized out>, marker=<optimized out>, size=<optimized out>, err=<optimized out>) at /usr/include/x86_64-linux-gnu/bits/string_fortified.h:34
#1  0x0000555555586108 in LoadEXRImageFromMemory (exr_image=0x7fffffffd730, exr_header=<optimized out>, memory=<optimized out>, size=<optimized out>, err=<optimized out>) at /home/lucas/Desktop/oss/tinyexr/tinyexr.h:6925
#2  0x0000555555589802 in LoadEXRImageFromFile (exr_image=0x7fffffffd730, exr_header=0x7fffffffdb50, filename=0x7fffffffe499 "./poc1", err=<optimized out>) at /home/lucas/Desktop/oss/tinyexr/tinyexr.h:6902
#3  0x000055555559a148 in LoadEXRWithLayer (out_rgba=<optimized out>, width=<optimized out>, height=<optimized out>, filename=0x7fffffffe499 "./poc1", layername=<optimized out>, err=<optimized out>) at /home/lucas/Desktop/oss/tinyexr/tinyexr.h:6201
#4  0x00005555555609a6 in LoadEXR (err=0x7fffffffdfa0, filename=<optimized out>, height=0x7fffffffdf90, width=0x7fffffffdf80, out_rgba=0x7fffffffdfc0) at /home/lucas/Desktop/oss/tinyexr/tinyexr.h:6148
#5  test_main (argv=<optimized out>, argc=<optimized out>) at /home/lucas/Desktop/oss/tinyexr/test_tinyexr.cc:223
#6  main (argc=<optimized out>, argv=<optimized out>) at /home/lucas/Desktop/oss/tinyexr/test_tinyexr.cc:194
```
<a name="SOfbE"></a>
## 3.Code in function
```bash
const unsigned char *head = memory;
  const unsigned char *marker = reinterpret_cast<const unsigned char *>(
      memory + exr_header->header_len +
      8);  // +8 for magic number + version header.
  return tinyexr::DecodeEXRImage(exr_image, exr_header, head, marker, size,    <--------------- line 6925
                                 err);
```
<a name="gwOqU"></a>
#### IMPACT
Potentially causing DoS
<a name="b12T8"></a>
# 0x02.out of memory in tinyexr.h:4304
<a name="GqMgw"></a>
#### Steps to reproduce the behavior:
POC2:[https://github.com/GGb0ndQAQ/POC/blob/main/tinyexr/poc2](https://github.com/GGb0ndQAQ/POC/blob/main/tinyexr/poc2)
<a name="gl6BT"></a>
## 1.Compile TinyEXR with Address Sanitizer
<a name="vRQE2"></a>
## 2.Run
```bash
./test_tinyexr ./poc2
```
Here is the trace reported by ASAN:
```bash
./test_tinyexr poc2
=================================================================
==4164418==ERROR: AddressSanitizer: allocator is out of memory trying to allocate 0x2005020050 bytes
    #0 0x7f511fd0f808 in __interceptor_malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cc:144
    #1 0x55b4b4b0d48e in AllocateImage /home/lucas/Desktop/oss/tinyexr/tinyexr.h:4304

==4164418==HINT: if you don't care about these errors you may set allocator_may_return_null=1
SUMMARY: AddressSanitizer: out-of-memory ../../../../src/libsanitizer/asan/asan_malloc_linux.cc:144 in __interceptor_malloc
==4164418==ABORTING
```
<a name="UOtGl"></a>
## 3.Code in function tinyexr.h:4304
```bash
if (requested_pixel_types[c] == TINYEXR_PIXELTYPE_HALF) {
        images[c] =
            reinterpret_cast<unsigned char *>(static_cast<unsigned short *>(
                malloc(sizeof(unsigned short) * data_len)));
      } else if (requested_pixel_types[c] == TINYEXR_PIXELTYPE_FLOAT) {
        images[c] = reinterpret_cast<unsigned char *>(
            static_cast<float *>(malloc(sizeof(float) * data_len)));         <--------------------- line 4304
      } else {
        images[c] = NULL; // just in case.
        valid = false;
        break;
      }
    } else if (channels[c].pixel_type == TINYEXR_PIXELTYPE_FLOAT) {
      // pixel_data_size += sizeof(float);
      // channel_offset += sizeof(float);
      images[c] = reinterpret_cast<unsigned char *>(
          static_cast<float *>(malloc(sizeof(float) * data_len)));
    } else if (channels[c].pixel_type == TINYEXR_PIXELTYPE_UINT) {
      // pixel_data_size += sizeof(unsigned int);
      // channel_offset += sizeof(unsigned int);
      images[c] = reinterpret_cast<unsigned char *>(
          static_cast<unsigned int *>(malloc(sizeof(unsigned int) * data_len)));
    }
```
<a name="J9fFE"></a>
#### IMPACT
Potentially causing DoS
<a name="sAMpc"></a>
# 0x03.out of memory in tinyexr.h:4304
<a name="arkNl"></a>
#### Steps to reproduce the behavior:
POC3:[https://github.com/GGb0ndQAQ/POC/blob/main/tinyexr/poc3](https://github.com/GGb0ndQAQ/POC/blob/main/tinyexr/poc3)
<a name="TDYB5"></a>
## 1.Compile TinyEXR with Address Sanitizer
<a name="m9UUh"></a>
## 2.Run
```bash
./test_tinyexr ./poc3
```
Here is the trace reported by ASAN:
```bash
./test_tinyexr poc3
=================================================================
==4164446==ERROR: AddressSanitizer: allocator is out of memory trying to allocate 0x2014008050 bytes
    #0 0x7f65de63d808 in __interceptor_malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cc:144
    #1 0x55e6ebba13e8 in AllocateImage /home/lucas/Desktop/oss/tinyexr/tinyexr.h:4319

==4164446==HINT: if you don't care about these errors you may set allocator_may_return_null=1
SUMMARY: AddressSanitizer: out-of-memory ../../../../src/libsanitizer/asan/asan_malloc_linux.cc:144 in __interceptor_malloc
==4164446==ABORTING
```
<a name="xzJag"></a>
## 3.Code in function tinyexr.h:4319
```bash
if (requested_pixel_types[c] == TINYEXR_PIXELTYPE_HALF) {
        images[c] =
            reinterpret_cast<unsigned char *>(static_cast<unsigned short *>(
                malloc(sizeof(unsigned short) * data_len)));
      } else if (requested_pixel_types[c] == TINYEXR_PIXELTYPE_FLOAT) {
        images[c] = reinterpret_cast<unsigned char *>(
            static_cast<float *>(malloc(sizeof(float) * data_len)));         
      } else {
        images[c] = NULL; // just in case.
        valid = false;
        break;
      }
    } else if (channels[c].pixel_type == TINYEXR_PIXELTYPE_FLOAT) {
      // pixel_data_size += sizeof(float);
      // channel_offset += sizeof(float);
      images[c] = reinterpret_cast<unsigned char *>(
          static_cast<float *>(malloc(sizeof(float) * data_len)));
    } else if (channels[c].pixel_type == TINYEXR_PIXELTYPE_UINT) {
      // pixel_data_size += sizeof(unsigned int);
      // channel_offset += sizeof(unsigned int);
      images[c] = reinterpret_cast<unsigned char *>(
          static_cast<unsigned int *>(malloc(sizeof(unsigned int) * data_len))); <--------------------- line 4319
    }
```
<a name="Go30W"></a>
#### IMPACT
Potentially causing DoS
