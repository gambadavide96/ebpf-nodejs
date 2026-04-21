{
  "targets": [
    {
      "target_name": "addon",
      "sources": [ "addon.cpp" ],
      "cflags!": [ "-O3" ],
      "cflags": [ "-g", "-O0" ],
      "cflags_cc!": [ "-O3", "-fno-exceptions" ],
      "cflags_cc": [ "-g", "-O0", "-fexceptions" ]
    }
  ]
}