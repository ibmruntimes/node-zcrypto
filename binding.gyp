{
    "targets": [{
        "target_name": "zcrypto",
        "include_dirs": [
            "<!@(node -p \"require('node-addon-api').include\")"
        ],
        "conditions": [
          [ "OS==\"zos\"", {
            "sources": [
               "zcrypto.cc",
               "zcrypto_impl.cc"
            ],
          }],
        ],

        "libraries": ["/usr/lib/GSKCMS64.x", "/usr/lib/GSKSSL64.x"],
        "dependencies": [
            "<!(node -p \"require('node-addon-api').gyp\")"
        ],
        "cflags": [  "-I/usr/lpp/gskssl/include" ],
        "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS" ],
    }]
}
