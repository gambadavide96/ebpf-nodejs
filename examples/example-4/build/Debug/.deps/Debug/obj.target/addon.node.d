cmd_Debug/obj.target/addon.node := g++ -o Debug/obj.target/addon.node -shared -pthread -rdynamic -m64  -Wl,-soname=addon.node -Wl,--start-group Debug/obj.target/addon/addon.o -Wl,--end-group 
